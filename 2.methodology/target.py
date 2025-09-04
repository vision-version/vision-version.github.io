from __future__ import annotations

import os
from functools import cached_property

import cpu_heater
from pydriller.domain.commit import Commit

import ast_parser
import code_transformation
import format_code
from ast_parser import ASTParser
from codefile import CodeFile
from common import Language
from project import Project


class Target:
    def __init__(
        self,
        cve: str,
        repo_path: str,
        file_list: set[str],
        matching_method: list[str],
        language: Language,
        addline_matching: dict[str, set[int]],
        deleteline_matching: dict[str, set[int]],
    ):
        self.cve = cve
        self.path = repo_path
        self.include_files = file_list
        self.matching_methods = matching_method
        self.project: Project | None = None
        self.language = language
        self.addline_matching = addline_matching
        self.deleteline_matching = deleteline_matching

        self.include_methods = set()
        self.project = Project("target", self.analysis_files, self.language)

    @cached_property
    def files(self):
        c_files_content = {}
        suffix_list = []
        if self.language == Language.CPP:
            suffix_list = ["c", "cpp", "cc", "cxx", "c++", "hpp", "h"]
        elif self.language == Language.JAVA:
            suffix_list = ["java"]
        for root, _, files in os.walk(self.path):
            for file in files:
                if file.split(".")[-1] in suffix_list:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r", errors="replace") as f:
                            content = f.read()
                        c_files_content[os.path.relpath(file_path, self.path)] = content
                    except Exception as e:
                        print(f"can't read file {file_path}：{e}")

        return c_files_content

    def get_file_content(self, include_code):
        methods = set()
        method_parser = ASTParser(include_code, self.language)
        if self.language == Language.CPP:
            nodes = method_parser.query_all(ast_parser.TS_C_METHOD)
            for node in nodes:
                name_node = node.child_by_field_name("declarator")
                while name_node is not None and name_node.type not in {
                    "identifier",
                    "operator_name",
                    "type_identifier",
                }:
                    all_temp_name_node = name_node
                    if (
                        name_node.child_by_field_name("declarator") is None
                        and name_node.type == "reference_declarator"
                    ):
                        for temp_node in name_node.children:
                            if temp_node.type == "function_declarator":
                                name_node = temp_node
                                break
                    if name_node.child_by_field_name("declarator") is not None:
                        name_node = name_node.child_by_field_name("declarator")
                    while name_node is not None and (
                        name_node.type == "qualified_identifier"
                        or name_node.type == "template_function"
                    ):
                        temp_name_node = name_node
                        for temp_node in name_node.children:
                            if temp_node.type in {
                                "identifier",
                                "destructor_name",
                                "qualified_identifier",
                                "operator_name",
                                "type_identifier",
                                "pointer_type_declarator",
                            }:
                                name_node = temp_node
                                break
                        if name_node == temp_name_node:
                            break
                    if name_node is not None and name_node.type == "destructor_name":
                        for temp_node in name_node.children:
                            if temp_node.type == "identifier":
                                name_node = temp_node
                                break

                    if (
                        name_node is not None
                        and name_node.type == "field_identifier"
                        and name_node.child_by_field_name("declarator") is None
                    ):
                        break
                    if name_node == all_temp_name_node:
                        break

                assert name_node is not None and name_node.text is not None
                methods.add((name_node.text.decode(), node.text.decode()))
        elif self.language == Language.JAVA:
            nodes = method_parser.query_all(ast_parser.TS_JAVA_METHOD)
            for node in nodes:
                parameters_node = node.child_by_field_name("parameters")
                if parameters_node is None:
                    continue
                parameters = ASTParser.children_by_type_name(
                    parameters_node, "formal_parameter"
                )
                parameter_signature_list = []
                for param in parameters:
                    type_node = param.child_by_field_name("type")
                    assert type_node is not None
                    if type_node.type == "generic_type":
                        type_identifier_node = ASTParser.child_by_type_name(
                            type_node, "type_identifier"
                        )
                        if type_identifier_node is None:
                            type_name = ""
                        else:
                            assert type_identifier_node.text is not None
                            type_name = type_identifier_node.text.decode()
                    else:
                        assert type_node.text is not None
                        type_name = type_node.text.decode()
                    parameter_signature_list.append(type_name)
                name_node = node.child_by_field_name("name")
                assert name_node is not None and name_node.text is not None
                methods.add(
                    (
                        f"{name_node.text.decode()}({','.join(parameter_signature_list)})",
                        node.text.decode(),
                    )
                )

        return methods

    def get_callee(self, method_code):
        callees = set()
        call = []
        ast = ASTParser(method_code, self.language)
        if self.language == Language.CPP:
            call = ast.query_all(ast_parser.CPP_CALL)
        elif self.language == Language.JAVA:
            call = ast.query_all(ast_parser.JAVA_CALL)
        if len(call) == 0:
            return None

        for node in call:
            callees.add(node.text.decode())

        return callees

    def bfs_search_files(self, filepath, methodname, step=0):
        if step >= 3:
            return
        callees = set()
        if filepath not in self.include_files:
            self.include_files.add(filepath)

        file_contents = self.get_file_content(self.files[filepath])
        for method_name, method_contents in file_contents:
            if methodname == method_name:
                callees = self.get_callee(method_contents)
                break
        if callees is None:
            return
        if len(callees) == 0:
            return
        self.include_methods.update(file_contents)
        for method_name, method_contents in list(self.include_methods):
            if method_name in callees:
                self.bfs_search_files(filepath, method_name, step + 1)
                callees.remove(method_name)
        if len(callees) == 0:
            return

        code = self.files[filepath]

        parser = ASTParser(code, self.language)
        if self.language == Language.CPP:
            includes = parser.query_all(ast_parser.CPP_INCLUDE)
            suffix_list = [".c", ".cc", ".cxx", ".cpp"]
            for include in includes:
                include_name = include.text.decode()
                prefix = os.path.dirname(filepath)
                if os.path.join(prefix, include_name) in self.files:
                    for suffix in suffix_list:
                        if (
                            os.path.join(prefix, include_name.replace(".h", suffix))
                            in self.files
                        ):
                            file_contents = self.get_file_content(
                                self.files[
                                    os.path.join(
                                        prefix, include_name.replace(".h", suffix)
                                    )
                                ]
                            )
                            for method_name, method_contents in file_contents:
                                if method_name in callees:
                                    if (
                                        os.path.join(
                                            prefix, include_name.replace(".h", suffix)
                                        )
                                        in self.include_files
                                    ):
                                        continue
                                    self.include_files.add(
                                        os.path.join(
                                            prefix, include_name.replace(".h", suffix)
                                        )
                                    )
                                    self.include_methods.update(file_contents)
                                    self.bfs_search_files(
                                        os.path.join(
                                            prefix, include_name.replace(".h", suffix)
                                        ),
                                        method_name,
                                        step + 1,
                                    )
                                    callees.remove(method_name)

                                    if len(callees) == 0:
                                        break

                            if len(callees) == 0:
                                break
                    if len(callees) == 0:
                        break
                    file_contents = self.get_file_content(
                        self.files[os.path.join(prefix, include_name)]
                    )
                    for method_name, method_contents in file_contents:
                        if method_name in callees:
                            if os.path.join(prefix, include_name) in self.include_files:
                                continue
                            self.include_files.add(os.path.join(prefix, include_name))
                            self.include_methods.update(file_contents)
                            self.bfs_search_files(
                                os.path.join(prefix, include_name),
                                method_name,
                                step + 1,
                            )
                            callees.remove(method_name)

                            if len(callees) == 0:
                                break

                    if len(callees) == 0:
                        break
                elif os.path.join(prefix, "include", include_name) in self.files:
                    for suffix in suffix_list:
                        if os.path.isfile(
                            os.path.join(
                                self.path,
                                prefix,
                                include_name.replace(".h", suffix),
                            )
                        ) and not os.path.islink(
                            os.path.join(
                                self.path,
                                prefix,
                                include_name.replace(".h", suffix),
                            )
                        ):
                            file_contents = self.get_file_content(
                                self.files[
                                    os.path.join(
                                        prefix, include_name.replace(".h", suffix)
                                    )
                                ]
                            )
                            for method_name, method_contents in file_contents:
                                if method_name in callees:
                                    if (
                                        os.path.join(
                                            prefix, include_name.replace(".h", suffix)
                                        )
                                        in self.include_files
                                    ):
                                        continue
                                    self.include_files.add(
                                        os.path.join(
                                            prefix, include_name.replace(".h", suffix)
                                        )
                                    )
                                    self.include_methods.update(file_contents)
                                    self.bfs_search_files(
                                        os.path.join(
                                            prefix, include_name.replace(".h", suffix)
                                        ),
                                        method_name,
                                        step + 1,
                                    )
                                    callees.remove(method_name)
                        elif (
                            os.path.join(
                                prefix, "src", include_name.replace(".h", suffix)
                            )
                            in self.files
                        ):
                            file_contents = self.get_file_content(
                                self.files[
                                    os.path.join(
                                        prefix,
                                        "src",
                                        include_name.replace(".h", suffix),
                                    )
                                ]
                            )
                            for method_name, method_contents in file_contents:
                                if method_name in callees:
                                    if (
                                        os.path.join(
                                            prefix,
                                            "src",
                                            include_name.replace(".h", suffix),
                                        )
                                        in self.include_files
                                    ):
                                        continue
                                    self.include_files.add(
                                        os.path.join(
                                            prefix,
                                            "src",
                                            include_name.replace(".h", suffix),
                                        )
                                    )
                                    self.include_methods.update(file_contents)
                                    self.bfs_search_files(
                                        os.path.join(
                                            prefix,
                                            "src",
                                            include_name.replace(".h", suffix),
                                        ),
                                        method_name,
                                        step + 1,
                                    )
                                    callees.remove(method_name)
                                    if len(callees) == 0:
                                        break

                        if len(callees) == 0:
                            break
                    file_contents = self.get_file_content(
                        self.files[os.path.join(prefix, "include", include_name)]
                    )
                    for method_name, method_contents in file_contents:
                        if method_name in callees:
                            if (
                                os.path.join(prefix, "include", include_name)
                                in self.include_files
                            ):
                                continue
                            self.include_files.add(
                                os.path.join(prefix, "include", include_name)
                            )
                            self.include_methods.update(file_contents)
                            self.bfs_search_files(
                                os.path.join(prefix, "include", include_name),
                                method_name,
                                step + 1,
                            )
                            callees.remove(method_name)

                            if len(callees) == 0:
                                break

                    if len(callees) == 0:
                        break
        elif self.language == Language.JAVA:
            packages = parser.query_all(ast_parser.TS_JAVA_PACKAGE)
            package_name = packages[0].text.decode().replace(".", "/")
            includes = parser.query_all(ast_parser.TS_JAVA_IMPORT)
            for include in includes:
                include_name = include.text.decode()
                prefix = os.path.dirname(filepath)
                raw_dir = prefix.replace(package_name, "")
                if (
                    os.path.join(prefix, include_name.replace(".", "/") + ".java")
                    in self.files
                ):
                    file_contents = self.get_file_content(
                        self.files[
                            os.path.join(
                                prefix, include_name.replace(".", "/") + ".java"
                            )
                        ]
                    )
                    for method_name, method_contents in file_contents:
                        if method_name in callees:
                            if (
                                os.path.join(
                                    prefix, include_name.replace(".", "/") + ".java"
                                )
                                in self.include_files
                            ):
                                continue
                            self.include_files.add(
                                os.path.join(
                                    prefix, include_name.replace(".", "/") + ".java"
                                )
                            )
                            self.include_methods.update(file_contents)
                            self.bfs_search_files(
                                os.path.join(
                                    prefix, include_name.replace(".", "/") + ".java"
                                ),
                                method_name,
                                step + 1,
                            )
                            callees.remove(method_name)

                            if len(callees) == 0:
                                break

                    if len(callees) == 0:
                        break
                elif (
                    os.path.join(raw_dir, include_name.replace(".", "/") + ".java")
                    in self.files
                ):
                    file_contents = self.get_file_content(
                        self.files[
                            os.path.join(
                                raw_dir, include_name.replace(".", "/") + ".java"
                            )
                        ]
                    )
                    for method_name, method_contents in file_contents:
                        if method_name in callees:
                            if (
                                os.path.join(
                                    raw_dir, include_name.replace(".", "/") + ".java"
                                )
                                in self.include_files
                            ):
                                continue
                            self.include_files.add(
                                os.path.join(
                                    raw_dir, include_name.replace(".", "/") + ".java"
                                )
                            )
                            self.include_methods.update(file_contents)
                            self.bfs_search_files(
                                os.path.join(
                                    raw_dir, include_name.replace(".", "/") + ".java"
                                ),
                                method_name,
                                step + 1,
                            )
                            callees.remove(method_name)

                            if len(callees) == 0:
                                break

                    if len(callees) == 0:
                        break

    def format(self, FilePath):
        codes = self.files[FilePath]
        extracted_macros_codes = codes
        assert extracted_macros_codes is not None
        source_code_before = format_code.format_and_del_comment_c_cpp(
            extracted_macros_codes, self.language
        )
        assert source_code_before is not None
        codefile = CodeFile(FilePath, source_code_before, isformat=False)
        return codefile

    @cached_property
    def analysis_files(self):
        results = []

        for method_sig in self.matching_methods:
            if self.language == Language.JAVA:
                self.bfs_search_files(
                    method_sig.split("#")[0], method_sig.split("#")[1]
                )
            else:
                self.bfs_search_files(
                    method_sig.split("#")[0], method_sig.split("#")[1]
                )

        worker_list = []
        for file in self.include_files:
            worker_list.append((file,))

        results = cpu_heater.multithreads(
            self.format, worker_list, max_workers=65536, show_progress=False
        )

        return results
