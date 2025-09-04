from __future__ import annotations

import os
import re
import subprocess
import tempfile
from functools import cached_property
from pathlib import Path

import cpu_heater
from git import Commit, Diff, Repo
from pydriller import GitRepository, Modification
from pydriller.domain.commit import Commit, ModificationType
from pydriller.utils.conf import Conf

import ast_parser
import code_transformation
import config
import format_code
from ast_parser import ASTParser
from codefile import CodeFile
from common import Language
from project import Class, Field, File, Import, Method, Project


def gitdiff(code1: str, code2: str):
    tf1 = tempfile.NamedTemporaryFile()
    tf2 = tempfile.NamedTemporaryFile()
    tf1.write(code1.encode())
    tf2.write(code2.encode())
    tf1.flush()
    tf2.flush()
    diff = subprocess.run(
        ["git", "--no-pager", "diff", "--no-index", "-w", "-b", tf1.name, tf2.name],
        stdout=subprocess.PIPE,
    ).stdout.decode()
    diff_lines = diff.splitlines()[4:]
    diff = "\n".join(diff_lines)
    return diff


class BPCommit(Commit):
    def _get_decoded_sc_str(self, diff):
        try:
            return diff.data_stream.read().decode("utf-8", "ignore")
        except (UnicodeDecodeError, AttributeError, ValueError):
            return None


class Patch:
    def __init__(self, repo_path: str, commit_id: str, language: Language):
        self.repo_path = repo_path
        self.repo_name = repo_path.split("/")[-1]
        self.commit_id = commit_id
        path = Path(repo_path)
        conf = Conf(
            {
                "path_to_repo": str(path),
                "skip_whitespaces": True,
                "include_remotes": True,
            }
        )
        self.repo = GitRepository(repo_path, conf=conf)
        self.commit = self.repo.get_commit(commit_id)
        self.git_repo = Repo(repo_path)
        self.git_commit = self.git_repo.commit(commit_id)

        self.diffs = self.commit.modifications

        self.modify_files = []
        self.add_files = []
        self.del_files = []
        for file in self.diffs:
            if not Patch.is_patch_related_file(file, language=language):
                continue
            if file.change_type == ModificationType.ADD:
                self.add_files.append(file)
            elif file.change_type == ModificationType.DELETE:
                self.del_files.append(file)
            elif file.change_type == ModificationType.MODIFY:
                assert file.old_path is not None
                extracted_macros_codes = file.source_code_before
                if language == Language.CPP:
                    extracted_macros_codes = code_transformation.extraction_macros(
                        file.source_code_before,
                        self.repo_path,
                        file.old_path,
                        self.commit_id + "~1",
                        self.pre_files,
                    )
                assert extracted_macros_codes is not None
                source_code_before = code_transformation.code_transformation(
                    extracted_macros_codes, language
                )
                source_code_before = extracted_macros_codes
                assert file.new_path is not None
                extracted_macros_codes = file.source_code
                if language == Language.CPP:
                    extracted_macros_codes = code_transformation.extraction_macros(
                        file.source_code,
                        self.repo_path,
                        file.new_path,
                    )
                assert extracted_macros_codes is not None
                source_code = code_transformation.code_transformation(
                    extracted_macros_codes, language
                )
                diff_and_sc = {
                    "diff": gitdiff(source_code_before, source_code),
                    "source_code_before": source_code_before,
                    "source_code": source_code,
                }
                modification = Modification(
                    file.old_path, file.new_path, file.change_type, diff_and_sc
                )
                self.modify_files.append(modification)

        self.language = language
        self.pre_include_files = set()
        self.pre_include_methods = set()
        self.post_include_files = set()
        self.post_include_methods = set()
        self.pre_project = Project(f"pre", self.pre_modify_files, language)
        self.post_project = Project(f"post", self.post_modify_files, language)

    @cached_property
    def pre_files(self):
        try:
            pre_commit = self.git_commit.parents[0]
            all_blob_contents = self.get_all_blobs(pre_commit.tree)
        except:
            pre_commit = self.git_repo.commit(f"{self.commit_id}~1")
            all_blob_contents = self.get_all_blobs(pre_commit.tree)

        return all_blob_contents

    @cached_property
    def post_files(self):
        all_blob_contents = self.get_all_blobs(self.git_commit.tree)
        return all_blob_contents

    def get_one_blob(self, blob):
        all_blob_contents = {}
        file_path = blob.path
        file_content = blob.data_stream.read().decode("utf-8", errors="ignore")
        all_blob_contents[file_path] = file_content
        return all_blob_contents

    def get_all_blobs(self, root_tree):
        all_blob_contents = {}
        worker_list = []
        for blob in root_tree.traverse():
            if blob.type == "blob":
                file_path = blob.path
                file_content = blob.data_stream.read().decode("utf-8", errors="ignore")
                all_blob_contents[file_path] = file_content

        return all_blob_contents

    @property
    def added_files(self) -> list[File]:
        file_name_list = (
            self.post_project.files_path_set - self.pre_project.files_path_set
        )
        file_list = []
        for file_name in file_name_list:
            file = self.post_project.get_file(file_name)
            if file is not None:
                file_list.append(file)
        return file_list

    @property
    def deleted_files(self) -> list[File]:
        file_name_list = (
            self.pre_project.files_path_set - self.post_project.files_path_set
        )
        file_list = []
        for file_name in file_name_list:
            file = self.post_project.get_file(file_name)
            if file is not None:
                file_list.append(file)
        return file_list

    @property
    def added_imports(self) -> list[Import]:
        import_name_list = (
            self.post_project.imports_signature_set
            - self.pre_project.imports_signature_set
        )
        import_list = []
        for import_name in import_name_list:
            import_ = self.post_project.get_import(import_name)
            if import_ is not None:
                import_list.append(import_)
        return import_list

    @property
    def deleted_imports(self) -> list[Import]:
        import_name_list = (
            self.pre_project.imports_signature_set
            - self.post_project.imports_signature_set
        )
        import_list = []
        for import_name in import_name_list:
            import_ = self.post_project.get_import(import_name)
            if import_ is not None:
                import_list.append(import_)
        return import_list

    @property
    def added_classes(self) -> list[Class]:
        class_name_list = (
            self.post_project.classes_signature_set
            - self.pre_project.classes_signature_set
        )
        class_list = []
        for class_name in class_name_list:
            clazz = self.post_project.get_class(class_name)
            if clazz is not None:
                class_list.append(clazz)
        return class_list

    @property
    def deleted_classes(self) -> list[Class]:
        class_name_list = (
            self.pre_project.classes_signature_set
            - self.post_project.classes_signature_set
        )
        class_list = []
        for class_name in class_name_list:
            clazz = self.post_project.get_class(class_name)
            if clazz is not None:
                class_list.append(clazz)
        return class_list

    @property
    def added_methods(self) -> list[Method]:
        method_name_list = (
            self.post_project.methods_signature_set
            - self.pre_project.methods_signature_set
        )
        method_list = []
        change_method_map_dict = self.change_method_map_dict
        for method_name in method_name_list:
            method = self.post_project.get_method(method_name)
            if method is not None and method not in change_method_map_dict.values():
                method_list.append(method)
        return method_list

    @property
    def added_methods_set(self) -> set[str]:
        return (
            self.post_project.methods_signature_set
            - self.pre_project.methods_signature_set
        )

    @property
    def change_method_map_dict(self):
        change_method_map_dict = {}
        for file in self.modify_files:
            path = file.new_path
            if path is None:
                continue
            pre_file = self.pre_project.get_file(path)
            post_file = self.post_project.get_file(path)
            if pre_file is None:
                continue
            if post_file is None:
                continue
            add_lines = set([line[0] for line in file.diff_parsed["added"]])
            delete_lines = set([line[0] for line in file.diff_parsed["deleted"]])
            new_old_map = {}
            old_new_map = {}
            delete = 1
            add = 1
            for i in range(1, 100000):
                while delete in delete_lines:
                    delete += 1
                while add in add_lines:
                    add += 1
                old_new_map[delete] = add
                new_old_map[add] = delete
                delete += 1
                add += 1
            del_not_modified_line = {}
            add_not_modified_line = {}
            for method in pre_file.methods:
                if (
                    method.signature
                    in self.added_methods_set | self.deleted_methods_set
                ):
                    method_line_set = set(
                        range(method.body_start_line, method.body_end_line + 1)
                    )
                    deleted = True
                    for line in method_line_set:
                        if line not in delete_lines and line in method.body_lines:
                            del_not_modified_line[method.signature] = line
                            deleted = False
                            break
                    if deleted:
                        continue
            for method in post_file.methods:
                if (
                    method.signature
                    in self.added_methods_set | self.deleted_methods_set
                ):
                    method_line_set = set(
                        range(method.body_start_line, method.body_end_line + 1)
                    )
                    added = True
                    for line in method_line_set:
                        if line not in add_lines and line in method.body_lines:
                            add_not_modified_line[method.signature] = line
                            added = False
                            break
                    if added:
                        continue
            for del_method in del_not_modified_line.keys():
                if del_method in self.added_methods_set:
                    continue
                for add_method in add_not_modified_line.keys():
                    if (
                        old_new_map[del_not_modified_line[del_method]]
                        == add_not_modified_line[add_method]
                    ):
                        change_method_map_dict[del_method] = (add_method, path)
        return change_method_map_dict

    @property
    def deleted_methods(self) -> list[Method]:
        method_name_list = (
            self.pre_project.methods_signature_set
            - self.post_project.methods_signature_set
        )
        change_method_map_dict = self.change_method_map_dict
        method_list = []
        for method_name in method_name_list:
            method = self.post_project.get_method(method_name)
            if (
                method is not None
                and method.signature not in change_method_map_dict.keys()
            ):
                method_list.append(method)
        return method_list

    @property
    def deleted_methods_set(self) -> set[str]:
        return (
            self.pre_project.methods_signature_set
            - self.post_project.methods_signature_set
        )

    @property
    def added_fields(self) -> list[Field]:
        field_name_list = (
            self.post_project.fields_signature_set
            - self.pre_project.fields_signature_set
        )
        field_list = []
        for field_name in field_name_list:
            field = self.post_project.get_field(field_name)
            if field is not None:
                field_list.append(field)
        return field_list

    @property
    def deleted_fields(self) -> list[Field]:
        field_name_list = (
            self.pre_project.fields_signature_set
            - self.post_project.fields_signature_set
        )
        field_list = []
        for field_name in field_name_list:
            field = self.post_project.get_field(field_name)
            if field is not None:
                field_list.append(field)
        return field_list

    @property
    def changed_files(self) -> list[File]:
        file_name_list = []
        for file in self.modify_files:
            file_name_list.append(file.new_path)
        file_list = []
        for file_name in file_name_list:
            file = self.post_project.get_file(file_name)
            if file is not None:
                file_list.append(file)
        return file_list

    @property
    def avarage_method_change(self) -> float:
        changed_methods = self.changed_methods
        total_lines = 0
        for method_sig in changed_methods:
            pre_method = self.pre_project.get_method(method_sig)
            post_method = self.post_project.get_method(method_sig)
            if pre_method is None or post_method is None:
                continue
            changed_lines = len(pre_method.diff_lines)
            total_lines += changed_lines
        if len(changed_methods) == 0:
            return 0
        return total_lines / len(changed_methods)

    @property
    def changed_methods(self) -> set[str]:
        changed_methods: set[str] = set()
        for file in self.modify_files:
            path = file.new_path
            if path is None:
                continue
            pre_file = self.pre_project.get_file(path)
            post_file = self.post_project.get_file(path)
            if pre_file is None:
                continue
            if post_file is None:
                continue
            add_lines = set([line[0] for line in file.diff_parsed["added"]])
            delete_lines = set([line[0] for line in file.diff_parsed["deleted"]])
            for method in pre_file.methods:
                if (
                    method.signature
                    in self.added_methods_set | self.deleted_methods_set
                ):
                    method_line_set = set(
                        range(method.body_start_line, method.body_end_line + 1)
                    )
                    continue
                method_line_set = set(
                    range(method.body_start_line, method.body_end_line + 1)
                )
                method_deleted_lines = method_line_set & delete_lines
                if method_deleted_lines:
                    changed_methods.add(method.signature)
            for method in post_file.methods:
                if (
                    method.signature
                    in self.added_methods_set | self.deleted_methods_set
                ):
                    continue
                method_line_set = set(
                    range(method.body_start_line, method.body_end_line + 1)
                )
                method_added_lines = method_line_set & add_lines
                if method_added_lines:
                    changed_methods.add(method.signature)
        for method in changed_methods.copy():
            pre_method = self.pre_project.get_method(method)
            post_method = self.post_project.get_method(method)
            if pre_method is None or post_method is None:
                continue
            if pre_method.normalized_body_code == post_method.normalized_body_code:
                changed_methods.remove(method)
            pre_method.counterpart = post_method
            post_method.counterpart = pre_method

        change_method_map_dict = self.change_method_map_dict
        for pre_method_name in change_method_map_dict.keys():
            pre_method = self.pre_project.get_method(pre_method_name)
            post_method = self.post_project.get_method(
                change_method_map_dict[pre_method_name][0]
            )
            if pre_method is None or post_method is None:
                continue
            pre_method.counterpart = post_method
            post_method.counterpart = pre_method
            changed_methods.add(pre_method_name)
        return changed_methods

    @cached_property
    def changed_method_file_map(self):
        changed_methods = set()
        for file in self.modify_files:
            path = file.new_path
            if path is None:
                continue
            pre_file = self.pre_project.get_file(path)
            post_file = self.post_project.get_file(path)
            if pre_file is None:
                continue
            if post_file is None:
                continue
            add_lines = set([line[0] for line in file.diff_parsed["added"]])
            delete_lines = set([line[0] for line in file.diff_parsed["deleted"]])
            for method in pre_file.methods:
                if (
                    method.signature
                    in self.added_methods_set | self.deleted_methods_set
                ):
                    method_line_set = set(
                        range(method.body_start_line, method.body_end_line + 1)
                    )
                    continue
                method_line_set = set(
                    range(method.body_start_line, method.body_end_line + 1)
                )
                method_deleted_lines = method_line_set & delete_lines
                if method_deleted_lines:
                    changed_methods.add((method.signature, file.new_path))
            for method in post_file.methods:
                if (
                    method.signature
                    in self.added_methods_set | self.deleted_methods_set
                ):
                    continue
                method_line_set = set(
                    range(method.body_start_line, method.body_end_line + 1)
                )
                method_added_lines = method_line_set & add_lines
                if method_added_lines:
                    changed_methods.add((method.signature, file.new_path))

        for method in changed_methods.copy():
            pre_method = self.pre_project.get_method(method[0])
            post_method = self.post_project.get_method(method[0])
            if pre_method is None or post_method is None:
                continue
            if pre_method.normalized_body_code == post_method.normalized_body_code:
                changed_methods.remove(method)
            pre_method.counterpart = post_method
            post_method.counterpart = pre_method

        change_method_map_dict = self.change_method_map_dict
        for pre_method_name in change_method_map_dict.keys():
            pre_method = self.pre_project.get_method(pre_method_name)
            post_method = self.post_project.get_method(
                change_method_map_dict[pre_method_name][0]
            )
            if pre_method is None or post_method is None:
                continue
            pre_method.counterpart = post_method
            post_method.counterpart = pre_method
            changed_methods.add(
                (pre_method_name, change_method_map_dict[pre_method_name][1])
            )
        change_map = {}
        for method_name, file_name in changed_methods:
            change_map[method_name] = file_name
        return change_map

    def format(self, FilePath, ispre):
        if ispre:
            codes = self.pre_files[FilePath]
            extracted_macros_codes = codes
            if self.language == Language.CPP:
                extracted_macros_codes = code_transformation.extraction_macros(
                    codes,
                    self.repo_path,
                    FilePath,
                    self.commit_id + "~1",
                    self.pre_files,
                )
        else:
            codes = self.post_files[FilePath]
            extracted_macros_codes = codes
            if self.language == Language.CPP:
                extracted_macros_codes = code_transformation.extraction_macros(
                    codes, self.repo_path, FilePath, self.commit_id, self.post_files
                )

        assert extracted_macros_codes is not None
        source_code_before = code_transformation.code_transformation(
            extracted_macros_codes, self.language
        )
        assert source_code_before is not None
        codefile = CodeFile(FilePath, source_code_before, isformat=False)
        return codefile

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

    def pre_bfs_search_files(self, filepath, methodname, step=0):
        if step >= 3:
            return
        callees = set()
        if filepath not in self.pre_include_files:
            self.pre_include_files.add(filepath)

        file_contents = self.get_file_content(self.pre_files[filepath])
        for method_name, method_contents in file_contents:
            if methodname == method_name:
                callees = self.get_callee(method_contents)
                break
        if callees is None:
            return
        if len(callees) == 0:
            return
        self.pre_include_methods.update(file_contents)
        for method_name, method_contents in list(self.pre_include_methods):
            if method_name in callees:
                self.pre_bfs_search_files(filepath, method_name, step + 1)
                callees.remove(method_name)
        if len(callees) == 0:
            return
        code = self.pre_files[filepath]

        parser = ASTParser(code, self.language)
        if self.language == Language.CPP:
            includes = parser.query_all(ast_parser.CPP_INCLUDE)
            suffix_list = [".c", ".cc", ".cxx", ".cpp"]
            for include in includes:
                include_name = include.text.decode()
                prefix = os.path.dirname(filepath)
                if os.path.join(prefix, include_name) in self.pre_files:
                    for suffix in suffix_list:
                        if (
                            os.path.join(prefix, include_name.replace(".h", suffix))
                            in self.pre_files
                        ):
                            file_contents = self.get_file_content(
                                self.pre_files[
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
                                        in self.pre_include_files
                                    ):
                                        continue
                                    self.pre_include_files.add(
                                        os.path.join(
                                            prefix, include_name.replace(".h", suffix)
                                        )
                                    )
                                    self.pre_include_methods.update(file_contents)
                                    self.pre_bfs_search_files(
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
                        self.pre_files[os.path.join(prefix, include_name)]
                    )
                    for method_name, method_contents in file_contents:
                        if method_name in callees:
                            if (
                                os.path.join(prefix, include_name)
                                in self.pre_include_files
                            ):
                                continue
                            self.pre_include_files.add(
                                os.path.join(prefix, include_name)
                            )
                            self.pre_include_methods.update(file_contents)
                            self.pre_bfs_search_files(
                                os.path.join(prefix, include_name),
                                method_name,
                                step + 1,
                            )
                            callees.remove(method_name)

                            if len(callees) == 0:
                                break

                    if len(callees) == 0:
                        break
                elif os.path.join(prefix, "include", include_name) in self.pre_files:
                    for suffix in suffix_list:
                        if os.path.isfile(
                            os.path.join(
                                self.repo_path,
                                prefix,
                                include_name.replace(".h", suffix),
                            )
                        ) and not os.path.islink(
                            os.path.join(
                                self.repo_path,
                                prefix,
                                include_name.replace(".h", suffix),
                            )
                        ):
                            file_contents = self.get_file_content(
                                self.pre_files[
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
                                        in self.pre_include_files
                                    ):
                                        continue
                                    self.pre_include_files.add(
                                        os.path.join(
                                            prefix, include_name.replace(".h", suffix)
                                        )
                                    )
                                    self.pre_include_methods.update(file_contents)
                                    self.pre_bfs_search_files(
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
                            in self.pre_files
                        ):
                            file_contents = self.get_file_content(
                                self.pre_files[
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
                                        in self.pre_include_files
                                    ):
                                        continue
                                    self.pre_include_files.add(
                                        os.path.join(
                                            prefix,
                                            "src",
                                            include_name.replace(".h", suffix),
                                        )
                                    )
                                    self.pre_include_methods.update(file_contents)
                                    self.pre_bfs_search_files(
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
                        self.pre_files[os.path.join(prefix, "include", include_name)]
                    )
                    for method_name, method_contents in file_contents:
                        if method_name in callees:
                            if (
                                os.path.join(prefix, "include", include_name)
                                in self.pre_include_files
                            ):
                                continue
                            self.pre_include_files.add(
                                os.path.join(prefix, "include", include_name)
                            )
                            self.pre_include_methods.update(file_contents)
                            self.pre_bfs_search_files(
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
                    in self.pre_files
                ):
                    file_contents = self.get_file_content(
                        self.pre_files[
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
                                in self.pre_include_files
                            ):
                                continue
                            self.pre_include_files.add(
                                os.path.join(
                                    prefix, include_name.replace(".", "/") + ".java"
                                )
                            )
                            self.pre_include_methods.update(file_contents)
                            self.pre_bfs_search_files(
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
                    in self.pre_files
                ):
                    file_contents = self.get_file_content(
                        self.pre_files[
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
                                in self.pre_include_files
                            ):
                                continue
                            self.pre_include_files.add(
                                os.path.join(
                                    raw_dir, include_name.replace(".", "/") + ".java"
                                )
                            )
                            self.pre_include_methods.update(file_contents)
                            self.pre_bfs_search_files(
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

    def post_bfs_search_files(self, filepath, methodname, step=0):
        if step >= 3:
            return
        callees = set()
        if filepath not in self.post_include_files:
            self.post_include_files.add(filepath)

        file_contents = self.get_file_content(self.post_files[filepath])
        for method_name, method_contents in file_contents:
            if methodname == method_name:
                callees = self.get_callee(method_contents)
                break
        if callees is None:
            return
        self.post_include_methods.update(file_contents)
        for method_name, method_contents in list(self.post_include_methods):
            if method_name in callees:
                self.post_bfs_search_files(filepath, method_name, step + 1)
                callees.remove(method_name)
        if len(callees) == 0:
            return

        code = self.post_files[filepath]

        parser = ASTParser(code, self.language)
        if self.language == Language.CPP:
            includes = parser.query_all(ast_parser.CPP_INCLUDE)
            suffix_list = [".c", ".cc", ".cxx", ".cpp"]
            for include in includes:
                include_name = include.text.decode()
                prefix = os.path.dirname(filepath)
                if os.path.join(prefix, include_name) in self.post_files:
                    for suffix in suffix_list:
                        if (
                            os.path.join(prefix, include_name.replace(".h", suffix))
                            in self.post_files
                        ):
                            file_contents = self.get_file_content(
                                self.post_files[
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
                                        in self.post_include_files
                                    ):
                                        continue
                                    self.post_include_files.add(
                                        os.path.join(
                                            prefix, include_name.replace(".h", suffix)
                                        )
                                    )
                                    self.post_include_methods.update(file_contents)
                                    self.post_bfs_search_files(
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
                        self.post_files[os.path.join(prefix, include_name)]
                    )
                    for method_name, method_contents in file_contents:
                        if method_name in callees:
                            if (
                                os.path.join(prefix, include_name)
                                in self.post_include_files
                            ):
                                continue
                            self.post_include_files.add(
                                os.path.join(prefix, include_name)
                            )
                            self.post_include_methods.update(file_contents)
                            self.post_bfs_search_files(
                                os.path.join(prefix, include_name),
                                method_name,
                                step + 1,
                            )
                            callees.remove(method_name)

                            if len(callees) == 0:
                                break

                    if len(callees) == 0:
                        break
                elif os.path.join(prefix, "include", include_name) in self.post_files:
                    for suffix in suffix_list:
                        if os.path.isfile(
                            os.path.join(
                                self.repo_path,
                                prefix,
                                include_name.replace(".h", suffix),
                            )
                        ) and not os.path.islink(
                            os.path.join(
                                self.repo_path,
                                prefix,
                                include_name.replace(".h", suffix),
                            )
                        ):
                            file_contents = self.get_file_content(
                                self.post_files[
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
                                        in self.post_include_files
                                    ):
                                        continue
                                    self.post_include_files.add(
                                        os.path.join(
                                            prefix, include_name.replace(".h", suffix)
                                        )
                                    )
                                    self.post_include_methods.update(file_contents)
                                    self.post_bfs_search_files(
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
                            in self.post_files
                        ):
                            file_contents = self.get_file_content(
                                self.post_files[
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
                                        in self.post_include_files
                                    ):
                                        continue
                                    self.post_include_files.add(
                                        os.path.join(
                                            prefix,
                                            "src",
                                            include_name.replace(".h", suffix),
                                        )
                                    )
                                    self.post_include_methods.update(file_contents)
                                    self.post_bfs_search_files(
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
                        self.post_files[os.path.join(prefix, "include", include_name)]
                    )
                    for method_name, method_contents in file_contents:
                        if method_name in callees:
                            if (
                                os.path.join(prefix, "include", include_name)
                                in self.post_include_files
                            ):
                                continue
                            self.post_include_files.add(
                                os.path.join(prefix, "include", include_name)
                            )
                            self.post_include_methods.update(file_contents)
                            self.post_bfs_search_files(
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
                    in self.pre_files
                ):
                    file_contents = self.get_file_content(
                        self.pre_files[
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
                                in self.pre_include_files
                            ):
                                continue
                            self.pre_include_files.add(
                                os.path.join(
                                    prefix, include_name.replace(".", "/") + ".java"
                                )
                            )
                            self.pre_include_methods.update(file_contents)
                            self.pre_bfs_search_files(
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
                    in self.pre_files
                ):
                    file_contents = self.get_file_content(
                        self.pre_files[
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
                                in self.pre_include_files
                            ):
                                continue
                            self.pre_include_files.add(
                                os.path.join(
                                    raw_dir, include_name.replace(".", "/") + ".java"
                                )
                            )
                            self.pre_include_methods.update(file_contents)
                            self.pre_bfs_search_files(
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

    @cached_property
    def pre_analysis_files(self):
        results = []
        for method_sig in self.changed_methods:
            if self.language == Language.JAVA:
                self.pre_bfs_search_files(
                    method_sig.split("#")[0], method_sig.split("#")[1]
                )
            else:
                self.pre_bfs_search_files(
                    method_sig.split("#")[0], method_sig.split("#")[1]
                )

        worker_list = []
        for file in self.pre_include_files:
            worker_list.append((file, True))

        results = cpu_heater.multithreads(
            self.format, worker_list, max_workers=512, show_progress=False
        )

        return results

    @cached_property
    def post_analysis_files(self):
        results = []

        for method_sig in self.changed_methods:
            self.post_bfs_search_files(
                method_sig.split("#")[0], method_sig.split("#")[1]
            )

        worker_list = []
        for file in self.post_include_files:
            worker_list.append((file, False))

        results = cpu_heater.multithreads(
            self.format, worker_list, max_workers=512, show_progress=False
        )

        return results

    def findLargestDir(self, min_dir, is_pre):
        split_list = min_dir.split("/")
        length = len(split_list)
        suffix_list = ["c", "cc", "cxx", "cpp", "c++", "h"]
        count = 0
        if is_pre:
            result = subprocess.run(
                ["git", "checkout", "-f", self.commit_id + "~1"],
                cwd=f"{self.repo_path}",
                check=True,
                text=True,
                capture_output=True,
            )
        else:
            result = subprocess.run(
                ["git", "checkout", "-f", self.commit_id],
                cwd=f"{self.repo_path}",
                check=True,
                text=True,
                capture_output=True,
            )
        for i in range(length, 0, -1):
            temp_dir = "/".join(split_list[:i])
            count = 0
            for _, _, files in os.walk(self.repo_path + temp_dir):
                for file in files:
                    for suffix in suffix_list:
                        if file.endswith(suffix):
                            count += 1
            if count > config.file_num_threshold:
                if i == length:
                    return config.warning_info
                else:
                    return self.repo_path + "/".join(split_list[: i + 1])
        return self.repo_path

    def LCP(self, old_file_relative_name_list):
        prefix = old_file_relative_name_list[0].file_path
        for i in range(1, len(old_file_relative_name_list)):
            prefix = self.lcp(prefix, old_file_relative_name_list[i].file_path)
            if not prefix:
                break
        return prefix

    def lcp(self, str1, str2):
        length, index = min(len(str1), len(str2)), 0
        while index < length and str1[index] == str2[index]:
            index += 1
        return str1[:index]

    @property
    def pre_modify_files(self) -> list[CodeFile]:
        result = []
        for file in self.modify_files:
            assert file.new_path is not None
            file = CodeFile(file.new_path, file.source_code_before)
            result.append(file)
        for file in self.del_files:
            assert file.old_path is not None
            file = CodeFile(file.old_path, file.source_code_before)
            result.append(file)
        return result

    @property
    def post_modify_files(self) -> list[CodeFile]:
        result = []
        for file in self.modify_files:
            assert file.new_path is not None
            file = CodeFile(file.new_path, file.source_code, isformat=False)
            result.append(file)
        for file in self.add_files:
            assert file.new_path is not None
            file = CodeFile(file.new_path, file.source_code)
            result.append(file)
        return result

    @staticmethod
    def is_patch_related_file(file: str | Modification, language: Language) -> bool:
        if language == Language.CPP:
            extension = ["c", "cpp", "c++", "cc", "C", "cxx", "h"]
        elif language == Language.JAVA:
            extension = ["java"]
        if isinstance(file, str):
            return file.split(".")[-1] in extension and "test/" not in file
        if isinstance(file, Modification):
            if file.filename.split(".")[-1] not in extension:
                return False
            if (
                file.change_type == ModificationType.MODIFY
                and file.new_path is not None
            ):
                file_path = file.new_path
            elif file.change_type == ModificationType.ADD and file.new_path is not None:
                file_path = file.new_path
            elif (
                file.change_type == ModificationType.DELETE
                and file.old_path is not None
            ):
                file_path = file.old_path
            else:
                return False
            return "test/" not in file_path and "tests/" not in file_path

    @cached_property
    def pre_analysis_project(self):
        return Project(f"pre", self.pre_analysis_files, self.language)

    @cached_property
    def post_analysis_project(self):
        return Project(f"post", self.post_analysis_files, self.language)


class DiffBlob:
    def __init__(self, blob: Diff):
        self.a_path = blob.a_path
        self.b_path = blob.b_path
        self.change_type = blob.change_type
        self.a_blob_content: str | None = None
        self.b_blob_content: str | None = None
        self.hunks: list[Hunk] = []

        if blob.a_path is None and blob.b_path is not None:
            self.change_type = "A"
        elif blob.a_path is not None and blob.b_path is None:
            self.change_type = "D"
        elif (
            blob.a_path is not None
            and blob.b_path is not None
            and blob.a_path == blob.b_path
        ):
            self.change_type = "C"
        elif (
            blob.a_path is not None
            and blob.b_path is not None
            and blob.a_path != blob.b_path
        ):
            self.change_type = "M"
        else:
            self.change_type = "U"

        if self.a_path is not None and blob.a_blob is not None:
            self.a_blob_content = blob.a_blob.data_stream.read().decode("utf-8")
        if self.b_path is not None and blob.b_blob is not None:
            self.b_blob_content = blob.b_blob.data_stream.read().decode("utf-8")

        if self.change_type == "M" or self.change_type == "C":
            self.hunks = self.parse_hunks(blob.diff.decode("utf-8"))

    def parse_hunks(self, diff: str) -> list:
        hunks_content: list[str] = []
        iter = re.finditer(r"@@.*?@@", diff)
        indices = [m.start(0) for m in iter]
        for i, v in enumerate(indices):
            if i == len(indices) - 1:
                hunks_content.append(diff[v:])
            else:
                hunks_content.append(diff[v : indices[i + 1]])
        hunks: list[Hunk] = []
        for hc in hunks_content:
            hunk = Hunk(hc)
            hunks.append(hunk)
        return hunks


class Hunk:
    def __init__(self, hunk_content: str):
        first_lf = hunk_content.find("\n")
        self.hunk_header = hunk_content[: first_lf + 1]
        self.hunk_content = hunk_content[first_lf + 1 :]
        self.a_start_line = 0
        self.a_num_lines = 0
        self.b_start_line = 0
        self.b_num_lines = 0
        self.add_lines: dict[int, str] = {}
        self.del_lines: dict[int, str] = {}

        lineinfo = re.match(r"@@ -(\d+),(\d+) \+(\d+),(\d+) @@", hunk_content).groups()
        self.a_start_line = int(lineinfo[0])
        self.a_num_lines = int(lineinfo[1])
        self.b_start_line = int(lineinfo[2])
        self.b_num_lines = int(lineinfo[3])

        lines = self.hunk_content.split("\n")
        for line in lines:
            if line.startswith("+"):
                self.add_lines[self.b_start_line] = line[1:]
                self.b_start_line += 1
            elif line.startswith("-"):
                self.del_lines[self.a_start_line] = line[1:]
                self.a_start_line += 1
            else:
                self.a_start_line += 1
                self.b_start_line += 1
