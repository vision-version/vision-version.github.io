from __future__ import annotations

import ast
from crypt import methods
import json
import os
import subprocess
import sys
from collections import deque
from functools import cached_property

import networkx as nx
from tree_sitter import Node

import ast_parser
import code_transformation
import format_code
import joern
from ast_parser import ASTParser
from codefile import CodeFile
from common import Language
from diffparser import AddHunk, DelHunk, Hunk, ModHunk, get_patch_hunks
from joern import PDGNode
from json2dot import convert_to_dot


def group_consecutive_ints(nums: list[int]):
    if len(nums) == 0:
        return []
    nums.sort()
    result = [[nums[0]]]
    for num in nums[1:]:
        if num == result[-1][-1] + 1:
            result[-1].append(num)
        else:
            result.append([num])
    return result


class ProjectJoern:
    def __init__(self, cpg_dir: str, pdg_dir: str):
        self.cpg = joern.CPG(cpg_dir)
        self.pdgs: dict[tuple[int, str, str], joern.PDG] = self.build_pdgs(pdg_dir)
        self.path = cpg_dir.replace("/cpg", "")

    def build_pdgs(self, pdg_dir: str):
        dot_names = os.listdir(pdg_dir)
        pdgs: dict[tuple[int, str, str], joern.PDG] = {}
        for dot in dot_names:
            dot_path = os.path.join(pdg_dir, dot)
            try:
                pdg = joern.PDG(pdg_path=dot_path)
            except Exception as e:
                continue
            if pdg.name is None or pdg.line_number is None or pdg.filename is None:
                continue
            pdgs[(pdg.line_number, pdg.name, pdg.filename)] = pdg
        return pdgs

    def get_pdg(self, method: Method) -> joern.PDG | None:
        if self.pdgs.get((method.start_line, method.name, method.file.path)) is None:
            if (
                self.pdgs.get((method.start_line + 1, method.name, method.file.path))
                is None
            ):
                return self.pdgs.get(
                    (method.start_line - 1, method.name, method.file.path)
                )
            else:
                return self.pdgs.get(
                    (method.start_line + 1, method.name, method.file.path)
                )
        else:
            return self.pdgs.get((method.start_line, method.name, method.file.path))


class Project:
    def __init__(self, project_name: str, files: list[CodeFile], language: Language):
        self.project_name: str = project_name
        self.language: Language = language
        self.files: list[File] = []

        self.files_path_set: set[str] = set()
        self.imports_signature_set: set[str] = set()
        self.classes_signature_set: set[str] = set()
        self.methods_signature_set: set[str] = set()
        self.fields_signature_set: set[str] = set()

        for file in files:
            file = File(file.file_path, file.formated_code, self, language)
            self.files.append(file)
            self.files_path_set.add(file.path)
            if language == Language.JAVA:
                self.imports_signature_set.update(
                    [import_.signature for import_ in file.imports]
                )
                self.classes_signature_set.update(
                    [clazz.fullname for clazz in file.classes]
                )
                self.methods_signature_set.update(
                    [
                        method.signature
                        for clazz in file.classes
                        for method in clazz.methods
                    ]
                )
                self.fields_signature_set.update(
                    [
                        field.signature
                        for clazz in file.classes
                        for field in clazz.fields
                    ]
                )
            elif language == Language.CPP:
                self.imports_signature_set.update(
                    [import_.signature for import_ in file.imports]
                )
                self.methods_signature_set.update(
                    [method.signature for method in file.methods]
                )

        self.joern: ProjectJoern | None = None

    def load_joern_graph(self, cpg_dir: str, pdg_dir: str):
        self.joern = ProjectJoern(cpg_dir, pdg_dir)

    def get_file(self, path: str) -> File | None:
        for file in self.files:
            if file.path == path:
                return file
        return None

    def get_import(self, signature: str) -> Import | None:
        for file in self.files:
            for import_ in file.imports:
                if import_.signature == signature:
                    return import_
        return None

    def get_class(self, fullname: str) -> Class | None:
        for file in self.files:
            for clazz in file.classes:
                if clazz.fullname == fullname:
                    return clazz
        return None

    def get_method(self, fullname: str) -> Method | None:
        if self.language == Language.JAVA:
            for file in self.files:
                for clazz in file.classes:
                    for method in clazz.methods:
                        if method.signature == fullname:
                            return method
        elif self.language == Language.CPP:
            for file in self.files:
                for method in file.methods:
                    if method.signature == fullname:
                        return method
        return None

    def get_field(self, fullname: str) -> Field | None:
        for file in self.files:
            for clazz in file.classes:
                for field in clazz.fields:
                    if field.signature == fullname:
                        return field
        return None

    @cached_property
    def cpg(self):
        return self.joern.cpg.g

    def get_callee(self, fullname: str):
        callees = []
        method = self.get_method(fullname)
        if method is None:
            return callees
        assert method is not None
        method_ids = method.line_number_pdg_map[0]
        line_map_method_nodes = method.line_number_pdg_map[1]
        call_ids = set()
        cpg = self.cpg
        for node in cpg.nodes:
            if (
                cpg.nodes[node]["label"] == "CALL"
                and int(cpg.nodes[node]["LINE_NUMBER"]) >= method.start_line
                and int(cpg.nodes[node]["LINE_NUMBER"]) <= method.end_line
            ):
                call_ids.add(node)

        for u, v, d in cpg.edges(data=True):
            try:
                if (
                    d["label"] == "CALL"
                    and (u in method_ids or u in call_ids)
                    and "LINE_NUMBER" in cpg.nodes[v].keys()
                ):
                    if "label" in cpg.nodes[v] and cpg.nodes[v]["label"] == "METHOD":
                        line_number = next(
                            (
                                key
                                for key, value in line_map_method_nodes.items()
                                if u in value
                            ),
                            None,
                        )
                        if line_number is None:
                            continue
                        callees.append(
                            {
                                "callee_linenumber": line_number,
                                "callee_method_name": f"{cpg.nodes[v]['FILENAME']}#{cpg.nodes[v]['NAME']}",
                                "method_line_number": cpg.nodes[v]["LINE_NUMBER"],
                            }
                        )
            except:
                continue
        return callees

    def get_methods(self):
        methods = []
        for file in self.files:
            for method in file.methods:
                methods.append(method.signature)
        return methods

class File:
    def __init__(
        self, path: str, content: str, project: Project | None, language: Language
    ):
        parser = ASTParser(content, language)
        self.language = language
        self.project = project
        self.parser = parser
        self.path = path
        self.name = os.path.basename(path)
        self.code = content

        if project is None:
            self.project = Project("None", [CodeFile(path, content)], language)
        else:
            self.project = project

    @cached_property
    def package(self) -> str:
        assert self.language == Language.JAVA
        package_node = self.parser.query_oneshot(ast_parser.TS_JAVA_PACKAGE)
        return package_node.text.decode() if package_node is not None else "<NONE>"

    @cached_property
    def imports(self) -> list[Import]:
        if self.language == Language.JAVA:
            return [
                Import(import_node, self, self.language)
                for import_node in self.parser.query_all(ast_parser.TS_JAVA_IMPORT)
            ]
        elif self.language == Language.CPP:
            return [
                Import(import_node, self, self.language)
                for import_node in self.parser.query_all(ast_parser.TS_C_INCLUDE)
            ]
        else:
            return []

    @cached_property
    def classes(self) -> list[Class]:
        if self.language == Language.JAVA:
            return [
                Class(class_node, self, self.language)
                for class_node in self.parser.query_all(ast_parser.TS_JAVA_CLASS)
            ]
        else:
            return []

    @cached_property
    def fields(self) -> list[Field]:
        return [field for clazz in self.classes for field in clazz.fields]

    @cached_property
    def methods(self) -> list[Method]:
        if self.language == Language.JAVA:
            return [method for clazz in self.classes for method in clazz.methods]
        elif self.language == Language.CPP:
            methods: list[Method] = []
            query = ast_parser.TS_C_METHOD
            methods_dict = {}
            methods_intervals = []
            for method_node in self.parser.query_all(query):
                if method_node.text.decode().lstrip().startswith("namespace"):
                    continue
                methods_dict[
                    f"{method_node.start_point[0]}##{method_node.end_point[0]}"
                ] = method_node
                methods_intervals.append(
                    (method_node.start_point[0], method_node.end_point[0])
                )
            methods_intervals = self.merge_intervals(methods_intervals)
            for st, ed in methods_intervals:
                if st == ed:
                    continue
                if f"{st}##{ed}" in methods_dict.keys():
                    methods.append(
                        Method(methods_dict[f"{st}##{ed}"], None, self, self.language)
                    )
            return methods
        else:
            return []

    def merge_intervals(self, intervals):
        if not intervals:
            return []
        intervals.sort(key=lambda x: x[0])

        merged = [intervals[0]]

        for current in intervals[1:]:
            last = merged[-1]

            if current[0] <= last[1]:
                merged[-1] = [last[0], max(last[1], current[1])]
            else:
                merged.append(current)

        return merged


class Import:
    def __init__(self, node: Node, file: File, language: Language):
        self.file = file
        self.node = node
        self.code = node.text.decode()
        self.signature = file.path + "#" + self.code


class Class:
    def __init__(self, node: Node, file: File, language: Language):
        self.language = language
        self.file = file
        self.code = node.text.decode()
        self.node = node
        name_node = node.child_by_field_name("name")
        if name_node is None:
            return
        self.name = name_node.text.decode()
        self.fullname = f"{file.package}.{self.name}"

    @cached_property
    def fields(self):
        file = self.file
        parser = file.parser
        class_node = self.node
        class_name = self.name
        fields: list[Field] = []
        query = f"""
        (class_declaration
            name: (identifier)@class.name
            (#eq? @class.name "{class_name}")
            body: (class_body
                (field_declaration)@field
            )
        )    
        """
        for field_node in parser.query_by_capture_name(query, "field", node=class_node):
            fields.append(Field(field_node, self, file))
        return fields

    @cached_property
    def methods(self):
        file = self.file
        parser = file.parser
        class_node = self.node
        class_name = self.name
        methods: list[Method] = []
        query = f"""
        (class_declaration
            name: (identifier)@class.name
            (#eq? @class.name "{class_name}")
            body: (class_body
                [(method_declaration)
                (constructor_declaration)]@method
            )
        )
        """
        for method_node in parser.query_by_capture_name(
            query, "method", node=class_node
        ):
            methods.append(Method(method_node, self, file, self.language))
        return methods


class Field:
    def __init__(self, node: Node, clazz: Class, file: File):
        self.name = (
            node.child_by_field_name("declarator")
            .child_by_field_name("name")
            .text.decode()
        )
        self.clazz = clazz
        self.file = file
        self.code = node.text.decode()
        self.signature = f"{self.clazz.fullname}.{self.name}"


class Method:
    def __init__(self, node: Node, clazz: Class | None, file: File, language: Language):
        self.language = language
        if language == Language.JAVA:
            name_node = node.child_by_field_name("name")
            assert name_node is not None and name_node.text is not None
            self.name = name_node.text.decode()
        else:
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
            self.name = name_node.text.decode()
        self.clazz = clazz
        self.file = file
        self.node = node
        assert node.text is not None
        self.code = node.text.decode()
        self.start_line = node.start_point[0] + 1
        self.end_line = node.end_point[0] + 1
        self.slice_line = None

        self.lines: dict[int, str] = {
            i + self.start_line: line for i, line in enumerate(self.code.split("\n"))
        }

        self.abs_lines: dict[int, str] = {
            i + self.start_line: line
            for i, line in enumerate(self.abstract_code.split("\n"))
        }

        self._pdg: joern.PDG | None = None

        self.joern_path: str | None = None

        self.counterpart: Method | None = None
        self.method_dir: str | None = None
        self.html_base_path: str = ""
        self.method_file: str = ""
        self.diff_add_lines: list[tuple[int, int]] = []
        self.diff_del_lines: list[tuple[int, int]] = []

    @classmethod
    def init_from_file_code(cls, path: str, language: Language):
        with open(path, "r") as f:
            code = f.read()
        file = File(path, code, None, language)
        parser = ASTParser(code, language)
        method_node = parser.query_oneshot(ast_parser.TS_C_METHOD)
        assert method_node is not None
        return cls(method_node, None, file, language)

    @property
    def pdg(self) -> joern.PDG | None:
        assert self.file.project.joern is not None
        if self._pdg is None:
            self._pdg = self.file.project.joern.get_pdg(self)
        return self._pdg

    @cached_property
    def abstract_code(self):
        return code_transformation.abstract(self.code, self.language)

    @property
    def line_pdg_pairs(self) -> dict[int, joern.PDGNode] | None:
        line_pdg_pairs = {}
        if self.pdg is None:
            return None
        for node_id in self.pdg.g.nodes():
            node = self.pdg.get_node(node_id)
            if node.line_number is None:
                continue
            line_pdg_pairs[node.line_number] = node
        return line_pdg_pairs

    @property
    def rel_line_pdg_pairs(self) -> dict[int, joern.PDGNode] | None:
        rel_line_pdg_pairs = {}
        if self.pdg is None:
            return None
        for node_id in self.pdg.g.nodes():
            node = self.pdg.get_node(node_id)
            if node.line_number is None:
                continue
            rel_line_pdg_pairs[node.line_number - self.start_line + 1] = node
        return rel_line_pdg_pairs

    @cached_property
    def line_number_pdg_map(self):
        assert self.file.project.joern is not None
        pdg_dir = os.path.join(self.file.project.joern.path, "pdg")
        dot_names = os.listdir(pdg_dir)
        for dot in dot_names:
            dot_path = os.path.join(pdg_dir, dot)
            try:
                pdg = joern.PDG(pdg_path=dot_path)
            except Exception as e:
                continue
            if pdg.name is None or pdg.line_number is None or pdg.filename is None:
                continue
            if pdg.line_number == self.start_line and pdg.filename == self.file.path:
                method_nodes = []
                line_map_method_nodes = pdg.line_map_method_nodes_id
                for line in line_map_method_nodes:
                    if isinstance(line_map_method_nodes[line], int):
                        method_nodes.append(line_map_method_nodes[line])
                        line_map_method_nodes[line] = [line_map_method_nodes[line]]
                    else:
                        method_nodes.extend(line_map_method_nodes[line])
                return [method_nodes, line_map_method_nodes]
        return [-1, -1]

    @property
    def caller(self):
        callers = []
        assert self.file.project.joern is not None
        cpg_path = os.path.join(self.file.project.joern.path, "cpg", "export.dot")
        cpg: nx.MultiDiGraph = nx.nx_agraph.read_dot(cpg_path)
        method_ids = self.line_number_pdg_map[0]
        line_map_method_nodes = self.line_number_pdg_map[1]
        for u, v, d in cpg.edges(data=True):
            if d["label"] == "CALL" and v in method_ids:
                line_number = cpg.nodes[u]["LINE_NUMBER"]
                callers.append(line_number + "__split__" + u)

        return callers

    @property
    def callee(self):
        callees = set()
        parser = ASTParser(self.code, self.language)

        call = parser.query_all(ast_parser.CPP_CALL)
        if len(call) == 0:
            return None

        for node in call:
            callees.add(node.text.decode())

        return callees

    @property
    def body_node(self) -> Node | None:
        return self.node.child_by_field_name("body")

    @property
    def body_start_line(self) -> int:
        if self.body_node is None:
            return self.start_line
        else:
            return self.body_node.start_point[0] + 1

    @property
    def body_end_line(self) -> int:
        if self.body_node is None:
            return self.end_line
        else:
            return self.body_node.end_point[0] + 1

    @property
    def diff_dir(self) -> str:
        assert self.method_dir is not None
        return f"{self.method_dir}/diff"

    @property
    def dot_dir(self) -> str:
        assert self.method_dir is not None
        return f"{self.method_dir}/dot"

    @property
    def rel_line_set(self) -> set[int]:
        return set(range(self.rel_start_line, self.rel_end_line + 1))

    @property
    def parameters(self) -> list[Node]:
        parameters_node = self.node.child_by_field_name("parameters")
        if parameters_node is None:
            return []
        parameters = ASTParser.children_by_type_name(
            parameters_node, "formal_parameter"
        )
        return parameters

    @property
    def parameter_signature(self) -> str:
        parameter_signature_list = []
        for param in self.parameters:
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
        return ",".join(parameter_signature_list)

    @property
    def signature(self) -> str:
        if self.language == Language.JAVA:
            assert self.clazz is not None
            return f"{self.file.path}#{self.name}({self.parameter_signature})"
        else:
            return f"{self.file.path}#{self.name}"

    @property
    def signature_r(self) -> str:
        if self.language == Language.JAVA:
            assert self.clazz is not None
            fullname_r = ".".join(self.clazz.fullname.split(".")[::-1])
            return f"{self.name}({self.parameter_signature}).{fullname_r}"
        else:
            return f"{self.name}#{self.start_line}#{self.end_line}#{self.file.name}"

    @property
    def diff_lines(self) -> set[int]:
        lines = set()
        for hunk in self.patch_hunks:
            if type(hunk) == DelHunk:
                lines.update(range(hunk.a_startline, hunk.a_endline + 1))
            elif type(hunk) == ModHunk:
                lines.update(range(hunk.a_startline, hunk.a_endline + 1))
        return lines

    @property
    def rel_diff_lines(self) -> set[int]:
        return set([line - self.start_line + 1 for line in self.diff_lines])

    @property
    def diff_identifiers(self):
        assert self.counterpart is not None
        diff_identifiers = {}
        for hunk in self.patch_hunks:
            if type(hunk) == DelHunk:
                lines = set(range(hunk.a_startline, hunk.a_endline + 1))
                criteria_identifier_a = self.identifier_by_lines(lines)
                diff_identifiers.update(criteria_identifier_a)
            elif type(hunk) == ModHunk:
                a_lines = set(range(hunk.a_startline, hunk.a_endline + 1))
                b_lines = set(range(hunk.b_startline, hunk.b_endline + 1))
                criteria_identifier_a = self.identifier_by_lines(a_lines)
                criteria_identifier_b = self.counterpart.identifier_by_lines(b_lines)
                lines = a_lines.union(b_lines)
                for line in lines:
                    if (
                        line in criteria_identifier_a.keys()
                        and line in criteria_identifier_b.keys()
                    ):
                        diff_identifiers[line] = (
                            criteria_identifier_a[line] - criteria_identifier_b[line]
                        )
                    elif line in criteria_identifier_a.keys():
                        diff_identifiers[line] = criteria_identifier_a[line]
        return diff_identifiers

    @property
    def body_lines(self) -> set[int]:
        body_start_line = self.body_start_line
        body_end_line = self.body_end_line
        if self.lines[self.body_start_line].strip().endswith("{"):
            body_start_line += 1
        if self.lines[self.body_end_line].strip().endswith("}"):
            body_end_line -= 1
        return set(range(body_start_line, body_end_line + 1))

    @property
    def body_code(self) -> str:
        return "\n".join([self.lines[line] for line in sorted(self.body_lines)])

    @cached_property
    def patch_hunks(self) -> list[Hunk]:
        assert self.counterpart is not None
        hunks = get_patch_hunks(self.file.code, self.counterpart.file.code)
        for hunk in hunks.copy():
            if type(hunk) == ModHunk or type(hunk) == DelHunk:
                if not (
                    self.start_line <= hunk.a_startline
                    and hunk.a_endline <= self.end_line
                ):
                    hunks.remove(hunk)
            elif type(hunk) == AddHunk:
                if (
                    hunk.insert_line < self.start_line
                    or hunk.insert_line > self.end_line
                ):
                    hunks.remove(hunk)

        def sort_key(hunk: Hunk):
            if type(hunk) == AddHunk:
                return hunk.insert_line
            elif type(hunk) == ModHunk or type(hunk) == DelHunk:
                return hunk.a_startline
            else:
                return 0

        hunks.sort(key=sort_key)
        return hunks

    @property
    def header_lines(self) -> set[int]:
        return set(range(self.start_line, self.body_start_line + 1))

    @property
    def body_lines(self) -> set[int]:
        body_start_line = self.body_start_line
        body_end_line = self.body_end_line
        if self.lines[self.body_start_line].strip().endswith("{"):
            body_start_line += 1
        if self.lines[self.body_end_line].strip().endswith("}"):
            body_end_line -= 1
        return set(range(body_start_line, body_end_line + 1))

    @property
    def body_code(self) -> str:
        return "\n".join([self.lines[line] for line in sorted(self.body_lines)])

    @property
    def comment_lines(self) -> set[int]:
        body_node = self.node.child_by_field_name("body")
        if body_node is None:
            return set()
        comment_lines = set()
        query = f"""
        (line_comment)@line_comment
        (block_comment)@block_comment
        """
        comment_nodes = self.file.parser.query_from_node(body_node, query)
        line_comments = [
            comment for comment in comment_nodes if comment[1] == "line_comment"
        ]
        block_comments = [
            comment for comment in comment_nodes if comment[1] == "block_comment"
        ]
        for comment_node in line_comments:
            line = comment_node.start_point[0] + 1
            if self.lines[line].strip() == comment_node.text.decode().strip():
                comment_lines.add(line)
        for comment_node in block_comments:
            start_line = comment_node.start_point[0] + 1
            end_line = comment_node.end_point[0] + 1
            if self.lines[start_line].strip().startswith("/*"):
                comment_lines.update(range(start_line, end_line + 1))
        return comment_lines

    @property
    def modified_parameters(self):
        diff_lines = self.diff_lines
        modified_parameters = {}
        if self.language == Language.CPP:
            assign_nodes = self.file.parser.get_all_assign_node()
            for node in assign_nodes:
                line = node.start_point[0] + 1
                if line in diff_lines:
                    left_param = node.child_by_field_name("left")
                    if left_param is None or left_param.text.decode() == "":
                        continue
                    try:
                        modified_parameters[line].add(left_param.text.decode())
                    except:
                        modified_parameters[line] = set()
                        modified_parameters[line].add(left_param.text.decode())

        return modified_parameters

    def abstract_code_by_lines(self, lines: set[int]):
        result = "\n".join([self.abs_rel_lines[line] for line in sorted(lines)])
        return result + "\n"

    def code_by_lines(self, lines: set[int], *, placeholder: str | None = None) -> str:
        if placeholder is None:
            result = "\n".join([self.rel_lines[line] for line in sorted(lines)])
            return result + "\n"
        else:
            code_with_placeholder = ""
            last_line = 0
            placeholder_counter = 0
            for line in sorted(lines):
                if line - last_line > 1:
                    is_comment = True
                    for i in range(last_line + 1, line):
                        if self.rel_lines[i].strip() == "":
                            continue
                        if not self.rel_lines[i].strip().startswith("//"):
                            is_comment = False
                            break
                    if is_comment:
                        pass
                    elif line - last_line == 2 and (
                        self.rel_lines[line - 1].strip() == ""
                        or self.rel_lines[line - 1].strip().startswith("//")
                    ):
                        pass
                    else:
                        code_with_placeholder += f"{placeholder}\n"
                        placeholder_counter += 1
                code_with_placeholder += self.rel_lines[line] + "\n"
                last_line = line
            return code_with_placeholder

    def reduced_hunks(self, slines: set[int]) -> list[str]:
        placeholder_lines = self.rel_line_set - slines
        return self.code_hunks(placeholder_lines)

    def code_hunks(self, lines: set[int]) -> list[str]:
        hunks: list[str] = []
        lineg = group_consecutive_ints(list(lines))
        for g in lineg:
            hunk = self.code_by_lines(set(g))
            hunks.append(hunk)
        return hunks

    def recover_placeholder(
        self, code: str, slice_lines: set[int], placeholder: str
    ) -> str | None:
        placeholder_hunks = self.reduced_hunks(slice_lines)
        if code.count(placeholder) != len(placeholder_hunks):
            return None
        result = ""
        for line in code.split("\n"):
            if line.strip().lower() == placeholder.strip().lower():
                result += placeholder_hunks.pop(0)
            else:
                result += line + "\n"
        return result

    def code_by_exclude_lines(self, lines: set[int], *, placeholder: str | None) -> str:
        exclude_lines = self.rel_line_set - lines
        return self.code_by_lines(exclude_lines, placeholder=placeholder)

    def identifier_by_lines(self, lines: set[int]):
        identifier_list = {}
        if self.language == Language.CPP:
            identifier_nodes = self.file.parser.get_all_identifier_node()
            for node in identifier_nodes:
                if node.parent.type == "unary_expression":
                    line = node.parent.start_point[0] + 1
                    if line in lines:
                        assert node.parent.text is not None
                        try:
                            identifier_list[line].add(node.parent.text.decode())
                        except:
                            identifier_list[line] = {node.parent.text.decode()}
                else:
                    line = node.start_point[0] + 1
                    if line in lines:
                        assert node.text is not None
                        try:
                            identifier_list[line].add(node.text.decode())
                        except:
                            identifier_list[line] = {node.text.decode()}
        return identifier_list

    def conditions_by_lines(self, lines: set[int]):
        conditions_list = set()
        if self.language == Language.CPP:
            conditional_nodes = self.file.parser.get_all_conditional_node()
            for node in conditional_nodes:
                line = node.start_point[0] + 1
                if line in lines:
                    conditions_list.add(line)
        return conditions_list

    def ret_by_lines(self, lines: set[int]):
        ret_list = set()
        if self.language == Language.CPP:
            ret_nodes = self.file.parser.get_all_return_node()
            for node in ret_nodes:
                line = node.start_point[0] + 1
                if line in lines:
                    ret_list.add(line)
        return ret_list

    def assignment_by_lines(self, lines: set[int]):
        assign_list = set()
        if self.language == Language.CPP:
            assign_nodes = self.file.parser.get_all_assign_node()
            for node in assign_nodes:
                line = node.start_point[0] + 1
                if line in lines:
                    assign_list.add(line)
        return assign_list

    def call_by_lines(self, lines: set[int]):
        ret_list = set()
        if self.language == Language.CPP:
            call_nodes = self.file.parser.get_all_call_node()
            for node in call_nodes:
                line = node.start_point[0] + 1
                if line in lines:
                    ret_list.add(line)
        return ret_list

    def all_assignment_lines(self):
        assign_list = set()
        if self.language == Language.CPP:
            assign_nodes = self.file.parser.get_all_assign_node()
            for node in assign_nodes:
                line = node.start_point[0] + 1
                assign_list.add(line)
        return assign_list

    @cached_property
    def all_flow_control_lines(self):
        control_list = {}
        if self.language == Language.CPP:
            control_nodes = self.file.parser.get_all_flow_control_goto()
            for node in control_nodes:
                line = node.start_point[0] + 1
                control_list[line] = "goto"
            control_nodes = self.file.parser.get_all_flow_control_break()
            for node in control_nodes:
                line = node.start_point[0] + 1
                control_list[line] = "break"
            control_nodes = self.file.parser.get_all_flow_control()
            for node in control_nodes:
                line = node.start_point[0] + 1
                control_list[line] = "continue"
        return control_list

    @property
    def normalized_body_code(self) -> str:
        return format_code.normalize(self.body_code)

    @property
    def formatted_code(self) -> str:
        return format.format(
            self.code, self.language, del_comment=True, del_linebreak=True
        )

    @property
    def rel_start_line(self) -> int:
        return 1

    @property
    def rel_end_line(self) -> int:
        return self.end_line - self.start_line + 1

    @property
    def rel_body_start_line(self) -> int:
        return self.body_start_line - self.start_line + 1

    @property
    def rel_body_end_line(self) -> int:
        return self.body_end_line - self.start_line + 1

    @property
    def rel_lines(self) -> dict[int, str]:
        return {line - self.start_line + 1: code for line, code in self.lines.items()}

    @property
    def abs_rel_lines(self) -> dict[int, str]:
        self.abs_lines: dict[int, str] = {
            i + self.start_line: line
            for i, line in enumerate(self.abstract_code.split("\n"))
        }
        return {
            line - self.start_line + 1: code for line, code in self.abs_lines.items()
        }

    @property
    def length(self):
        return self.end_line - self.start_line + 1

    @property
    def file_suffix(self):
        if self.language == Language.CPP:
            suffix = ".c"
        elif self.language == Language.JAVA:
            suffix = ".java"
        else:
            suffix = ""
        return suffix

    def write_dot(self, dir: str | None = None):
        if self.file.path == "libcpp/init.c":
            return
        if self.pdg is None:
            return
        assert self.pdg is not None
        dot_name = f"{self.file.project.project_name}.dot"
        if dir is not None:
            dot_path = os.path.join(dir, dot_name)
        else:
            dot_path = os.path.join(self.dot_dir, dot_name)
        nx.nx_agraph.write_dot(self.pdg.g, dot_path)

    def write_code(self, dir: str | None = None):
        assert self.method_dir is not None
        file_name = f"{self.file.project.project_name}{self.file_suffix}"
        if dir is not None:
            code_path = os.path.join(dir, file_name)
        else:
            code_path = os.path.join(self.method_dir, file_name)
        with open(code_path, "w") as f:
            f.write(self.code)

    def diff2html(self, method: Method):
        assert self.method_dir is not None
        file1 = self.method_file
        file2 = method.method_file
        title = f"{self.signature} vs {method.signature}"
        output_path = os.path.join(self.method_dir, "diff.html")
        out = subprocess.run(
            [
                "git",
                "--no-pager",
                "diff",
                "--no-index",
                "-w",
                "-b",
                "--unified=10000",
                "--function-context",
                file1,
                file2,
            ],
            stdout=subprocess.PIPE,
        )
        subprocess.run(
            [
                "diff2html",
                "-f",
                "html",
                "-F",
                output_path,
                "--su",
                "-s",
                "side",
                "--lm",
                "lines",
                "-i",
                "stdin",
                "-t",
                title,
            ],
            input=out.stdout,
            stderr=subprocess.DEVNULL,
        )

    def code_by_lines_ppathf(
        self, lines: set[int], *, placeholder: bool = False
    ) -> str:
        if not placeholder:
            result = "\n".join([self.rel_lines[line] for line in sorted(lines)])
            return result + "\n"
        else:
            code_with_placeholder = ""
            last_line = 0
            placeholder_counter = 0
            for line in sorted(lines):
                if line - last_line > 1:
                    is_comment = True
                    for i in range(last_line + 1, line):
                        if self.rel_lines[i].strip() == "":
                            continue
                        if not self.rel_lines[i].strip().startswith("//"):
                            is_comment = False
                            break
                    if is_comment:
                        pass
                    elif line - last_line == 2 and (
                        self.rel_lines[line - 1].strip() == ""
                        or self.rel_lines[line - 1].strip().startswith("//")
                    ):
                        pass
                    else:
                        code_with_placeholder += (
                            f"/* Placeholder_{placeholder_counter} */\n"
                        )
                        placeholder_counter += 1
                code_with_placeholder += self.rel_lines[line] + "\n"
                last_line = line
            return code_with_placeholder

    @staticmethod
    def backward_slice(
        criteria_lines: set[int],
        criteria_nodes: set[PDGNode],
        criteria_identifier: set[str],
        all_nodes: dict[int, list[PDGNode]],
        level: int,
    ) -> tuple[set[int], list[PDGNode]]:
        result_lines = criteria_lines.copy()
        result_nodes = criteria_nodes.copy()

        for slice_line in criteria_lines:
            for node in all_nodes[slice_line]:
                if node.type == "METHOD_RETURN":
                    continue
                for pred_node in node.pred_cfg_nodes:
                    if (
                        pred_node.line_number is None
                        or int(pred_node.line_number) == sys.maxsize
                    ):
                        continue
                    result_lines.add(int(pred_node.line_number))
                    result_nodes.add(pred_node)

        for sline in criteria_lines:
            for node in all_nodes[sline]:
                if node.type in ["METHOD_RETURN"]:
                    continue
                visited = set()
                queue = deque([(node, 0)])
                while queue:
                    node, depth = queue.popleft()
                    if node not in visited:
                        visited.add(node)
                        result_nodes.add(node)
                        if node.line_number is not None:
                            result_lines.add(node.line_number)
                        if depth < level:
                            for pred_node, edge in node.pred_ddg:
                                if (
                                    pred_node.line_number is None
                                    or int(pred_node.line_number) == sys.maxsize
                                ):
                                    continue
                                if edge not in node.code:
                                    continue
                                if len(criteria_identifier) > 0:
                                    if edge not in criteria_identifier:
                                        continue
                                queue.append((pred_node, depth + 1))

        return result_lines, result_nodes

    @staticmethod
    def forward_slice(
        criteria_lines: set[int],
        criteria_nodes: set[PDGNode],
        criteria_identifier: dict[int, set[str]],
        all_nodes: dict[int, list[PDGNode]],
        level: int,
        need_header_line=False,
    ):
        result_nodes = set()
        result_lines = set()
        result_edges = set()
        result_weight = {}
        flag = need_header_line

        for sline in criteria_lines:
            for node in all_nodes[sline]:
                if node.type == "METHOD":
                    continue
                if (
                    "METHOD_RETURN" in ast.literal_eval(node.type)
                ) and not need_header_line:
                    continue

                visited = set()
                queue = deque([(node, node, 0)])
                while queue:
                    pre_node, node, depth = queue.popleft()
                    if node not in visited:
                        visited.add(node)
                        result_nodes.add(node)
                        if node.line_number is not None:
                            result_lines.add(node.line_number)
                            try:
                                result_weight[node.line_number] += 1 / (depth + 1)
                                result_weight[node.line_number] = (
                                    result_weight[node.line_number]
                                    if result_weight[node.line_number] <= 1
                                    else 1
                                )
                            except:
                                result_weight[node.line_number] = 1 / (depth + 1)
                                result_weight[node.line_number] = (
                                    result_weight[node.line_number]
                                    if result_weight[node.line_number] <= 1
                                    else 1
                                )
                            if pre_node != node and pre_node.line_number is not None:
                                result_edges.add(
                                    (pre_node.line_number, node.line_number)
                                )
                        if (
                            node.type != "METHOD"
                            and "RETURN" not in ast.literal_eval(node.type)
                        ) or need_header_line:
                            for succ_node, edge in node.succ_ddg:
                                if edge not in node.code:
                                    continue

                                if (
                                    sline not in criteria_identifier.keys()
                                    and criteria_identifier != {}
                                ):
                                    continue
                                if (
                                    criteria_identifier != {}
                                    and len(criteria_identifier[sline]) > 0
                                ):
                                    if edge not in criteria_identifier[sline]:
                                        continue
                                queue.append((node, succ_node, depth + 1))

                            need_header_line = False
        need_header_line = flag
        for sline in criteria_lines:
            for node in all_nodes[sline]:
                if node.type == "METHOD":
                    continue
                if (
                    "METHOD_RETURN" in ast.literal_eval(node.type)
                ) and not need_header_line:
                    continue

                need_header_line = False
                visited = set()
                queue = deque([(node, node, 0)])
                while queue:
                    pre_node, node, depth = queue.popleft()
                    if node not in visited:
                        visited.add(node)
                        result_nodes.add(node)
                        if node.line_number is not None:
                            result_lines.add(node.line_number)
                            try:
                                result_weight[node.line_number] += 1 / (depth + 1)
                                result_weight[node.line_number] = (
                                    result_weight[node.line_number]
                                    if result_weight[node.line_number] <= 1
                                    else 1
                                )
                            except:
                                result_weight[node.line_number] = 1 / (depth + 1)
                                result_weight[node.line_number] = (
                                    result_weight[node.line_number]
                                    if result_weight[node.line_number] <= 1
                                    else 1
                                )
                            if pre_node != node and pre_node.line_number is not None:
                                result_edges.add(
                                    (pre_node.line_number, node.line_number)
                                )
                        if "RETURN" not in ast.literal_eval(node.type):
                            for succ_node in node.succ_cdg:
                                queue.append((node, succ_node, depth + 1))

        return result_lines, result_nodes, result_weight, result_edges

    def slice(
        self,
        criteria_lines: set[int],
        criteria_identifier: set,
        backward_slice_level: int = 4,
        forward_slice_level: int = 4,
        is_rel: bool = False,
    ):
        assert self.pdg is not None
        if is_rel:
            criteria_lines = set(
                [line + self.start_line - 1 for line in criteria_lines]
            )

        all_lines = set(self.lines.keys())
        all_nodes: dict[int, list[PDGNode]] = {
            line: self.pdg.get_nodes_by_line_number(line) for line in all_lines
        }
        criteria_nodes: set[PDGNode] = set()
        for line in criteria_lines:
            for node in self.pdg.get_nodes_by_line_number(line):
                node.is_patch_node = True
                node.add_attr("color", "red")
                criteria_nodes.add(node)

        slice_result_lines = set(criteria_lines)
        slice_result_lines |= self.header_lines
        slice_result_lines.add(self.end_line)

        result_lines, backward_nodes = self.backward_slice(
            criteria_lines,
            criteria_nodes,
            criteria_identifier,
            all_nodes,
            backward_slice_level,
        )
        slice_result_lines.update(result_lines)
        result_lines, forward_nodes = self.forward_slice(
            criteria_lines,
            criteria_nodes,
            criteria_identifier,
            all_nodes,
            forward_slice_level,
        )
        slice_result_lines.update(result_lines)
        slice_nodes = criteria_nodes.union(backward_nodes).union(forward_nodes)
        slice_result_rel_lines = set(
            [
                line - self.start_line + 1
                for line in slice_result_lines
                if line >= self.start_line
            ]
        )

        sliced_code = self.code_by_lines(slice_result_rel_lines)
        return slice_result_lines, slice_result_rel_lines, slice_nodes, sliced_code

    def slice_by_diff_lines(
        self,
        backward_slice_level: int = 4,
        forward_slice_level: int = 4,
        need_criteria_identifier: bool = False,
        write_dot: bool = False,
    ):
        criteria_identifier = self.diff_identifiers if need_criteria_identifier else {}
        slice_results = self.slice(
            self.diff_lines,
            criteria_identifier,
            backward_slice_level,
            forward_slice_level=forward_slice_level,
            is_rel=False,
        )
        if write_dot and slice_results is not None:
            assert self.pdg is not None and self.method_dir is not None
            slice_nodes = slice_results[2]
            g = nx.subgraph(self.pdg.g, [node.node_id for node in slice_nodes])
            os.makedirs(self.method_dir, exist_ok=True)
            role = self.file.project.project_name
            nx.nx_agraph.write_dot(
                g,
                os.path.join(
                    self.dot_dir,
                    f"{role}#{backward_slice_level}#{forward_slice_level}.dot",
                ),
            )
        return slice_results

    def backward_slice_vul_detect(
        self,
        criteria_lines: set[int],
        criteria_nodes: set[PDGNode],
        criteria_identifier,
        all_nodes: dict[int, list[PDGNode]],
        need_header_line=False,
    ):
        result_lines = criteria_lines.copy()
        result_nodes = criteria_nodes.copy()
        result_edges = set()
        result_weight = {}
        if need_header_line:
            flag = True
        else:
            flag = False

        for sline in criteria_lines:
            for node in all_nodes[sline]:
                if node.type == "METHOD":
                    continue
                if (
                    "METHOD_RETURN" in ast.literal_eval(node.type)
                ) and not need_header_line:
                    continue
                visited = set()
                queue = deque([(node, node, 0)])
                while queue:
                    node, succ_node, depth = queue.popleft()
                    if node not in visited:
                        visited.add(node)
                        result_nodes.add(node)
                        if node.line_number is not None:
                            result_lines.add(node.line_number)
                            try:
                                result_weight[node.line_number] += 1 / (depth + 1)
                                result_weight[node.line_number] = (
                                    result_weight[node.line_number]
                                    if result_weight[node.line_number] <= 1
                                    else 1
                                )
                            except:
                                result_weight[node.line_number] = 1 / (depth + 1)
                                result_weight[node.line_number] = (
                                    result_weight[node.line_number]
                                    if result_weight[node.line_number] <= 1
                                    else 1
                                )
                            if node != succ_node and succ_node.line_number is not None:
                                result_edges.add(
                                    (node.line_number, succ_node.line_number)
                                )
                        if node.type == "METHOD":
                            continue
                        if (
                            "METHOD_PARAMETER_IN" in ast.literal_eval(node.type)
                        ) and not need_header_line:
                            continue
                        else:
                            need_header_line = False
                        for pred_node, edge in node.pred_ddg:
                            if (
                                pred_node.line_number is None
                                or int(pred_node.line_number) == sys.maxsize
                            ):
                                continue
                            if edge not in node.code:
                                continue
                            if (
                                sline not in criteria_identifier.keys()
                                and criteria_identifier != {}
                            ):
                                continue
                            if (
                                criteria_identifier != {}
                                and len(criteria_identifier[sline]) > 0
                            ):
                                if edge not in criteria_identifier[sline]:
                                    continue
                            queue.append((pred_node, node, depth + 1))

        if flag:
            need_header_line = True

        for sline in criteria_lines:
            for node in all_nodes[sline]:
                if node.type == "METHOD":
                    continue
                if (
                    "METHOD_RETURN" in ast.literal_eval(node.type)
                ) and not need_header_line:
                    continue
                visited = set()
                queue = deque([(node, node, 0)])
                while queue:
                    node, succ_node, depth = queue.popleft()
                    if node not in visited:
                        visited.add(node)
                        result_nodes.add(node)
                        if node.line_number is not None:
                            result_lines.add(node.line_number)
                            try:
                                result_weight[node.line_number] += 1 / (depth + 1)
                                result_weight[node.line_number] = (
                                    result_weight[node.line_number]
                                    if result_weight[node.line_number] <= 1
                                    else 1
                                )
                            except:
                                result_weight[node.line_number] = 1 / (depth + 1)
                                result_weight[node.line_number] = (
                                    result_weight[node.line_number]
                                    if result_weight[node.line_number] <= 1
                                    else 1
                                )
                            if node != succ_node and succ_node.line_number is not None:
                                result_edges.add(
                                    (node.line_number, succ_node.line_number)
                                )
                        if node.type == "METHOD":
                            continue
                        if (
                            "METHOD_PARAMETER_IN" in ast.literal_eval(node.type)
                        ) and not need_header_line:
                            continue
                        else:
                            need_header_line = False
                        for pred_node in node.pred_cdg:
                            if (
                                pred_node.line_number is None
                                or int(pred_node.line_number) == sys.maxsize
                            ):
                                continue
                            queue.append((pred_node, node, depth + 1))

        return result_lines, result_nodes, result_weight, result_edges

    def normal_forward_slice_on_DDG(
        self, sline: int, node: PDGNode, criteria_identifier: set[str]
    ) -> tuple[set[int], set[int], dict[int, float], set[tuple[int, int]]]:
        result_nodes = set()
        result_lines = set()
        result_edges = set()
        result_weight = {}
        if node.type == "METHOD" or "PARAM" in ast.literal_eval(node.type):
            return result_nodes, result_lines, result_weight, result_edges
        visited = set()
        queue = deque([(node, node, 0)])
        while queue:
            pre_node, node, depth = queue.popleft()
            if node not in visited:
                visited.add(node)
                result_nodes.add(node)
                if node.line_number is not None:
                    result_lines.add(node.line_number)
                    try:
                        result_weight[node.line_number] += 1 / (depth + 1)
                        result_weight[node.line_number] = (
                            result_weight[node.line_number]
                            if result_weight[node.line_number] <= 1
                            else 1
                        )
                    except:
                        result_weight[node.line_number] = 1 / (depth + 1)
                        result_weight[node.line_number] = (
                            result_weight[node.line_number]
                            if result_weight[node.line_number] <= 1
                            else 1
                        )
                    if pre_node != node and pre_node.line_number is not None:
                        result_edges.add((pre_node.line_number, node.line_number))
                if node.type != "METHOD" and "RETURN" not in ast.literal_eval(
                    node.type
                ):
                    for succ_node, edge in node.succ_ddg:
                        if edge not in node.code:
                            continue

                        if (
                            sline not in criteria_identifier.keys()
                            and criteria_identifier != {}
                        ):
                            continue
                        if (
                            criteria_identifier != {}
                            and len(criteria_identifier[sline]) > 0
                        ):
                            if edge not in criteria_identifier[sline]:
                                continue
                        queue.append((node, succ_node, depth + 1))
        return result_nodes, result_lines, result_weight, result_edges

    def normal_forward_slice_on_CDG(
        self, node: PDGNode
    ) -> tuple[set[int], set[int], dict[int, float], set[tuple[int, int]]]:
        result_nodes = set()
        result_lines = set()
        result_edges = set()
        result_weight = {}
        if node.type == "METHOD" or "PARAM" in ast.literal_eval(node.type):
            return result_nodes, result_lines, result_weight, result_edges
        visited = set()
        queue = deque([(node, node, 0)])
        while queue:
            pre_node, node, depth = queue.popleft()
            if node not in visited:
                visited.add(node)
                result_nodes.add(node)
                if node.line_number is not None:
                    result_lines.add(node.line_number)
                    try:
                        result_weight[node.line_number] += 1 / (depth + 1)
                        result_weight[node.line_number] = (
                            result_weight[node.line_number]
                            if result_weight[node.line_number] <= 1
                            else 1
                        )
                    except:
                        result_weight[node.line_number] = 1 / (depth + 1)
                        result_weight[node.line_number] = (
                            result_weight[node.line_number]
                            if result_weight[node.line_number] <= 1
                            else 1
                        )
                    if pre_node != node and pre_node.line_number is not None:
                        result_edges.add((pre_node.line_number, node.line_number))
                if "RETURN" not in ast.literal_eval(node.type):
                    for succ_node in node.succ_cdg:
                        queue.append((node, succ_node, depth + 1))

        return result_nodes, result_lines, result_weight, result_edges

    def customized_forward_slice_per_node(
        self, sline: int, node, criteria_identifier, all_nodes, all_assignments
    ) -> tuple[set[int], set[int], dict[int, float], set[tuple[int, int]]]:
        result_nodes = set()
        result_lines = set()
        result_edges = set()
        result_weights = {}
        temp_criteria_lines = set()
        temp_criteria_nodes = set()
        visited = set()
        queue = deque([(node, 0)])
        while queue:
            temp_node, depth = queue.popleft()
            if temp_node not in visited:
                visited.add(temp_node)
                if (
                    temp_node.type != "METHOD"
                    and "METHOD_PARAMETER_IN" not in ast.literal_eval(temp_node.type)
                    and temp_node.line_number not in all_assignments
                ):
                    for pred_node, edge in temp_node.pred_ddg:
                        if (
                            pred_node.line_number is None
                            or int(pred_node.line_number) == sys.maxsize
                        ):
                            continue
                        if edge not in temp_node.code:
                            continue
                        if (
                            sline not in criteria_identifier.keys()
                            and criteria_identifier != {}
                        ):
                            continue
                        if (
                            criteria_identifier != {}
                            and len(criteria_identifier[sline]) > 0
                        ):
                            if edge not in criteria_identifier[sline]:
                                continue
                        queue.append((pred_node, depth + 1))
                else:
                    if (
                        temp_node.type == "METHOD"
                        or "METHOD_PARAMETER_IN" in ast.literal_eval(temp_node.type)
                    ):
                        continue
                    temp_criteria_lines.add(temp_node.line_number)
                    temp_criteria_nodes.add(temp_node)
                    break

        if len(temp_criteria_nodes) == 0:
            (
                temp_result_nodes,
                temp_result_lines,
                temp_result_weights,
                temp_result_edges,
            ) = self.normal_forward_slice_on_CDG(node)
            result_lines = result_lines.union(temp_result_lines)
            result_nodes = result_nodes.union(temp_result_nodes)
            result_edges = result_edges.union(temp_result_edges)
            result_weights.update(temp_result_weights)
        else:
            result_lines = result_lines.union(temp_criteria_lines)
            result_nodes = result_nodes.union(temp_criteria_nodes)
            for temp_sline in temp_criteria_lines:
                for temp_node in all_nodes[temp_sline]:
                    (
                        temp_result_nodes,
                        temp_result_lines,
                        temp_result_weights,
                        temp_result_edges,
                    ) = self.normal_forward_slice_on_DDG(
                        sline, temp_node, criteria_identifier
                    )
                    result_lines = result_lines.union(temp_result_lines)
                    result_nodes = result_nodes.union(temp_result_nodes)
                    result_edges = result_edges.union(temp_result_edges)
                    result_weights.update(temp_result_weights)

        return result_nodes, result_lines, result_weights, result_edges

    def customized_forward_slice_vul_detect(
        self,
        criteria_lines: set[int],
        criteria_nodes: set[PDGNode],
        criteria_identifier: set[str],
        all_nodes: dict[int, list[PDGNode]],
        need_header_line=False,
        is_rel=False,
    ):
        assignments = self.assignment_by_lines(criteria_lines)
        ret = self.ret_by_lines(criteria_lines)
        conditions = self.conditions_by_lines(criteria_lines)
        calls = self.call_by_lines(criteria_lines)
        result_lines = criteria_lines.copy()
        result_nodes = criteria_nodes.copy()
        result_edges = set()
        all_assignments = self.all_assignment_lines()
        result_weights = {}

        for sline in criteria_lines:
            if sline in ret:
                continue
            for node in all_nodes[sline]:
                if node.type == "METHOD":
                    continue
                if ("PARAM" in ast.literal_eval(node.type)) and not need_header_line:
                    continue
                if sline in assignments:
                    (
                        temp_result_nodes,
                        temp_result_lines,
                        temp_result_weights,
                        temp_result_edges,
                    ) = self.normal_forward_slice_on_DDG(
                        sline, node, criteria_identifier
                    )
                    result_lines = result_lines.union(temp_result_lines)
                    result_nodes = result_nodes.union(temp_result_nodes)
                    result_edges = result_edges.union(temp_result_edges)
                    for line in temp_result_weights:
                        try:
                            result_weights[line] += temp_result_weights[line]
                            result_weights[line] = (
                                result_weights[line] if result_weights[line] <= 1 else 1
                            )
                        except:
                            result_weights[line] = temp_result_weights[line]
                            result_weights[line] = (
                                result_weights[line] if result_weights[line] <= 1 else 1
                            )
                elif sline in conditions:
                    (
                        temp_result_nodes,
                        temp_result_lines,
                        temp_result_weights,
                        temp_result_edges,
                    ) = self.customized_forward_slice_per_node(
                        sline, node, criteria_identifier, all_nodes, all_assignments
                    )
                    result_lines = result_lines.union(temp_result_lines)
                    result_nodes = result_nodes.union(temp_result_nodes)
                    result_edges = result_edges.union(temp_result_edges)
                    for line in temp_result_weights:
                        try:
                            result_weights[line] += temp_result_weights[line]
                            result_weights[line] = (
                                result_weights[line] if result_weights[line] <= 1 else 1
                            )
                        except:
                            result_weights[line] = temp_result_weights[line]
                            result_weights[line] = (
                                result_weights[line] if result_weights[line] <= 1 else 1
                            )

                elif sline in calls:
                    (
                        temp_result_nodes,
                        temp_result_lines,
                        temp_result_weights,
                        temp_result_edges,
                    ) = self.customized_forward_slice_per_node(
                        sline, node, criteria_identifier, all_nodes, all_assignments
                    )
                    result_lines = result_lines.union(temp_result_lines)
                    result_nodes = result_nodes.union(temp_result_nodes)
                    result_edges = result_edges.union(temp_result_edges)
                    for line in temp_result_weights:
                        try:
                            result_weights[line] += temp_result_weights[line]
                            result_weights[line] = (
                                result_weights[line] if result_weights[line] <= 1 else 1
                            )
                        except:
                            result_weights[line] = temp_result_weights[line]
                            result_weights[line] = (
                                result_weights[line] if result_weights[line] <= 1 else 1
                            )

        return result_lines, result_nodes, result_edges, result_weights

    def cfg_slicing_for_control(
        self,
        criteria_lines: set[int],
        criteria_nodes: set[PDGNode],
        all_nodes,
        need_header_line=False,
        level=3,
    ):
        result_lines = criteria_lines.copy()
        result_nodes = criteria_nodes.copy()
        result_edges = set()
        result_weights = {}
        method_code = self.code
        ast_parser = ASTParser(method_code, Language.CPP)
        goto_query = """
        (goto_statement
        (statement_identifier)@label
        )
        """
        flag = need_header_line
        goto_results = ast_parser.query_all(goto_query)
        for line in criteria_lines:
            if line in self.all_flow_control_lines:
                for node in all_nodes[line]:
                    if node.type == "METHOD":
                        continue
                    if (
                        "METHOD_RETURN" in ast.literal_eval(node.type)
                    ) and not need_header_line:
                        continue
                    else:
                        need_header_line = False
                if self.all_flow_control_lines[line] == "goto":
                    for res in goto_results:
                        if res.start_point[0] + 1 == line - self.start_line + 1:
                            identifier = res.text.decode()
                            lable_query = f"""
                            (labeled_statement
                                label: (statement_identifier)@label
                                (#eq? @label "{identifier}")
                            )
                            """
                            result_node = ast_parser.query_oneshot(lable_query)
                            if result_node is not None:
                                result_lines.add(
                                    result_node.start_point[0] + self.start_line
                                )
                                result_edges.add(
                                    (line, result_node.start_point[0] + self.start_line)
                                )
                                try:
                                    result_weights[
                                        result_node.start_point[0] + self.start_line
                                    ] += 1 / 2
                                    result_weights[
                                        result_node.start_point[0] + self.start_line
                                    ] = (
                                        result_weights[
                                            result_node.start_point[0] + self.start_line
                                        ]
                                        if result_weights[
                                            result_node.start_point[0] + self.start_line
                                        ]
                                        <= 1
                                        else 1
                                    )
                                except:
                                    result_weights[
                                        result_node.start_point[0] + self.start_line
                                    ] = 1 / 2
                                    result_weights[
                                        result_node.start_point[0] + self.start_line
                                    ] = (
                                        result_weights[
                                            result_node.start_point[0] + self.start_line
                                        ]
                                        if result_weights[
                                            result_node.start_point[0] + self.start_line
                                        ]
                                        <= 1
                                        else 1
                                    )
                                lable_line = (
                                    result_node.start_point[0] + self.start_line
                                )
                                while (
                                    lable_line in all_nodes
                                    and len(all_nodes[lable_line]) == 0
                                ):
                                    lable_line += 1
                                if lable_line not in all_nodes:
                                    lable_line -= 1
                                for node in all_nodes[lable_line]:
                                    if (
                                        node.type == "METHOD"
                                        or "METHOD_RETURN"
                                        in ast.literal_eval(node.type)
                                    ):
                                        continue
                                    visited = set()
                                    queue = deque([(node, node, 1)])
                                    while queue:
                                        pred_node, node, depth = queue.popleft()
                                        if depth > level:
                                            continue
                                        if node not in visited:
                                            visited.add(node)
                                            result_nodes.add(node)
                                            if node.line_number is not None:
                                                result_lines.add(node.line_number)
                                                try:
                                                    result_weights[
                                                        node.line_number
                                                    ] += 1 / (depth + 1)
                                                    result_weights[node.line_number] = (
                                                        result_weights[node.line_number]
                                                        if result_weights[
                                                            node.line_number
                                                        ]
                                                        <= 1
                                                        else 1
                                                    )
                                                except:
                                                    result_weights[node.line_number] = (
                                                        1 / (depth + 1)
                                                    )
                                                    result_weights[node.line_number] = (
                                                        result_weights[node.line_number]
                                                        if result_weights[
                                                            node.line_number
                                                        ]
                                                        <= 1
                                                        else 1
                                                    )
                                                if (
                                                    node != pred_node
                                                    and pred_node.line_number
                                                    is not None
                                                ):
                                                    result_edges.add(
                                                        (
                                                            pred_node.line_number,
                                                            node.line_number,
                                                        )
                                                    )
                                            if (
                                                node.type != "METHOD"
                                                and "METHOD_PARAMETER_IN"
                                                not in ast.literal_eval(node.type)
                                            ):
                                                for succ_node in node.succ_cfg_nodes:
                                                    if (
                                                        succ_node.line_number is None
                                                        or int(succ_node.line_number)
                                                        == sys.maxsize
                                                    ):
                                                        continue
                                                    queue.append(
                                                        (node, succ_node, depth + 1)
                                                    )
                else:
                    for_query = """
                    ( for_statement)@name(   switch_statement)@name(while_statement)@name
                    """
                    results = ast_parser.query_all(for_query)
                    for identifier_node in results:
                        if (
                            line - self.start_line + 1
                            < identifier_node.start_point[0] + 1
                            or line - self.start_line + 1
                            > identifier_node.end_point[0] + 1
                        ):
                            continue
                        if self.all_flow_control_lines[line] == "break":
                            break_query = "( break_statement)@name"
                            body = identifier_node.child_by_field_name("body")
                            break_results = ast_parser.query_all(break_query, node=body)
                            for res in break_results:
                                if line - self.start_line + 1 != res.start_point[0] + 1:
                                    continue
                                end_line = (
                                    identifier_node.end_point[0] + self.start_line
                                )
                                while end_line not in all_nodes:
                                    end_line += 1
                                result_lines.add(end_line)
                                result_edges.add((line, end_line))
                                try:
                                    result_weights[end_line] += 1 / 2
                                    result_weights[end_line] = (
                                        result_weights[end_line]
                                        if result_weights[end_line] <= 1
                                        else 1
                                    )
                                except:
                                    result_weights[end_line] = 1 / 2
                                    result_weights[end_line] = (
                                        result_weights[end_line]
                                        if result_weights[end_line] <= 1
                                        else 1
                                    )
                        else:
                            continue_query = "(continue_statement)@name"
                            body = identifier_node.child_by_field_name("body")
                            continue_results = ast_parser.query_all(
                                continue_query, node=body
                            )
                            for res in continue_results:
                                if line - self.start_line + 1 != res.start_point[0] + 1:
                                    continue
                                end_line = (
                                    identifier_node.start_point[0] + self.start_line
                                )
                                while end_line not in all_nodes:
                                    end_line += 1
                                result_lines.add(end_line)
                                result_edges.add((line, end_line))
                                try:
                                    result_weights[end_line] += 1 / 2
                                    result_weights[end_line] = (
                                        result_weights[end_line]
                                        if result_weights[end_line] <= 1
                                        else 1
                                    )
                                except:
                                    result_weights[end_line] = 1 / 2
                                    result_weights[end_line] = (
                                        result_weights[end_line]
                                        if result_weights[end_line] <= 1
                                        else 1
                                    )
                need_header_line = flag
                for node in all_nodes[line]:
                    if node.type == "METHOD":
                        continue
                    if (
                        "METHOD_RETURN" in ast.literal_eval(node.type)
                        and not need_header_line
                    ):
                        continue
                    need_header_line = False
                    visited = set()
                    queue = deque([(node, node, 1)])
                    while queue:
                        node, succ_node, depth = queue.popleft()
                        if depth > level:
                            continue
                        if node not in visited:
                            visited.add(node)
                            result_nodes.add(node)
                            if node.line_number is not None:
                                result_lines.add(node.line_number)
                                try:
                                    result_weights[node.line_number] += 1 / (depth + 1)
                                    result_weights[node.line_number] = (
                                        result_weights[node.line_number]
                                        if result_weights[node.line_number] <= 1
                                        else 1
                                    )
                                except:
                                    result_weights[node.line_number] = 1 / (depth + 1)
                                    result_weights[node.line_number] = (
                                        result_weights[node.line_number]
                                        if result_weights[node.line_number] <= 1
                                        else 1
                                    )
                                if (
                                    node != succ_node
                                    and succ_node.line_number is not None
                                ):
                                    result_edges.add(
                                        (node.line_number, succ_node.line_number)
                                    )
                            if (
                                node.type != "METHOD"
                                and "METHOD_PARAMETER_IN"
                                not in ast.literal_eval(node.type)
                            ):
                                for pred_node in node.pred_cfg_nodes:
                                    if (
                                        pred_node.line_number is None
                                        or int(pred_node.line_number) == sys.maxsize
                                    ):
                                        continue
                                    queue.append((pred_node, node, depth + 1))

        return result_lines, result_nodes, result_edges, result_weights

    def slice_vul_detect(
        self,
        criteria_lines: set[int],
        criteria_identifier,
        need_header_line=False,
        is_rel=False,
    ):
        if self.pdg is None:
            return set(), set(), set(), "", "", {}, set()
        assert self.pdg is not None
        if is_rel:
            criteria_lines = set(
                [line + self.start_line - 1 for line in criteria_lines]
            )
        all_lines = set(self.lines.keys())
        all_nodes: dict[int, list[PDGNode]] = {
            line: self.pdg.get_nodes_by_line_number(line) for line in all_lines
        }
        if self.end_line not in all_nodes:
            all_nodes[self.end_line] = []
        criteria_nodes: set[PDGNode] = set()
        for line in criteria_lines:
            for node in self.pdg.get_nodes_by_line_number(line):
                node.is_patch_node = True
                node.add_attr("color", "red")
                criteria_nodes.add(node)
        slice_result_edges = set()

        temp_lines = criteria_lines.copy()
        if need_header_line:
            for slice_line in temp_lines:
                for node in all_nodes[slice_line]:
                    if node.type != "METHOD":
                        continue
                    for pred_node in node.succ_cfg_nodes:
                        if (
                            pred_node.line_number is None
                            or int(pred_node.line_number) == sys.maxsize
                        ):
                            continue
                        criteria_lines.add(int(pred_node.line_number))
                        criteria_nodes.add(pred_node)
                        slice_result_edges.add((slice_line, int(pred_node.line_number)))

        slice_result_lines = set(criteria_lines)

        temp_result_lines, cfg_nodes, cfg_edges, cfg_weights = (
            self.cfg_slicing_for_control(
                criteria_lines, criteria_nodes, all_nodes, need_header_line
            )
        )
        slice_result_lines.update(temp_result_lines)

        result_lines, backward_nodes, backward_weight, backward_edges = (
            self.backward_slice_vul_detect(
                criteria_lines,
                criteria_nodes,
                criteria_identifier,
                all_nodes,
                need_header_line,
            )
        )

        slice_result_lines.update(result_lines)
        if need_header_line:
            result_lines, forward_nodes, forward_weights, forward_edges = (
                self.forward_slice(
                    criteria_lines,
                    criteria_nodes,
                    criteria_identifier,
                    all_nodes,
                    level=4,
                    need_header_line=need_header_line,
                )
            )
        else:
            result_lines, forward_nodes, forward_edges, forward_weights = (
                self.customized_forward_slice_vul_detect(
                    criteria_lines, criteria_nodes, criteria_identifier, all_nodes
                )
            )
        slice_result_lines.update(result_lines)
        slice_nodes = (
            criteria_nodes.union(backward_nodes)
            .union(forward_nodes)
            .union(set(cfg_nodes))
        )
        slice_result_edges = cfg_edges.union(backward_edges).union(forward_edges)
        slice_result_weight = cfg_weights
        for line in criteria_lines:
            slice_result_weight[line] = 1
        for line in backward_weight:
            try:
                slice_result_weight[line] += backward_weight[line]
                slice_result_weight[line] = (
                    slice_result_weight[line] if slice_result_weight[line] <= 1 else 1
                )
            except:
                slice_result_weight[line] = backward_weight[line]
                slice_result_weight[line] = (
                    slice_result_weight[line] if slice_result_weight[line] <= 1 else 1
                )

        for line in forward_weights:
            try:
                slice_result_weight[line] += forward_weights[line]
                slice_result_weight[line] = (
                    slice_result_weight[line] if slice_result_weight[line] <= 1 else 1
                )
            except:
                slice_result_weight[line] = forward_weights[line]
                slice_result_weight[line] = (
                    slice_result_weight[line] if slice_result_weight[line] <= 1 else 1
                )

        slice_result_rel_lines = set(
            [
                line - self.start_line + 1
                for line in slice_result_lines
                if line >= self.start_line and line <= self.end_line
            ]
        )

        slice_result_lines = set(
            [line + self.start_line - 1 for line in slice_result_rel_lines]
        )

        for inedge, outedge in slice_result_edges.copy():
            if inedge not in slice_result_lines or outedge not in slice_result_lines:
                slice_result_edges.remove((inedge, outedge))

        for sline in slice_result_lines:
            for node in self.pdg.get_nodes_by_line_number(sline):
                slice_nodes.add(node)

        sliced_code = self.code_by_lines(slice_result_rel_lines)
        abs_sliced_code = self.abstract_code_by_lines(slice_result_rel_lines)

        return (
            slice_result_lines,
            slice_result_rel_lines,
            slice_nodes,
            sliced_code,
            abs_sliced_code,
            slice_result_weight,
            slice_result_edges,
        )

    def slice_by_every_lines(self, write_dot: bool = False):
        slice_all_results = []
        slice_all_lines = []
        cnt = 0
        for line in self.body_lines:
            if (
                self.lines[line]
                .strip()
                .replace(" ", "")
                .replace("{", "")
                .replace("}", "")
                .replace("\t", "")
                .replace("\n", "")
                .replace("(", "")
                .replace(")", "")
                == ""
            ):
                continue
            slice_results = self.slice_vul_detect(
                {line}, self.identifier_by_lines({line}), is_rel=False
            )
            if (
                slice_results in slice_all_results
                or slice_results is None
                or slice_results[1] in slice_all_lines
                or (
                    len(slice_results[2]) <= 3
                    and len(slice_results[1]) < self.end_line - self.start_line
                )
            ):
                for node in slice_results[2]:
                    node.add_attr("color", "black")
                continue
            else:
                slice_all_lines.append(slice_results[1])
                slice_all_results.append(slice_results)
                cnt += 1
            if write_dot and slice_results is not None:
                if self.pdg is None:
                    return slice_results
                assert self.pdg is not None and self.method_dir is not None
                slice_nodes = slice_results[2]
                for line in slice_results:
                    for node in self.pdg.get_nodes_by_line_number(line):
                        if node not in slice_nodes:
                            slice_nodes.add(node)
                g = nx.subgraph(self.pdg.g, [node.node_id for node in slice_nodes])
                os.makedirs(self.method_dir, exist_ok=True)
                os.makedirs(f"{self.method_dir}/{cnt}", exist_ok=True)
                os.makedirs(f"{self.method_dir}/{cnt}/dot", exist_ok=True)
                role = self.file.project.project_name
                nx.nx_agraph.write_dot(
                    g,
                    os.path.join(
                        self.method_dir, f"{cnt}", "dot", f"{role}_slicing_{cnt}.dot"
                    ),
                )
                fp = open(
                    os.path.join(
                        self.method_dir, f"{cnt}", f"target_slicing{self.file_suffix}"
                    ),
                    "w",
                )
                fp.write(slice_results[-2])
                fp.close()
                fp = open(
                    os.path.join(
                        self.method_dir,
                        f"{cnt}",
                        f"target_slicing_sn{self.file_suffix}",
                    ),
                    "w",
                )
                fp.write(slice_results[-1])
                fp.close()
                for node in slice_nodes:
                    node.add_attr("color", "black")
        return slice_all_results

    def slice_by_diff_lines_vul_detect(
        self,
        need_criteria_identifier: bool = False,
        write_dot: bool = False,
        self_counterpart_line_map: dict[int, int] = {},
        level=0,
    ):
        diff_identifiers = self.diff_identifiers if need_criteria_identifier else {}
        modified_parameters = (
            self.modified_parameters if need_criteria_identifier else {}
        )
        criteria_identifier = diff_identifiers
        if need_criteria_identifier:
            for line in modified_parameters.keys():
                try:
                    criteria_identifier[line] = criteria_identifier[line].union(
                        modified_parameters[line]
                    )
                except:
                    criteria_identifier[line] = modified_parameters[line]

        for line in criteria_identifier:
            for identifier in list(criteria_identifier[line]):
                if "->" in identifier:
                    if len(identifier.split("->")) > 2:
                        criteria_identifier[line].add(
                            "->".join(identifier.split("->")[:-1])
                        )
                    else:
                        criteria_identifier[line].add(identifier.split("->")[0])
                elif "." in identifier:
                    if len(identifier.split(".")) > 2:
                        criteria_identifier[line].add(
                            ".".join(identifier.split(".")[:-1])
                        )
                    else:
                        criteria_identifier[line].add(identifier.split(".")[0])
        if self.slice_line is not None:
            return self.slice_line + (self.lines, self.abs_lines, criteria_identifier)
        elif level > 1:
            return None
        criteria_lines = set()
        if len(self.diff_lines) == 0:
            lines = self.counterpart.slice_by_diff_lines_vul_detect(
                need_criteria_identifier=True, write_dot=True, level=level + 1
            )
            if lines is None:
                return None
            sliced_lines = lines[0]
            assert self_counterpart_line_map != {}
            counterpart_self_line_map = {
                v: k for k, v in self_counterpart_line_map.items()
            }
            for line in sliced_lines:
                if self.start_line + line - 1 in counterpart_self_line_map:
                    if (
                        counterpart_self_line_map[self.start_line + line - 1]
                        + self.start_line
                        - 1
                        > self.end_line
                    ):
                        continue
                    criteria_lines.add(
                        counterpart_self_line_map[self.start_line + line - 1]
                        + self.start_line
                        - 1
                    )
        else:
            criteria_lines = self.diff_lines
        if self.start_line in criteria_lines:
            need_header_line = True
        else:
            need_header_line = False

        slice_results = self.slice_vul_detect(
            criteria_lines,
            criteria_identifier,
            is_rel=False,
            need_header_line=need_header_line,
        )
        if write_dot and slice_results is not None:
            if self.file.path == "libcpp/init.c":
                self.slice_line = slice_results
                return slice_results + (self.lines, self.abs_lines, criteria_identifier)
            if self.pdg is None:
                return slice_results + (self.lines, self.abs_lines, criteria_identifier)
            assert self.pdg is not None and self.method_dir is not None
            slice_nodes = slice_results[2]
            g = nx.subgraph(self.pdg.g, [node.node_id for node in slice_nodes])
            os.makedirs(self.method_dir, exist_ok=True)
            role = self.file.project.project_name
            nx.nx_agraph.write_dot(g, os.path.join(self.dot_dir, f"{role}_slicing.dot"))
            fp = open(f"{self.method_dir}/{role}_slicing.{self.file_suffix}", "w")
            fp.write(slice_results[3])
            fp.close()

            slice_result_lines, slice_result_weight, slice_result_edges = (
                slice_results[0],
                slice_results[5],
                slice_results[6],
            )
            graph = {}
            graph["edges"] = []
            graph["nodes"] = []

            for line in slice_result_lines:
                try:
                    graph["nodes"].append(f"{self.signature}#{line}")
                except:
                    graph["nodes"] = [f"{self.signature}#{line}"]
            for edge in slice_result_edges:
                try:
                    graph["edges"].append(
                        (f"{self.signature}#{edge[0]}", f"{self.signature}#{edge[1]}")
                    )
                except:
                    graph["edges"] = [
                        (f"{self.signature}#{edge[0]}", f"{self.signature}#{edge[1]}")
                    ]

            graph["node_dicts"] = {}
            for line in slice_result_lines:
                graph["node_dicts"][f"{self.signature}#{line}"] = {}
                graph["node_dicts"][f"{self.signature}#{line}"]["weight"] = (
                    slice_result_weight[line]
                )
                graph["node_dicts"][f"{self.signature}#{line}"]["node_string"] = (
                    self.lines[line]
                )
                graph["node_dicts"][f"{self.signature}#{line}"]["abs_node_string"] = (
                    self.abs_lines[line]
                )

            fp = open(f"{self.method_dir}/{role}_slicing_wfg.json", "w")
            json.dump(graph, fp, indent=4)
            fp.close()
            convert_to_dot(
                f"{self.method_dir}/{role}_slicing_wfg.json",
                f"{self.method_dir}/{role}_slicing_wfg.dot",
            )

        self.slice_line = slice_results

        return slice_results + (self.lines, self.abs_lines, criteria_identifier)

    def slice_by_diff_lines_detect(
        self,
        criteria_lines: set,
        counterpart_criteria_lines: set,
        need_criteria_identifier: bool = False,
        write_dot: bool = False,
        level=0,
        role="pre",
    ):
        diff_identifiers = self.diff_identifiers if need_criteria_identifier else {}
        modified_parameters = (
            self.modified_parameters if need_criteria_identifier else {}
        )
        criteria_identifier = diff_identifiers
        if need_criteria_identifier:
            for line in modified_parameters.keys():
                try:
                    criteria_identifier[line] = criteria_identifier[line].union(
                        modified_parameters[line]
                    )
                except:
                    criteria_identifier[line] = modified_parameters[line]

        for line in criteria_identifier:
            for identifier in list(criteria_identifier[line]):
                if "->" in identifier:
                    if len(identifier.split("->")) > 2:
                        criteria_identifier[line].add(
                            "->".join(identifier.split("->")[:-1])
                        )
                    else:
                        criteria_identifier[line].add(identifier.split("->")[0])
                elif "." in identifier:
                    if len(identifier.split(".")) > 2:
                        criteria_identifier[line].add(
                            ".".join(identifier.split(".")[:-1])
                        )
                    else:
                        criteria_identifier[line].add(identifier.split(".")[0])
        if self.slice_line is not None:
            return self.slice_line + (self.lines, self.abs_lines, criteria_identifier)
        elif level > 1:
            return None
        if len(criteria_lines) == 0:
            lines = self.counterpart.slice_by_diff_lines_detect(
                counterpart_criteria_lines,
                criteria_lines,
                need_criteria_identifier=True,
                write_dot=True,
                level=1,
            )
            if lines is None:
                return None
            sliced_lines = lines[0]
            for line in sliced_lines:
                criteria_lines.add(line)
        if self.start_line in criteria_lines:
            need_header_line = True
        else:
            need_header_line = False

        slice_results = self.slice_vul_detect(
            criteria_lines,
            criteria_identifier,
            is_rel=False,
            need_header_line=need_header_line,
        )
        if write_dot and slice_results is not None:
            if self.file.path == "libcpp/init.c":
                self.slice_line = slice_results
                return slice_results + (self.lines, self.abs_lines, criteria_identifier)
            if self.pdg is None:
                return slice_results + (self.lines, self.abs_lines, criteria_identifier)
            assert self.pdg is not None and self.method_dir is not None
            slice_nodes = slice_results[2]
            g = nx.subgraph(self.pdg.g, [node.node_id for node in slice_nodes])
            os.makedirs(self.method_dir, exist_ok=True)
            nx.nx_agraph.write_dot(g, os.path.join(self.dot_dir, f"{role}_slicing.dot"))
            fp = open(f"{self.method_dir}/{role}_slicing.{self.file_suffix}", "w")
            fp.write(slice_results[3])
            fp.close()

            slice_result_lines, slice_result_weight, slice_result_edges = (
                slice_results[0],
                slice_results[5],
                slice_results[6],
            )
            graph = {}
            graph["edges"] = []
            graph["nodes"] = []

            for line in slice_result_lines:
                try:
                    graph["nodes"].append(f"{self.signature}#{line}")
                except:
                    graph["nodes"] = [f"{self.signature}#{line}"]
            for edge in slice_result_edges:
                try:
                    graph["edges"].append(
                        (f"{self.signature}#{edge[0]}", f"{self.signature}#{edge[1]}")
                    )
                except:
                    graph["edges"] = [
                        (f"{self.signature}#{edge[0]}", f"{self.signature}#{edge[1]}")
                    ]
            graph["node_dicts"] = {}
            for line in slice_result_lines:
                graph["node_dicts"][f"{self.signature}#{line}"] = {}
                graph["node_dicts"][f"{self.signature}#{line}"]["weight"] = (
                    slice_result_weight[line]
                )
                graph["node_dicts"][f"{self.signature}#{line}"]["node_string"] = (
                    self.lines[line]
                )
                graph["node_dicts"][f"{self.signature}#{line}"]["abs_node_string"] = (
                    self.abs_lines[line]
                )

            fp = open(f"{self.method_dir}/{role}_slicing_wfg.json", "w")
            json.dump(graph, fp, indent=4)
            fp.close()
            convert_to_dot(
                f"{self.method_dir}/{role}_slicing_wfg.json",
                f"{self.method_dir}/{role}_slicing_wfg.dot",
            )

        self.slice_line = slice_results

        return slice_results + (self.lines, self.abs_lines, criteria_identifier)

    def slice_by_header_line_vul_detect(
        self,
        args_list: list = [],
        criteria_identifier: set = set(),
        need_criteria_identifier: bool = False,
        write_dot: bool = False,
    ):
        true_criteria_identifier = {}
        if self.slice_line is not None:
            return self.slice_line + (
                self.lines,
                self.abs_lines,
                true_criteria_identifier,
            )
        if need_criteria_identifier:
            identifiers = []
            parser = ASTParser(self.code, self.language)
            parameters = parser.query_all(
                "(parameter_list  ( parameter_declaration (identifier)@name ))(pointer_declarator(identifier))@name"
            )
            assert parameters is not None
            for parameter in parameters:
                identifiers.append(parameter.text.decode())
            param_arg_pairs = zip(identifiers, args_list)
            arg_param_mapping = {}
            for param, arg in param_arg_pairs:
                arg_param_mapping[arg] = param
            if len(criteria_identifier) == 0:
                for identifier in identifiers:
                    try:
                        true_criteria_identifier[self.start_line].append(identifier)
                    except:
                        true_criteria_identifier[self.start_line] = [identifier]
            else:
                for identifier in criteria_identifier:
                    try:
                        true_criteria_identifier[self.start_line].append(
                            arg_param_mapping[identifier]
                        )
                    except:
                        true_criteria_identifier[self.start_line] = [
                            arg_param_mapping[identifier]
                        ]

        for line in true_criteria_identifier:
            for identifier in list(true_criteria_identifier[line]):
                if "->" in identifier:
                    if len(identifier.split("->")) > 2:
                        true_criteria_identifier[line].add(
                            "->".join(identifier.split("->")[:-1])
                        )
                    else:
                        true_criteria_identifier[line].add(identifier.split("->")[0])
                elif "." in identifier:
                    if len(identifier.split(".")) > 2:
                        true_criteria_identifier[line].add(
                            ".".join(identifier.split(".")[:-1])
                        )
                    else:
                        true_criteria_identifier[line].add(identifier.split(".")[0])

        if self.slice_line is not None:
            return self.slice_line + (
                self.lines,
                self.abs_lines,
                true_criteria_identifier,
            )

        criteria_lines = set()
        criteria_lines.add(self.start_line)

        slice_results = self.slice_vul_detect(
            criteria_lines,
            true_criteria_identifier,
            is_rel=False,
            need_header_line=True,
        )
        if write_dot and slice_results is not None:
            if self.file.path == "libcpp/init.c":
                self.slice_line = slice_results
                return slice_results + (
                    self.lines,
                    self.abs_lines,
                    true_criteria_identifier,
                )
            if self.pdg is None:
                return slice_results + (
                    self.lines,
                    self.abs_lines,
                    true_criteria_identifier,
                )
            assert self.pdg is not None and self.method_dir is not None
            slice_nodes = slice_results[2]
            g = nx.subgraph(self.pdg.g, [node.node_id for node in slice_nodes])
            os.makedirs(self.method_dir, exist_ok=True)
            role = self.file.project.project_name
            nx.nx_agraph.write_dot(g, os.path.join(self.dot_dir, f"{role}_slicing.dot"))
            fp = open(f"{self.method_dir}/{role}_slicing.{self.file_suffix}", "w")
            fp.write(slice_results[3])
            fp.close()

            slice_result_lines, slice_result_weight, slice_result_edges = (
                slice_results[0],
                slice_results[5],
                slice_results[6],
            )
            graph = {}
            graph["edges"] = []
            graph["nodes"] = []
            for line in slice_result_lines:
                try:
                    graph["nodes"].append(f"{self.signature}#{line}")
                except:
                    graph["nodes"] = [f"{self.signature}#{line}"]
            for edge in slice_result_edges:
                try:
                    graph["edges"].append(
                        (f"{self.signature}#{edge[0]}", f"{self.signature}#{edge[1]}")
                    )
                except:
                    graph["edges"] = [
                        (f"{self.signature}#{edge[0]}", f"{self.signature}#{edge[1]}")
                    ]

            graph["node_dicts"] = {}
            for line in slice_result_lines:
                graph["node_dicts"][f"{self.signature}#{line}"] = {}
                graph["node_dicts"][f"{self.signature}#{line}"]["weight"] = (
                    slice_result_weight[line]
                )
                graph["node_dicts"][f"{self.signature}#{line}"]["node_string"] = (
                    self.lines[line]
                )
                graph["node_dicts"][f"{self.signature}#{line}"]["abs_node_string"] = (
                    self.abs_lines[line]
                )

            fp = open(f"{self.method_dir}/{role}_slicing_wfg.json", "w")
            json.dump(graph, fp, indent=4)
            fp.close()
            convert_to_dot(
                f"{self.method_dir}/{role}_slicing_wfg.json",
                f"{self.method_dir}/{role}_slicing_wfg.dot",
            )

        self.slice_line = slice_results

        return slice_results + (self.lines, self.abs_lines, true_criteria_identifier)


if __name__ == "__main__":
    pass
