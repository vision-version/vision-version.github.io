from __future__ import annotations

import ast
import copy
import logging
import os
import subprocess
import sys
import traceback
from typing import Any

import cpu_heater
import networkx as nx

import joern_node
from common import Language


def set_joern_env(joern_path: str):
    os.environ["PATH"] = joern_path + os.pathsep + os.environ["PATH"]
    assert (
        subprocess.run(["which", "joern"], stdout=subprocess.PIPE)
        .stdout.decode()
        .strip()
        == joern_path + "/joern"
    )
    os.environ["JOERN_HOME"] = joern_path


def export(
    code_path: str, output_path: str, language: Language, overwrite: bool = False
):
    pdg_dir = os.path.join(output_path, "pdg")
    cfg_dir = os.path.join(output_path, "cfg")
    cpg_dir = os.path.join(output_path, "cpg")
    cpg_bin = os.path.join(output_path, "cpg.bin")
    if (
        os.path.exists(pdg_dir)
        and os.path.exists(cfg_dir)
        and os.path.exists(cpg_dir)
        and not overwrite
    ):
        return
    else:
        if os.path.exists(pdg_dir):
            subprocess.run(["rm", "-rf", pdg_dir])
        if os.path.exists(cpg_dir):
            subprocess.run(["rm", "-rf", cfg_dir])
        if os.path.exists(cpg_bin):
            subprocess.run(["rm", "-rf", cpg_bin])
    subprocess.run(
        ["joern-parse", "--language", language.value, os.path.abspath(code_path)],
        cwd=output_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    subprocess.run(
        ["joern-export", "--repr", "cfg", "--out", os.path.abspath(cfg_dir)],
        cwd=output_path,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["joern-export", "--repr", "pdg", "--out", os.path.abspath(pdg_dir)],
        cwd=output_path,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["joern-export", "--repr", "all", "--out", os.path.abspath(cpg_dir)],
        cwd=output_path,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

def joern_script_run(cpgFile: str, script_path: str, output_path: str):
    subprocess.run(
        [
            "joern",
            "--script",
            script_path,
            "--param",
            f"cpgFile={cpgFile}",
            "--param",
            f"outFile={output_path}",
        ],
        cwd=os.path.dirname(cpgFile),
    )


def preprocess(pdg_dir: str, cfg_dir: str, cpg_dir: str, need_cdg: bool):
    flag = False
    t = 0
    cpg = None
    while not flag:
        try:
            cpg = nx.nx_agraph.read_dot(os.path.join(cpg_dir, "export.dot"))
            flag = True
        except Exception as e:
            print(e)
            import re

            if t >= 10:
                break
            if str(e).startswith("Error: syntax error"):
                matches = re.findall(r"'(.*?)'", str(e))
                fp = open(os.path.join(cpg_dir, "export.dot"))
                lines = fp.read()
                fp.close()
                for match in matches:
                    lines = lines.replace(match, f"\{match}")

                fp = open(os.path.join(cpg_dir, "export.dot"), "w")
                fp.write(lines)
                fp.close()
                t += 1
            else:
                break
    if cpg is None:
        return

    for pdg_file in os.listdir(pdg_dir):
        file_id = pdg_file.split("-")[0]
        try:
            pdg: nx.MultiDiGraph = nx.nx_agraph.read_dot(
                os.path.join(pdg_dir, pdg_file)
            )
            if os.path.exists(os.path.join(cfg_dir, f"{file_id}-cfg.dot")):
                cfg: nx.MultiDiGraph = nx.nx_agraph.read_dot(
                    os.path.join(cfg_dir, f"{file_id}-cfg.dot")
                )
        except Exception as e:
            logging.error(f"Error in reading {pdg_file} or {file_id}-cfg.dot")
            os.remove(os.path.join(pdg_dir, pdg_file))
            if os.path.exists(os.path.join(cfg_dir, f"{file_id}-cfg.dot")):
                os.remove(os.path.join(cfg_dir, f"{file_id}-cfg.dot"))
            continue

        ddg_null_edges = []
        for u, v, k, d in pdg.edges(data=True, keys=True):
            if need_cdg:
                null_edges_label = ["DDG: ", "DDG: this"]
            else:
                null_edges_label = ["DDG: ", "CDG: ", "DDG: this"]
            if d["label"] in null_edges_label:
                ddg_null_edges.append((u, v, k, d))
        pdg.remove_edges_from(ddg_null_edges)

        if os.path.exists(os.path.join(cfg_dir, f"{file_id}-cfg.dot")):
            dg: nx.MultiDiGraph = nx.compose(pdg, cfg)
        for u, v, k, d in pdg.edges(data=True, keys=True):
            if "label" not in d:
                pdg.edges[u, v, k]["label"] = "CFG"

        method_node = None
        param_nodes = []
        for node in pdg.nodes:
            if node not in cpg.nodes.keys():
                continue
            for key, value in cpg.nodes[node].items():
                pdg.nodes[node][key] = value
            pdg.nodes[node]["NODE_TYPE"] = pdg.nodes[node]["label"]
            node_type = pdg.nodes[node]["NODE_TYPE"]
            if node_type == "METHOD":
                method_node = node
            if node_type == "METHOD_PARAMETER_IN":
                param_nodes.append(node)
            if "CODE" not in pdg.nodes[node]:
                pdg.nodes[node]["CODE"] = ""
            node_code = (
                pdg.nodes[node]["CODE"]
                .replace("\n", "\\n")
                .replace('"', r"__quote__")
                .replace("\\", r"__Backslash__")
            )
            pdg.nodes[node]["CODE"] = (
                pdg.nodes[node]["CODE"]
                .replace("\n", "\\n")
                .replace('"', r"__quote__")
                .replace("\\", r"__Backslash__")
            )
            node_line = (
                pdg.nodes[node]["LINE_NUMBER"]
                if "LINE_NUMBER" in pdg.nodes[node]
                else 0
            )
            node_column = (
                pdg.nodes[node]["COLUMN_NUMBER"]
                if "COLUMN_NUMBER" in pdg.nodes[node]
                else 0
            )
            pdg.nodes[node]["label"] = (
                f"[{node}][{node_line}:{node_column}][{node_type}]: {node_code}"
            )
            if pdg.nodes[node]["NODE_TYPE"] == "METHOD_RETURN":
                pdg.remove_edges_from(list(pdg.in_edges(node)))
        for param_node in param_nodes:
            pdg.add_edge(method_node, param_node, label="DDG")

        nx.nx_agraph.write_dot(pdg, os.path.join(pdg_dir, pdg_file))


def merge_node(pdg, nodes, line, full_code):
    new_node_line_map = {}
    new_node = pdg.nodes[nodes[0]].copy()
    max_col = 0
    min_col = sys.maxsize
    new_node["label"] = (
        full_code[int(line) - 1]
        .strip()
        .replace(r'"', r"__quote__")
        .replace("\\", r"__Backslash__")
    )
    new_node["CODE"] = (
        full_code[int(line) - 1]
        .strip()
        .replace(r'"', r"__quote__")
        .replace("\\", r"__Backslash__")
    )
    new_node["INCLUDE_ID"] = {line: nodes}
    for node in nodes:
        for key, value in pdg.nodes[node].items():
            if key in [
                "label",
                "LINE_NUMBER",
                "CODE",
                "FILENAME",
                "FULL_NAME",
                "LINE_NUMBER_END",
            ]:
                continue
            if key == "COLUMN_NUMBER":
                min_col = min(min_col, int(value))
                continue
            if key == "COLUMN_NUMBER_END":
                max_col = max(max_col, int(value))
                continue
            try:
                new_node[key].append(value)
            except:
                new_node[key] = [value]
    new_node["COLUMN_NUMBER"] = min_col
    new_node["COLUMN_NUMBER_END"] = max_col
    new_node_line_map[line] = new_node

    return new_node_line_map


def merge(output_path: str, pdg_dir: str, code_dir: str, overwrite: bool = False):
    pdg_old_merge_dir = os.path.join(output_path, "pdg_old_merge")
    if overwrite or not os.path.exists(pdg_old_merge_dir):
        if os.path.exists(pdg_old_merge_dir):
            subprocess.run(["rm", "-rf", pdg_old_merge_dir])
        subprocess.run(["cp", "-r", pdg_dir, pdg_old_merge_dir])
        for pdg_file in os.listdir(pdg_dir):
            try:
                pdg: nx.MultiDiGraph = nx.nx_agraph.read_dot(
                    os.path.join(pdg_dir, pdg_file)
                )
            except Exception as e:
                logging.error(f"Error in reading {pdg_file}")
                os.remove(os.path.join(pdg_dir, pdg_file))
                continue

            node_line_map = {}
            file_name = ""
            already_merged = False
            for node in pdg.nodes:
                if "INCLUDE_ID" in pdg.nodes[node].keys():
                    already_merged = True
                if "CODE" not in pdg.nodes[node]:
                    pdg.nodes[node]["CODE"] = ""
                node_line = (
                    pdg.nodes[node]["LINE_NUMBER"]
                    if "LINE_NUMBER" in pdg.nodes[node]
                    else 0
                )
                if "FILENAME" in pdg.nodes[node].keys():
                    file_name = pdg.nodes[node]["FILENAME"]
                if "NODE_TYPE" not in pdg.nodes[node].keys():
                    continue
                node_type = pdg.nodes[node]["NODE_TYPE"]
                if node_type == "METHOD":
                    continue
                try:
                    node_line_map[node_line].append(node)
                except:
                    node_line_map[node_line] = [node]
            if file_name == "":
                continue
            if already_merged:
                continue
            if not os.path.exists(os.path.join(code_dir, file_name)):
                continue

            fp = open(os.path.join(code_dir, file_name))
            full_code = fp.readlines()
            fp.close()
            new_node_line_maps = {}
            worker_list = []
            for line in node_line_map:
                if line == 0:
                    continue
                if int(line) > len(full_code):
                    continue
                worker_list.append((pdg, node_line_map[line], line, full_code))
            results = cpu_heater.multithreads(
                merge_node, worker_list, max_workers=512, show_progress=False
            )
            for new_node_line_map in results:
                new_node_line_maps.update(new_node_line_map)

            for line in new_node_line_maps:
                for key, value in new_node_line_maps[line].items():
                    pdg.nodes[node_line_map[line][0]][key] = value

            for line in node_line_map:
                for i, node in enumerate(node_line_map[line]):
                    if i == 0:
                        continue
                    in_edges = pdg.in_edges(node, data=True, keys=True)
                    out_edges = pdg.out_edges(node, data=True, keys=True)
                    for u, v, k, d in in_edges:
                        if u == node_line_map[line][0]:
                            continue
                        pdg.add_edge(u, node_line_map[line][0], label=d["label"])
                    for u, v, k, d in out_edges:
                        if v == node_line_map[line][0]:
                            continue
                        pdg.add_edge(node_line_map[line][0], v, label=d["label"])
                    pdg.remove_edges_from(list(in_edges))
                    pdg.remove_node(node)

            edges = set()
            raw_edges = copy.deepcopy(pdg.edges(data=True, keys=True))
            for u, v, k, d in raw_edges:
                if f"{u}__split__{v}__split__{d['label']}" in edges:
                    pdg.remove_edge(u, v, k)
                else:
                    edges.add(f"{u}__split__{v}__split__{d['label']}")
            nx.nx_agraph.write_dot(pdg, os.path.join(pdg_dir, pdg_file))


def add_cfg_lines(
    output_path: str, pdg_dir: str, code_dir: str, cpg_dir: str, overwrite: bool = False
):
    pdg_old_add_var_def_dir = os.path.join(output_path, "pdg_old_def")
    if overwrite or not os.path.exists(pdg_old_add_var_def_dir):
        if os.path.exists(pdg_old_add_var_def_dir):
            subprocess.run(["rm", "-rf", pdg_old_add_var_def_dir])
        subprocess.run(["cp", "-r", pdg_dir, pdg_old_add_var_def_dir])

        cpg = None
        flag = False
        t = 0
        while not flag:
            try:
                cpg = nx.nx_agraph.read_dot(os.path.join(cpg_dir, "export.dot"))
                flag = True
            except Exception as e:
                print(e)
                import re

                if t >= 10:
                    break
                if str(e).startswith("Error: syntax error"):
                    matches = re.findall(r"'(.*?)'", str(e))
                    fp = open(os.path.join(cpg_dir, "export.dot"))
                    lines = fp.read()
                    fp.close()
                    for match in matches:
                        lines = lines.replace(match, f"\{match}")

                    fp = open(os.path.join(cpg_dir, "export.dot"), "w")
                    fp.write(lines)
                    fp.close()
                    t += 1
                else:
                    break
        if cpg is None:
            return
        ids = set()
        for node in cpg.nodes:
            ids.add(int(node))
        max_id = max(ids) + 1
        for pdg_file in os.listdir(pdg_dir):
            try:
                pdg: nx.MultiDiGraph = nx.nx_agraph.read_dot(
                    os.path.join(pdg_dir, pdg_file)
                )
            except Exception as e:
                logging.error(f"Error in reading {pdg_file}")
                os.remove(os.path.join(pdg_dir, pdg_file))
                continue
            file_name = ""
            method_node = None
            lines = set()
            line_node_map = {}
            for node in pdg.nodes:
                node_line = (
                    pdg.nodes[node]["LINE_NUMBER"]
                    if "LINE_NUMBER" in pdg.nodes[node]
                    else 0
                )
                line_node_map[int(node_line)] = node
                lines.add(int(node_line))
                if "FILENAME" in pdg.nodes[node].keys():
                    file_name = pdg.nodes[node]["FILENAME"]
                if "NODE_TYPE" not in pdg.nodes[node]:
                    print(pdg_file)

                if pdg.nodes[node]["NODE_TYPE"] == "METHOD":
                    method_node = node
                elif "LINE_NUMBER_END" in pdg.nodes[node].keys():
                    lines.add(
                        i
                        for i in range(
                            int(pdg.nodes[node]["LINE_NUMBER"]),
                            int(pdg.nodes[node]["LINE_NUMBER_END"] + 1),
                        )
                    )
            if method_node is None:
                continue
            if not os.path.exists(os.path.join(code_dir, file_name)):
                continue
            fp = open(os.path.join(code_dir, file_name))
            full_code = fp.readlines()
            fp.close()

            if "LINE_NUMBER" not in pdg.nodes[method_node].keys():
                continue
            line = int(pdg.nodes[method_node]["LINE_NUMBER"])
            if "LINE_NUMBER_END" not in pdg.nodes[method_node].keys():
                continue

            while line < int(pdg.nodes[method_node]["LINE_NUMBER_END"]):
                if line in lines:
                    line += 1
                    continue
                if (
                    line > len(full_code)
                    or full_code[line - 1]
                    .replace(" ", "")
                    .replace("{", "")
                    .replace("}", "")
                    .replace("\t", "")
                    .replace("\n", "")
                    .replace("(", "")
                    .replace(")", "")
                    == ""
                ):
                    line += 1
                    continue

                new_node_attr = {
                    "CODE": full_code[int(line) - 1]
                    .strip()
                    .replace(r'"', r"__quote__")
                    .replace("\\", r"__Backslash__"),
                    "label": full_code[int(line) - 1]
                    .strip()
                    .replace(r'"', r"__quote__")
                    .replace("\\", r"__Backslash__"),
                    "INCLUDE_ID": {line: max_id},
                    "LINE_NUMBER": line,
                    "NODE_TYPE": ["variable_declaration"],
                }

                pdg.add_node(max_id, **new_node_attr)
                if line - 1 in line_node_map.keys():
                    pdg.add_edge(line_node_map[line - 1], max_id, label="CFG")
                if line + 1 in lines and line + 1 in line_node_map.keys():
                    pdg.add_edge(max_id, line_node_map[line + 1], label="CFG")
                line_node_map[line] = max_id
                max_id += 1
                line += 1
            nx.nx_agraph.write_dot(pdg, os.path.join(pdg_dir, pdg_file))


def export_with_preprocess(
    code_path: str,
    output_path: str,
    language: Language,
    overwrite: bool = False,
    cdg_need: bool = True,
):
    export(
        code_path=code_path,
        output_path=output_path,
        language=language,
        overwrite=overwrite,
    )
    pdg_dir = os.path.join(output_path, "pdg")
    cfg_dir = os.path.join(output_path, "cfg")
    cpg_dir = os.path.join(output_path, "cpg")
    pdg_old_dir = os.path.join(output_path, "pdg-old")
    if overwrite or not os.path.exists(pdg_old_dir):
        if os.path.exists(pdg_old_dir):
            subprocess.run(["rm", "-rf", pdg_old_dir])
        subprocess.run(["cp", "-r", pdg_dir, pdg_old_dir])
        preprocess(pdg_dir, cfg_dir, cpg_dir, cdg_need)


def export_with_preprocess_and_merge(
    code_path: str,
    output_path: str,
    language: Language,
    overwrite: bool = False,
    cdg_need: bool = True,
):
    pdg_dir = os.path.join(output_path, "pdg")
    cpg_dir = os.path.join(output_path, "cpg")
    print("export_with_preprocess")
    export_with_preprocess(code_path, output_path, language, overwrite)

    print("merge")
    merge(output_path, pdg_dir, code_path, overwrite)

    print("add_cfg_lines")
    add_cfg_lines(output_path, pdg_dir, code_path, cpg_dir, overwrite)


class CPGNode:
    def __init__(self, node_id: int):
        self.node_id = node_id
        self.attr = {}

    def get_value(self, key: str) -> str | None:
        if key in self.attr:
            return self.attr[key]
        else:
            return None

    def set_attr(self, key: str, value: str):
        self.attr[key] = value


class Edge:
    def __init__(self, edge_id: tuple[int, int]):
        self.edge_id = edge_id
        self.attr: list[tuple[int, int]] = []

    def set_attr(self, key, value):
        self.attr.append((key, value))


class CPG:
    def __init__(self, cpg_dir: str):
        self.cpg_dir = cpg_dir
        cpg_path = os.path.join(cpg_dir, "export.dot")
        if not os.path.exists(cpg_path):
            raise FileNotFoundError(f"export.dot is not found in {cpg_path}")
        cpg = None
        flag = False
        t = 0
        while not flag:
            try:
                cpg = nx.nx_agraph.read_dot(cpg_path)
                flag = True
            except Exception as e:
                error_message = traceback.format_exc()
                print(e)
                import re

                if t >= 10:
                    break
                if str(e).startswith("Error: syntax error"):
                    matches = re.findall(r"'(.*?)'", str(e))
                    fp = open(cpg_path)
                    lines = fp.read()
                    fp.close()
                    for match in matches:
                        lines = lines.replace(match, f"\{match}")

                    fp = open(os.path.join(cpg_dir, "export.dot"), "w")
                    fp.write(lines)
                    fp.close()
                    t += 1
                else:
                    break
        self.g: nx.MultiDiGraph = cpg

    def get_node(self, node_id: int) -> dict[str, str]:
        return self.g.nodes[node_id]

    def _init__(self, cpg_dir: str):
        self.cpg_dir = cpg_dir
        cpg_path = os.path.join(cpg_dir, "export.dot")
        if not os.path.exists(cpg_path):
            raise FileNotFoundError(f"export.dot is not found in {cpg_path}")
        if not os.path.exists(cpg_path):
            raise FileNotFoundError(f"export.dot is not found in {cpg_path}")
        cpg = None
        flag = False
        t = 0
        while not flag:
            try:
                cpg = nx.nx_agraph.read_dot(cpg_path)
                flag = True
            except Exception as e:
                print(e)
                import re

                if t >= 10:
                    break
                if str(e).startswith("Error: syntax error"):
                    matches = re.findall(r"'(.*?)'", str(e))
                    fp = open(cpg_path)
                    lines = fp.read()
                    fp.close()
                    for match in matches:
                        lines = lines.replace(match, f"\{match}")

                    fp = open(os.path.join(cpg_dir, "export.dot"), "w")
                    fp.write(lines)
                    fp.close()
                    t += 1
                else:
                    break
        cpg_nx: nx.MultiDiGraph = cpg
        self.g: nx.MultiDiGraph = nx.MultiDiGraph()
        for nx_node in cpg_nx.nodes():
            node_type = cpg_nx.nodes[nx_node]["label"]
            node = self._parser_node(node_type, int(nx_node), cpg_nx.nodes[nx_node])
            self.g.add_node(int(nx_node), **node.to_dict())
        for u, v, data in cpg_nx.edges(data=True):
            src = int(u)
            dst = int(v)
            self.g.add_edge(src, dst, **data)
        for u, v, data in self.g.edges(data=True):
            print(u, v, data)

    def _parser_node(self, node_type: str, node_id: int, node_attr: dict[str, str]):
        Node = getattr(joern_node, node_type)
        attr: dict[str, Any] = {}
        for key in Node.__dataclass_fields__.keys():
            if key.upper() in node_attr:
                if key in [
                    "line_number",
                    "column_number",
                    "line_number_end",
                    "column_number_end",
                    "order",
                    "argument_index",
                    "index",
                ]:
                    attr[key] = int(node_attr[key.upper()])
                elif key in ["is_external", "is_variadic"]:
                    attr[key] = bool(node_attr[key.upper()])
                else:
                    attr[key] = node_attr[key.upper()]
        node: joern_node.NODE = Node(id=node_id, **attr)
        return node


class PDGNode:
    def __init__(self, node_id: int, attr: dict[str, str], pdg: PDG):
        self.node_id: int = node_id
        self.attr: dict[str, str] = attr
        self.pdg: PDG = pdg
        self.is_patch_node = False

    def __hash__(self):
        return hash(self.node_id)

    def __eq__(self, node: object):
        if not isinstance(node, PDGNode):
            return False
        if self.node_id == node.node_id:
            return True
        else:
            return False

    @property
    def line_number(self) -> int | None:
        if "LINE_NUMBER" not in self.attr:
            return None
        return int(self.attr["LINE_NUMBER"])

    @property
    def type(self) -> str:
        return self.attr["NODE_TYPE"]

    @property
    def code(self) -> str:
        if "CODE" not in self.attr:
            return ""
        return (
            self.attr["CODE"]
            .replace(r"__quote__", r'"')
            .replace("__Backslash__", r"\\")
        )

    @property
    def get_successors(self) -> list[PDGNode]:
        nodes = []
        for node in self.pdg.g.successors(self.node_id):
            nodes.append(PDGNode(node, self.pdg.g.nodes[node], self.pdg))
        return nodes

    @property
    def get_predecessors(self) -> list[PDGNode]:
        nodes = []
        for node in self.pdg.g.predecessors(self.node_id):
            nodes.append(PDGNode(node, self.pdg.g.nodes[node], self.pdg))
        return nodes

    def get_predecessors_by_label(self, label: str) -> list[tuple[PDGNode, str]]:
        nodes = []
        for node in self.pdg.g.predecessors(self.node_id):
            for _, edge in self.pdg.g[node][self.node_id].items():
                if edge["label"].startswith(label):
                    nodes.append(
                        (PDGNode(node, self.pdg.g.nodes[node], self.pdg), edge["label"])
                    )
        return nodes

    def get_successors_by_label(self, label: str) -> list[tuple[PDGNode, str]]:
        nodes = []
        for node in self.pdg.g.successors(self.node_id):
            for _, edge in self.pdg.g[self.node_id][node].items():
                if edge["label"].startswith(label):
                    nodes.append(
                        (PDGNode(node, self.pdg.g.nodes[node], self.pdg), edge["label"])
                    )
        return nodes

    @property
    def pred_cfg_nodes(self) -> list[PDGNode]:
        pred = self.get_predecessors_by_label("CFG")
        return [node for node, _ in pred]

    @property
    def succ_cfg_nodes(self) -> list[PDGNode]:
        succ = self.get_successors_by_label("CFG")
        return [node for node, _ in succ]

    @property
    def pred_ddg_nodes(self) -> list[PDGNode]:
        pred = self.get_predecessors_by_label("DDG")
        return [node for node, _ in pred]

    @property
    def pred_cdg(self) -> list[PDGNode]:
        pred = self.get_predecessors_by_label("CDG")
        return [node for node, _ in pred]

    @property
    def succ_cdg(self) -> list[PDGNode]:
        succ = self.get_successors_by_label("CDG")
        return [node for node, _ in succ]

    @property
    def pred_ddg(self) -> list[tuple[PDGNode, str]]:
        pred_ddg = self.get_predecessors_by_label("DDG")
        pred_ddg = [(node, e.replace("DDG: ", "")) for node, e in pred_ddg]
        return pred_ddg

    @property
    def succ_ddg(self) -> list[tuple[PDGNode, str]]:
        succ_ddg = self.get_successors_by_label("DDG")
        succ_ddg = [(node, e.replace("DDG: ", "")) for node, e in succ_ddg]
        return succ_ddg

    @property
    def succ_ddg_nodes(self) -> list[PDGNode]:
        succ = self.get_successors_by_label("DDG")
        return [node for node, _ in succ]

    def add_attr(self, key: str, value: str):
        self.attr[key] = value


class PDG:
    def __init__(self, pdg_path: str) -> None:
        self.pdg_path = pdg_path
        if not os.path.exists(self.pdg_path):
            raise FileNotFoundError(f"dot file is not found in {self.pdg_path}")

        self.g: nx.MultiDiGraph = nx.nx_agraph.read_dot(pdg_path)
        self.method_node = None
        for node in self.g.nodes():
            if self.g.nodes[node]["NODE_TYPE"] == "METHOD":
                self.method_node = node
                break

        self.line_map_method_nodes = {self.method_node: [self.method_node]}
        for node in self.g.nodes():
            if "INCLUDE_ID" not in self.g.nodes[node].keys():
                continue
            else:
                self.line_map_method_nodes.update(
                    ast.literal_eval(self.g.nodes[node]["INCLUDE_ID"])
                )

    @property
    def method_node_id(self):
        return self.method_node

    @property
    def line_map_method_nodes_id(self):
        return self.line_map_method_nodes

    @property
    def filename(self) -> str | None:
        if self.method_node == None:
            return None
        return self.g.nodes[self.method_node]["FILENAME"]

    @property
    def line_number(self) -> int | None:
        if (
            self.method_node is None
            or "LINE_NUMBER" not in self.g.nodes[self.method_node]
        ):
            return None
        return int(self.g.nodes[self.method_node]["LINE_NUMBER"])

    @property
    def name(self) -> str | None:
        if self.method_node == None:
            return None
        if "NAME" not in self.g.nodes[self.method_node].keys():
            return None
        return self.g.nodes[self.method_node]["NAME"]

    def get_node(self, node_id) -> PDGNode:
        return PDGNode(node_id, self.g.nodes[node_id], self)

    def get_nodes_by_line_number(self, line_number: int) -> list[PDGNode]:
        nodes: list[PDGNode] = []
        for node, attr in self.g.nodes.items():
            if "LINE_NUMBER" not in attr:
                continue
            if attr["LINE_NUMBER"] == str(line_number):
                pdg_node = PDGNode(node, attr, self)
                nodes.append(pdg_node)
        return nodes


if __name__ == "__main__":
    pass
