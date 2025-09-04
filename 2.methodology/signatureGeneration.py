import json
import os
import sys

import cpu_heater

import hunkmap
import joern
from ast_parser import ASTParser
from codefile import create_code_tree
from common import Language
from json2dot import convert_to_dot
from patch import Patch
from project import Method, Project
from split_clusters import split_clusters

JOERN_PATH = "/path/to/joern"
CACHE_DIR = "/path/to/signature"


def export_joern_graph(
    pre_dir: str,
    post_dir: str,
    need_cdg: bool,
    language: Language,
    multiprocess: bool = True,
    overwrite: bool = False,
):
    worker_args = [
        (f"{pre_dir}/code", pre_dir, language, overwrite, need_cdg),
        (f"{post_dir}/code", post_dir, language, overwrite, need_cdg),
    ]
    if multiprocess:
        cpu_heater.multiprocess(
            joern.export_with_preprocess_and_merge,
            worker_args,
            max_workers=2,
            show_progress=False,
        )
    else:
        joern.export_with_preprocess_and_merge(*worker_args[0])
        joern.export_with_preprocess_and_merge(*worker_args[1])


def write2file(file_path: str, content: str):
    with open(file_path, "w") as f:
        f.write(content)


def get_pre_post_methods(
    patch, pre_post_projects: tuple[Project, Project], signature: str
):
    pre_project, post_project = pre_post_projects

    pre_method = pre_project.get_method(signature)
    if signature in patch.change_method_map_dict.keys():
        post_method = post_project.get_method(
            patch.change_method_map_dict[signature][0]
        )
    else:
        post_method = post_project.get_method(signature)
    if pre_method is None:
        return
    if post_method is None:
        return
    return pre_method, post_method


def init_method_dir(pre_post_methods: tuple[Method, Method], cache_dir: str):
    pre_method, post_method = pre_post_methods
    method_dir = f"{cache_dir}/method/{pre_method.signature_r}"
    dot_dir = f"{cache_dir}/method/{pre_method.signature_r}/dot"

    os.makedirs(method_dir, exist_ok=True)
    os.makedirs(dot_dir, exist_ok=True)

    pre_method.method_dir, post_method.method_dir = (method_dir,) * 2
    pre_method.write_code(method_dir)
    post_method.write_code(method_dir)
    pre_method.write_dot(dot_dir)
    post_method.write_dot(dot_dir)

    return method_dir


def init_single_method_dir(method, cache_dir):
    method_dir = f"{cache_dir}/method/{method.signature_r}"
    dot_dir = f"{cache_dir}/method/{method.signature_r}/dot"

    os.makedirs(dot_dir, exist_ok=True)
    os.makedirs(method_dir, exist_ok=True)

    method.method_dir = method_dir
    method.write_code(method_dir)
    method.write_dot(dot_dir)

    return method_dir


def worker_fn(pre_project: Project, ref_id, cnt):
    if cnt > 3:
        return None
    callees = pre_project.get_callee(ref_id)
    return callees, cnt + 1, ref_id


def get_callgraph(patch, project):
    edges = set()
    points = set()
    step = 0
    worker_list = []
    for method_signature in patch.changed_methods:
        points.add(method_signature)
        worker_list.append((project, method_signature, step))

    if len(patch.changed_methods) >= 10:
        return points, edges

    while worker_list != []:
        results = cpu_heater.multithreads(
            worker_fn, worker_list, max_workers=256, show_progress=False
        )
        worker_list = []
        for res in results:
            if res is None:
                continue
            callee, cnt, ref_id = res
            if cnt > 3:
                continue
            for point in callee:
                points.add(ref_id)
                points.add(point["callee_method_name"])
                point["caller_method_name"] = ref_id
                edges.add(
                    (
                        ref_id,
                        point["callee_method_name"],
                        point["callee_linenumber"],
                        point["method_line_number"],
                    )
                )
                if point["callee_method_name"] in points:
                    continue
                worker_list.append((project, point["callee_method_name"], cnt))

    return points, edges


def get_pre_post_call(patch, pre_post_projects, cache_dir):
    if os.path.exists(f"{cache_dir}/call.json"):
        fp = open(f"{cache_dir}/call.json")
        graph = json.load(fp)
        fp.close()
        return graph
    pre_project, post_project = pre_post_projects

    points, edges = get_callgraph(patch, pre_project)
    call = {}
    call["pre"] = {}
    call["pre"]["points"] = list(points)
    call["pre"]["edges"] = list(edges)
    points, edges = get_callgraph(patch, post_project)
    call["post"] = {}
    call["post"]["points"] = list(points)
    call["post"]["edges"] = list(edges)
    fp = open(f"{cache_dir}/call.json", "w")
    json.dump(call, fp, indent=4)
    fp.close()

    return call


def slicing_single_method(patch, method_signature, pre_post_projects, cache_dir):
    pre_post_methods: None | tuple[Method, Method] = get_pre_post_methods(
        patch, pre_post_projects, method_signature
    )
    assert pre_post_methods is not None

    init_method_dir(pre_post_methods, cache_dir)
    pre_method, post_method = pre_post_methods
    pre_method.counterpart = post_method
    post_method.counterpart = pre_method

    pre_post_line_map, pre_post_hunk_map, pre_post_add_lines, re_post_del_lines = (
        hunkmap.method_map(pre_method, post_method)
    )
    post_pre_line_map = {v: k for k, v in pre_post_line_map.items()}
    if pre_post_methods is None:
        return None, None
    if (
        method_signature
        == "tensorflow/core/grappler/costs/op_level_cost_estimator.cc#PredictFusedOp"
    ):
        return None, None

    pre_slice_results = pre_method.slice_by_diff_lines_vul_detect(
        need_criteria_identifier=True,
        write_dot=True,
        self_counterpart_line_map=post_pre_line_map,
    )
    post_slice_results = post_method.slice_by_diff_lines_vul_detect(
        need_criteria_identifier=True,
        write_dot=True,
        self_counterpart_line_map=pre_post_line_map,
    )

    return pre_slice_results, post_slice_results


def slice_per_callee(
    patch,
    project,
    cache_dir,
    callgraph,
    sliced_results,
    method_signature,
    visited,
    pre_post_projects,
    level,
    is_pre,
):
    sliced_graph = {}
    sliced_graph["nodes"] = []
    sliced_graph["edges"] = []
    sliced_graph["node_dicts"] = {}
    (
        slice_result_lines,
        slice_result_weight,
        slice_result_edges,
        lines,
        abs_lines,
        criteria_identifier,
    ) = (
        sliced_results[0],
        sliced_results[5],
        sliced_results[6],
        sliced_results[7],
        sliced_results[8],
        sliced_results[9],
    )
    if level > 3:
        return None, visited
    if is_pre:
        call_edges = callgraph["pre"]["edges"]
    else:
        call_edges = callgraph["post"]["edges"]

    for call_edge in call_edges:
        if int(call_edge[2]) in slice_result_lines and call_edge[0] == method_signature:
            callee_mathod = project.get_method(call_edge[1])
            if callee_mathod is None:
                continue
            assert callee_mathod is not None
            if call_edge[1] in patch.changed_methods:
                if call_edge[1] in visited:
                    continue
                visited.add(call_edge[1])
                pre_slice_callee_results, post_slice_callee_results = (
                    slicing_single_method(
                        patch, call_edge[1], pre_post_projects, cache_dir
                    )
                )
                if (
                    pre_slice_callee_results is None
                    or post_slice_callee_results is None
                ):
                    continue
                if is_pre:
                    (
                        pre_slice_callee_result_lines,
                        pre_slice_callee_result_weight,
                        pre_slice_callee_result_edges,
                        pre_callee_lines,
                        pre_callee_abs_lines,
                    ) = (
                        pre_slice_callee_results[0],
                        pre_slice_callee_results[5],
                        pre_slice_callee_results[6],
                        pre_slice_callee_results[7],
                        pre_slice_callee_results[8],
                    )
                    callee_results = pre_slice_callee_results
                else:
                    (
                        pre_slice_callee_result_lines,
                        pre_slice_callee_result_weight,
                        pre_slice_callee_result_edges,
                        pre_callee_lines,
                        pre_callee_abs_lines,
                    ) = (
                        post_slice_callee_results[0],
                        post_slice_callee_results[5],
                        post_slice_callee_results[6],
                        post_slice_callee_results[7],
                        post_slice_callee_results[8],
                    )
                    callee_results = post_slice_callee_results

                if len(pre_slice_callee_result_lines) == 0:
                    continue
                for line in pre_slice_callee_result_lines:
                    try:
                        sliced_graph["nodes"].append(f"{call_edge[0]}#{line}")
                    except:
                        sliced_graph["nodes"] = [f"{call_edge[0]}#{line}"]
                for edge in pre_slice_callee_result_edges:
                    try:
                        sliced_graph["edges"].append(
                            (f"{call_edge[0]}#{edge[0]}", f"{call_edge[0]}#{edge[1]}")
                        )
                    except:
                        sliced_graph["edges"] = [
                            (f"{call_edge[0]}#{edge[0]}", f"{call_edge[0]}#{edge[1]}")
                        ]

                sliced_graph["node_dicts"] = {}
                for line in pre_slice_callee_result_lines:
                    sliced_graph["node_dicts"][f"{call_edge[0]}#{line}"] = {}
                    sliced_graph["node_dicts"][f"{call_edge[0]}#{line}"]["weight"] = (
                        pre_slice_callee_result_weight[line]
                    )
                    sliced_graph["node_dicts"][f"{call_edge[0]}#{line}"][
                        "node_string"
                    ] = pre_callee_lines[line]
                    sliced_graph["node_dicts"][f"{call_edge[0]}#{line}"][
                        "abs_node_string"
                    ] = pre_callee_abs_lines[line]

                caller_line = f"{method_signature}#{call_edge[2]}"
                callee_line = f"{callee_mathod.signature}#{sorted(pre_slice_callee_result_lines)[0]}"
                sliced_graph["nodes"].append(caller_line)
                sliced_graph["nodes"].append(callee_line)
                sliced_graph["edges"].append((caller_line, callee_line))
                res, visited = slice_per_callee(
                    patch,
                    project,
                    cache_dir,
                    callgraph,
                    callee_results,
                    call_edge[1],
                    visited,
                    pre_post_projects,
                    level + 1,
                    is_pre,
                )
                if res is None:
                    continue
                sliced_graph["nodes"].extend(res["nodes"])
                sliced_graph["edges"].extend(res["edges"])
                sliced_graph["node_dicts"].update(res["node_dicts"])
        elif call_edge[1] == method_signature and call_edge[0] in patch.changed_methods:
            if call_edge[0] in visited:
                continue
            visited.add(call_edge[0])
            pre_slice_caller_results, post_slice_caller_results = slicing_single_method(
                patch, call_edge[0], pre_post_projects, cache_dir
            )
            if pre_slice_caller_results is None or post_slice_caller_results is None:
                continue
            if is_pre:
                (
                    pre_slice_caller_result_lines,
                    pre_slice_caller_result_weight,
                    pre_slice_caller_result_edges,
                    pre_callee_lines,
                    pre_callee_abs_lines,
                ) = (
                    pre_slice_caller_results[0],
                    pre_slice_caller_results[5],
                    pre_slice_caller_results[6],
                    pre_slice_caller_results[7],
                    pre_slice_caller_results[8],
                )
                caller_results = pre_slice_caller_results
            else:
                (
                    pre_slice_caller_result_lines,
                    pre_slice_caller_result_weight,
                    pre_slice_caller_result_edges,
                    pre_callee_lines,
                    pre_callee_abs_lines,
                ) = (
                    post_slice_caller_results[0],
                    post_slice_caller_results[5],
                    post_slice_caller_results[6],
                    post_slice_caller_results[7],
                    post_slice_caller_results[8],
                )
                caller_results = post_slice_caller_results
            for line in pre_slice_caller_result_lines:
                try:
                    sliced_graph["nodes"].append(f"{call_edge[0]}#{line}")
                except:
                    sliced_graph["nodes"] = [f"{call_edge[0]}#{line}"]
            for edge in pre_slice_caller_result_edges:
                try:
                    sliced_graph["edges"].append(
                        (f"{call_edge[0]}#{edge[0]}", f"{call_edge[0]}#{edge[1]}")
                    )
                except:
                    sliced_graph["edges"] = [
                        (f"{call_edge[0]}#{edge[0]}", f"{call_edge[0]}#{edge[1]}")
                    ]

            sliced_graph["node_dicts"] = {}
            for line in pre_slice_caller_result_lines:
                sliced_graph["node_dicts"][f"{call_edge[0]}#{line}"] = {}
                sliced_graph["node_dicts"][f"{call_edge[0]}#{line}"]["weight"] = (
                    pre_slice_caller_result_weight[line]
                )
                sliced_graph["node_dicts"][f"{call_edge[0]}#{line}"]["node_string"] = (
                    pre_callee_lines[line]
                )
                sliced_graph["node_dicts"][f"{call_edge[0]}#{line}"][
                    "abs_node_string"
                ] = pre_callee_abs_lines[line]
            res, visited = slice_per_callee(
                patch,
                project,
                cache_dir,
                callgraph,
                caller_results,
                call_edge[0],
                visited,
                pre_post_projects,
                level + 1,
                is_pre,
            )
            if res is None:
                continue
            sliced_graph["nodes"].extend(res["nodes"])
            sliced_graph["edges"].extend(res["edges"])
            sliced_graph["node_dicts"].update(res["node_dicts"])
        elif int(call_edge[2]) in slice_result_lines:
            callee_method: Method = project.get_method(call_edge[1])
            if callee_method is None:
                continue
            init_single_method_dir(callee_method, cache_dir)
            parser = ASTParser(lines[int(call_edge[2])], Language.CPP)
            nodes = parser.query_all("(call_expression)@name")
            for node in nodes:
                child = node.child_by_field_name("function")
                args = []
                if child is None or child.text is None:
                    continue
                if child.text.decode() == call_edge[1].split("#")[1]:
                    arguments_node = node.child_by_field_name("arguments")
                    if arguments_node is None:
                        continue
                    for arg in arguments_node.children:
                        if arg.type != "," and arg.type != "(" and arg.type != ")":
                            assert arg.text is not None
                            arg_value = arg.text.decode("utf-8")
                            args.append(arg_value)
                    if call_edge[2] in criteria_identifier:
                        slice_callee_results = (
                            callee_method.slice_by_header_line_vul_detect(
                                args, criteria_identifier[call_edge[2], True, True]
                            )
                        )
                    else:
                        slice_callee_results = (
                            callee_method.slice_by_header_line_vul_detect(
                                args, set(), True, True
                            )
                        )

                    (
                        slice_callee_results_lines,
                        slice_callee_results_weight,
                        slice_callee_results_edges,
                        slice_callee_lines,
                        slice_callee_results_abs_lines,
                    ) = (
                        slice_callee_results[0],
                        slice_callee_results[5],
                        slice_callee_results[6],
                        slice_callee_results[7],
                        slice_callee_results[8],
                    )
                    caller_line = f"{method_signature}#{call_edge[2]}"
                    callee_line = f"{callee_method.signature}#{sorted(slice_callee_results_lines)[0]}"
                    callee_codes = ""
                    abs_callee_codes = ""
                    for line in slice_callee_results_lines:
                        callee_codes += slice_callee_lines[line]
                        abs_callee_codes += slice_callee_results_abs_lines[line]
                    sliced_graph["edges"].append((caller_line, callee_line))
                    sliced_graph["nodes"].append(callee_line)
                    sliced_graph["nodes"].append(caller_line)
                    sliced_graph["node_dicts"][callee_line] = {}
                    sliced_graph["node_dicts"][callee_line]["weight"] = 1 / level
                    sliced_graph["node_dicts"][callee_line]["node_string"] = (
                        callee_codes
                    )
                    sliced_graph["node_dicts"][callee_line]["abs_node_string"] = (
                        abs_callee_codes
                    )

    return sliced_graph, visited


def slicing_multi_method(
    patch, pre_post_projects: tuple[Project, Project], cache_dir, callgraph
):
    visited = set()
    graph_clusters = []
    pre_project, post_project = pre_post_projects
    for method_signature in patch.changed_methods:
        graph_cluster = {}
        if method_signature == "ttssh2/ttxssh/ssh.c#handle_pty_failure":
            continue
        pre_sliced_graph = {}
        pre_sliced_graph["nodes"] = []
        pre_sliced_graph["edges"] = []
        pre_sliced_graph["node_dicts"] = {}

        post_sliced_graph = {}
        post_sliced_graph["nodes"] = []
        post_sliced_graph["edges"] = []
        post_sliced_graph["node_dicts"] = {}
        if method_signature in visited:
            continue
        visited.add(method_signature)
        pre_slice_results, post_slice_results = slicing_single_method(
            patch, method_signature, pre_post_projects, cache_dir
        )
        if pre_slice_results is None or post_slice_results is None:
            continue
        (
            pre_slice_result_lines,
            pre_slice_result_weight,
            pre_slice_result_edges,
            pre_lines,
            pre_abs_lines,
        ) = (
            pre_slice_results[0],
            pre_slice_results[5],
            pre_slice_results[6],
            pre_slice_results[7],
            pre_slice_results[8],
        )
        (
            post_slice_result_lines,
            post_slice_result_weight,
            post_slice_result_edges,
            post_lines,
            post_abs_lines,
        ) = (
            post_slice_results[0],
            post_slice_results[5],
            post_slice_results[6],
            post_slice_results[7],
            post_slice_results[8],
        )
        for line in pre_slice_result_lines:
            try:
                pre_sliced_graph["nodes"].append(f"{method_signature}#{line}")
            except:
                pre_sliced_graph["nodes"] = [f"{method_signature}#{line}"]
        for edge in pre_slice_result_edges:
            try:
                pre_sliced_graph["edges"].append(
                    (f"{method_signature}#{edge[0]}", f"{method_signature}#{edge[1]}")
                )
            except:
                pre_sliced_graph["edges"] = [
                    (f"{method_signature}#{edge[0]}", f"{method_signature}#{edge[1]}")
                ]

        for line in pre_slice_result_lines:
            pre_sliced_graph["node_dicts"][f"{method_signature}#{line}"] = {}
            pre_sliced_graph["node_dicts"][f"{method_signature}#{line}"]["weight"] = (
                pre_slice_result_weight[line]
            )
            pre_sliced_graph["node_dicts"][f"{method_signature}#{line}"][
                "node_string"
            ] = pre_lines[line]
            pre_sliced_graph["node_dicts"][f"{method_signature}#{line}"][
                "abs_node_string"
            ] = pre_abs_lines[line]
        res, visited = slice_per_callee(
            patch,
            pre_project,
            cache_dir,
            callgraph,
            pre_slice_results,
            method_signature,
            visited,
            pre_post_projects,
            1,
            True,
        )
        if res is None:
            continue
        pre_sliced_graph["nodes"].extend(res["nodes"])
        pre_sliced_graph["nodes"] = list(set(pre_sliced_graph["nodes"]))
        pre_sliced_graph["edges"].extend(res["edges"])
        pre_sliced_graph["edges"] = list(set(pre_sliced_graph["edges"]))
        pre_sliced_graph["node_dicts"].update(res["node_dicts"])

        id_graph_id_map = {}
        pre_sliced_graph_true = {}
        pre_sliced_graph_true["node_dicts"] = {}
        pre_sliced_graph_true["nodes"] = []
        pre_sliced_graph_true["edges"] = []
        id = 0
        for graph_id in pre_sliced_graph["nodes"]:
            id_graph_id_map[graph_id] = id
            pre_sliced_graph_true["nodes"].append(id)
            id += 1
        for edge in pre_sliced_graph["edges"]:
            pre_sliced_graph_true["edges"].append(
                (id_graph_id_map[edge[0]], id_graph_id_map[edge[1]])
            )

        for key in pre_sliced_graph["node_dicts"]:
            pre_sliced_graph_true["node_dicts"][id_graph_id_map[key]] = (
                pre_sliced_graph["node_dicts"][key]
            )
        graph_cluster["pre"] = pre_sliced_graph_true

        for line in post_slice_result_lines:
            try:
                post_sliced_graph["nodes"].append(f"{method_signature}#{line}")
            except:
                post_sliced_graph["nodes"] = [f"{method_signature}#{line}"]
        for edge in post_slice_result_edges:
            try:
                post_sliced_graph["edges"].append(
                    (f"{method_signature}#{edge[0]}", f"{method_signature}#{edge[1]}")
                )
            except:
                post_sliced_graph["edges"] = [
                    (f"{method_signature}#{edge[0]}", f"{method_signature}#{edge[1]}")
                ]

        for line in post_slice_result_lines:
            post_sliced_graph["node_dicts"][f"{method_signature}#{line}"] = {}
            post_sliced_graph["node_dicts"][f"{method_signature}#{line}"]["weight"] = (
                post_slice_result_weight[line]
            )
            post_sliced_graph["node_dicts"][f"{method_signature}#{line}"][
                "node_string"
            ] = post_lines[line]
            post_sliced_graph["node_dicts"][f"{method_signature}#{line}"][
                "abs_node_string"
            ] = post_abs_lines[line]
        res, visited = slice_per_callee(
            patch,
            post_project,
            cache_dir,
            callgraph,
            pre_slice_results,
            method_signature,
            visited,
            pre_post_projects,
            1,
            False,
        )
        if res is None:
            continue
        post_sliced_graph["nodes"].extend(res["nodes"])
        post_sliced_graph["edges"].extend(res["edges"])
        post_sliced_graph["node_dicts"].update(res["node_dicts"])

        post_sliced_graph["nodes"].extend(res["nodes"])
        post_sliced_graph["nodes"] = list(set(post_sliced_graph["nodes"]))
        post_sliced_graph["edges"].extend(res["edges"])
        post_sliced_graph["edges"] = list(set(post_sliced_graph["edges"]))
        post_sliced_graph["node_dicts"].update(res["node_dicts"])

        id_graph_id_map = {}
        post_sliced_graph_true = {}
        post_sliced_graph_true["node_dicts"] = {}
        post_sliced_graph_true["nodes"] = []
        post_sliced_graph_true["edges"] = []
        id = 0
        for graph_id in post_sliced_graph["nodes"]:
            id_graph_id_map[graph_id] = id
            post_sliced_graph_true["nodes"].append(id)
            id += 1
        for edge in post_sliced_graph["edges"]:
            post_sliced_graph_true["edges"].append(
                (id_graph_id_map[edge[0]], id_graph_id_map[edge[1]])
            )

        for key in post_sliced_graph["node_dicts"]:
            post_sliced_graph_true["node_dicts"][id_graph_id_map[key]] = (
                post_sliced_graph["node_dicts"][key]
            )

        graph_cluster["post"] = post_sliced_graph_true
        graph_clusters.append(graph_cluster)

    clusters = split_clusters(graph_clusters)
    fp = open(f"{cache_dir}/graph_cluster.json", "w")
    json.dump(clusters, fp, indent=4)
    fp.close()


def generate_call(worker_id, cveid, commit_id, repo_path):
    error_code = {}
    error_code[cveid] = {}
    try:
        language = Language.CPP
        try:
            patch = Patch(repo_path, commit_id, language)
        except Exception as e:
            os.system(f"git config --global --add safe.directory {repo_path}")
            try:
                patch = Patch(repo_path, commit_id, language)
            except Exception as e:
                error_code[cveid]["summary"] = "Patch generate error"
                error_code[cveid]["detail"] = e
                return error_code, worker_id
        try:
            pre_code_files = patch.pre_analysis_files
            post_code_files = patch.post_analysis_files
        except Exception as e:
            error_code[cveid]["summary"] = "patch project generate error"
            error_code[cveid]["detail"] = e
            return error_code, worker_id

        cache_dir = f"{CACHE_DIR}/{cveid}"
        if os.path.exists(f"{cache_dir}/pre_sliced_wfg.json") and os.path.exists(
            f"{cache_dir}/post_sliced_wfg.json"
        ):
            error_code[cveid]["summary"] = "already exists"
            error_code[cveid]["detail"] = "already exists"
            return error_code, worker_id
        pre_dir = os.path.join(cache_dir, "pre")
        post_dir = os.path.join(cache_dir, "post")
        create_code_tree(pre_code_files, pre_dir)
        create_code_tree(post_code_files, post_dir)
        try:
            export_joern_graph(
                pre_dir,
                post_dir,
                need_cdg=True,
                language=language,
                overwrite=True,
                multiprocess=True,
            )
        except Exception as e:
            error_code[cveid]["summary"] = "PDG ERROR"
            error_code[cveid]["detail"] = e
            return error_code, worker_id

        patch.pre_analysis_project.load_joern_graph(f"{pre_dir}/cpg", f"{pre_dir}/pdg")
        patch.post_analysis_project.load_joern_graph(
            f"{post_dir}/cpg", pdg_dir=f"{post_dir}/pdg"
        )

        pre_post_projects = (patch.pre_analysis_project, patch.post_analysis_project)

        try:
            callgraph = get_pre_post_call(patch, pre_post_projects, cache_dir)
        except Exception as e:
            error_code[cveid]["summary"] = "CALL GRAPH ERROR"
            error_code[cveid]["detail"] = e
            return error_code, worker_id

        try:
            if len(patch.changed_methods) == 1:
                pre_slice_results, post_slice_results = slicing_single_method(
                    patch, list(patch.changed_methods)[0], pre_post_projects, cache_dir
                )
                if pre_slice_results is None or post_slice_results is None:
                    error_code[cveid]["summary"] = "single method failed"
                    error_code[cveid]["detail"] = "single method failed"
                    return error_code, worker_id
                (
                    pre_slice_result_lines,
                    pre_slice_result_weight,
                    pre_slice_result_edges,
                    pre_lines,
                    pre_abs_lines,
                ) = (
                    pre_slice_results[0],
                    pre_slice_results[5],
                    pre_slice_results[6],
                    pre_slice_results[7],
                    pre_slice_results[8],
                )
                (
                    post_slice_result_lines,
                    post_slice_result_weight,
                    post_slice_result_edges,
                    post_lines,
                    post_abs_lines,
                ) = (
                    post_slice_results[0],
                    post_slice_results[5],
                    post_slice_results[6],
                    post_slice_results[7],
                    post_slice_results[8],
                )
                pre_sliced_graph = {}
                pre_sliced_graph["nodes"] = list(pre_slice_result_lines)
                pre_sliced_graph["edges"] = list(pre_slice_result_edges)
                pre_sliced_graph["node_dicts"] = {}
                for line in pre_slice_result_lines:
                    pre_sliced_graph["node_dicts"][line] = {}
                    pre_sliced_graph["node_dicts"][line]["weight"] = (
                        pre_slice_result_weight[line]
                    )
                    pre_sliced_graph["node_dicts"][line]["node_string"] = pre_lines[
                        line
                    ]
                    pre_sliced_graph["node_dicts"][line]["abs_node_string"] = (
                        pre_abs_lines[line]
                    )
                post_sliced_graph = {}
                post_sliced_graph["nodes"] = list(post_slice_result_lines)
                post_sliced_graph["edges"] = list(post_slice_result_edges)
                post_sliced_graph["node_dicts"] = {}
                for line in post_slice_result_lines:
                    post_sliced_graph["node_dicts"][line] = {}
                    post_sliced_graph["node_dicts"][line]["weight"] = (
                        post_slice_result_weight[line]
                    )
                    post_sliced_graph["node_dicts"][line]["node_string"] = post_lines[
                        line
                    ]
                    post_sliced_graph["node_dicts"][line]["abs_node_string"] = (
                        post_abs_lines[line]
                    )

                fp = open(f"{cache_dir}/pre_sliced_wfg.json", "w")
                json.dump(pre_sliced_graph, fp, indent=4)
                fp.close()
                convert_to_dot(
                    f"{cache_dir}/pre_sliced_wfg.json",
                    f"{cache_dir}/pre_sliced_wfg.dot",
                )

                fp = open(f"{cache_dir}/post_sliced_wfg.json", "w")
                json.dump(post_sliced_graph, fp, indent=4)
                fp.close()
                graph_cluster = {}
                graph_cluster["pre"] = pre_sliced_graph
                graph_cluster["post"] = post_sliced_graph
                graph_clusters = [graph_cluster]
                clusters = split_clusters(graph_clusters)
                fp = open(f"{cache_dir}/graph_cluster.json", "w")
                json.dump(clusters, fp, indent=4)
                fp.close()
            else:
                slicing_multi_method(patch, pre_post_projects, cache_dir, callgraph)
        except Exception as e:
            error_code[cveid]["summary"] = "slicing error"
            error_code[cveid]["detail"] = e
            return error_code, worker_id
    except Exception as e:
        error_code[cveid]["summary"] = "overall failed"
        error_code[cveid]["detail"] = e
        return error_code, worker_id

    error_code[cveid]["summary"] = "SUCCESS"
    error_code[cveid]["detail"] = "SUCCESS"
    return error_code, worker_id


def generate_call_java(worker_id, cveid, commit_id, repo_path):
    error_code = {}
    error_code[cveid] = {}
    try:
        language = Language.JAVA
        try:
            patch = Patch(repo_path, commit_id, language)
        except Exception as e:
            os.system(f"git config --global --add safe.directory {repo_path}")
            try:
                patch = Patch(repo_path, commit_id, language)
            except Exception as e:
                error_code[cveid]["summary"] = "Patch generate error"
                error_code[cveid]["detail"] = e
                return error_code, worker_id
        try:
            pre_code_files = patch.pre_analysis_files
            post_code_files = patch.post_analysis_files
        except Exception as e:
            error_code[cveid]["summary"] = "patch project generate error"
            error_code[cveid]["detail"] = e
            return error_code, worker_id

        cache_dir = f"{CACHE_DIR}/{cveid}"
        if os.path.exists(f"{cache_dir}/pre_sliced_wfg.json") and os.path.exists(
            f"{cache_dir}/post_sliced_wfg.json"
        ):
            error_code[cveid]["summary"] = "already exists"
            error_code[cveid]["detail"] = "already exists"
            return error_code, worker_id
        pre_dir = os.path.join(cache_dir, "pre")
        post_dir = os.path.join(cache_dir, "post")
        create_code_tree(pre_code_files, pre_dir)
        create_code_tree(post_code_files, post_dir)
        try:
            export_joern_graph(
                pre_dir,
                post_dir,
                need_cdg=True,
                language=language,
                overwrite=True,
                multiprocess=True,
            )
        except Exception as e:
            error_code[cveid]["summary"] = "PDG ERROR"
            error_code[cveid]["detail"] = e
            return error_code, worker_id

        patch.pre_analysis_project.load_joern_graph(f"{pre_dir}/cpg", f"{pre_dir}/pdg")
        patch.post_analysis_project.load_joern_graph(
            f"{post_dir}/cpg", pdg_dir=f"{post_dir}/pdg"
        )

        pre_post_projects = (patch.pre_analysis_project, patch.post_analysis_project)

        try:
            callgraph = get_pre_post_call(patch, pre_post_projects, cache_dir)
        except Exception as e:
            error_code[cveid]["summary"] = "CALL GRAPH ERROR"
            error_code[cveid]["detail"] = e
            return error_code, worker_id

        try:
            if len(patch.changed_methods) == 1:
                pre_slice_results, post_slice_results = slicing_single_method(
                    patch, list(patch.changed_methods)[0], pre_post_projects, cache_dir
                )
                if pre_slice_results is None or post_slice_results is None:
                    error_code[cveid]["summary"] = "single method failed"
                    error_code[cveid]["detail"] = "single method failed"
                    return error_code, worker_id
                (
                    pre_slice_result_lines,
                    pre_slice_result_weight,
                    pre_slice_result_edges,
                    pre_lines,
                    pre_abs_lines,
                ) = (
                    pre_slice_results[0],
                    pre_slice_results[5],
                    pre_slice_results[6],
                    pre_slice_results[7],
                    pre_slice_results[8],
                )
                (
                    post_slice_result_lines,
                    post_slice_result_weight,
                    post_slice_result_edges,
                    post_lines,
                    post_abs_lines,
                ) = (
                    post_slice_results[0],
                    post_slice_results[5],
                    post_slice_results[6],
                    post_slice_results[7],
                    post_slice_results[8],
                )
                pre_sliced_graph = {}
                pre_sliced_graph["nodes"] = list(pre_slice_result_lines)
                pre_sliced_graph["edges"] = list(pre_slice_result_edges)
                pre_sliced_graph["node_dicts"] = {}
                for line in pre_slice_result_lines:
                    pre_sliced_graph["node_dicts"][line] = {}
                    pre_sliced_graph["node_dicts"][line]["weight"] = (
                        pre_slice_result_weight[line]
                    )
                    pre_sliced_graph["node_dicts"][line]["node_string"] = pre_lines[
                        line
                    ]
                    pre_sliced_graph["node_dicts"][line]["abs_node_string"] = (
                        pre_abs_lines[line]
                    )
                post_sliced_graph = {}
                post_sliced_graph["nodes"] = list(post_slice_result_lines)
                post_sliced_graph["edges"] = list(post_slice_result_edges)
                post_sliced_graph["node_dicts"] = {}
                for line in post_slice_result_lines:
                    post_sliced_graph["node_dicts"][line] = {}
                    post_sliced_graph["node_dicts"][line]["weight"] = (
                        post_slice_result_weight[line]
                    )
                    post_sliced_graph["node_dicts"][line]["node_string"] = post_lines[
                        line
                    ]
                    post_sliced_graph["node_dicts"][line]["abs_node_string"] = (
                        post_abs_lines[line]
                    )

                fp = open(f"{cache_dir}/pre_sliced_wfg.json", "w")
                json.dump(pre_sliced_graph, fp, indent=4)
                fp.close()
                convert_to_dot(
                    f"{cache_dir}/pre_sliced_wfg.json",
                    f"{cache_dir}/pre_sliced_wfg.dot",
                )

                fp = open(f"{cache_dir}/post_sliced_wfg.json", "w")
                json.dump(post_sliced_graph, fp, indent=4)
                fp.close()
                graph_cluster = {}
                graph_cluster["pre"] = pre_sliced_graph
                graph_cluster["post"] = post_sliced_graph
                graph_clusters = [graph_cluster]
                clusters = split_clusters(graph_clusters)
                fp = open(f"{cache_dir}/graph_cluster.json", "w")
                json.dump(clusters, fp, indent=4)
                fp.close()
            else:
                slicing_multi_method(patch, pre_post_projects, cache_dir, callgraph)
        except Exception as e:
            error_code[cveid]["summary"] = "slicing error"
            error_code[cveid]["detail"] = e
            return error_code, worker_id
    except Exception as e:
        error_code[cveid]["summary"] = "overall failed"
        error_code[cveid]["detail"] = e
        return error_code, worker_id

    error_code[cveid]["summary"] = "SUCCESS"
    error_code[cveid]["detail"] = "SUCCESS"
    return error_code, worker_id


if __name__ == "__main__":
    joern.set_joern_env(JOERN_PATH)

    cveid = sys.argv[1]
    commit_id = sys.argv[2]
    repo_path = sys.argv[3]
    generate_call(cveid, cveid, commit_id, repo_path)
