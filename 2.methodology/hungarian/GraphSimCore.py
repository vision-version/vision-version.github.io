import math
import sys
from ctypes import *

import numpy

sys.path.append("../")
import json

import cpu_heater
import networkx as nx
import torch

import hungarian
from sim_model.SimilarityService import SimilarityService

USE_WEIGHT = True
device = torch.device("cuda") if torch.cuda.is_available() else torch.device("cpu")

DEBUG = False
global cachedUnixCoderSim
cachedUnixCoderSim = {}


def node_col_work_fn(
    matrix_len, row_id, g1, g1_indexs, g2, g2_indexs, column_id, similarity_service=None
):
    src = obtain_node_feature(g1, g1_indexs, row_id)
    dst = obtain_node_feature(g2, g2_indexs, column_id)
    cost = cal_nodecost(src, dst, similarity_service)
    if USE_WEIGHT:
        src_weight = obtain_node_weight(g1, g1_indexs, row_id)
        dst_weight = obtain_node_weight(g2, g2_indexs, column_id)
        cost_weight = (cost) * (1 / src_weight * 1 / dst_weight) / 2
        cost = cost_weight

    return cost


def node_row_work_fn(
    matrix_len, row_id, g1, g1_indexs, g2, g2_indexs, similarity_service=None
):
    worker_list = []
    for column_id in range(matrix_len):
        worker_list.append(
            (
                matrix_len,
                row_id,
                g1,
                g1_indexs,
                g2,
                g2_indexs,
                column_id,
                similarity_service,
            )
        )

    costs = cpu_heater.multithreads(
        node_col_work_fn, worker_list, max_workers=8, show_progress=False
    )

    return costs


def graph_node_distance(g1, g2):
    MAX_VALUE = 10000
    cost_matrix = []
    g1_indexs = list(g1.nodes())
    g2_indexs = list(g2.nodes())

    matrix_len = max(len(g1), len(g2))
    min_len = min(len(g1), len(g2))
    if min_len == 0:
        return MAX_VALUE

    worker_list = []

    similarity_service = SimilarityService()
    for row_id in range(matrix_len):
        worker_list.append(
            (matrix_len, row_id, g1, g1_indexs, g2, g2_indexs, similarity_service)
        )

    cost_matrix = cpu_heater.multithreads(
        node_row_work_fn, worker_list, max_workers=8, show_progress=False
    )
    if len(cost_matrix) == 0:
        return MAX_VALUE
    cost_matrix = torch.tensor(cost_matrix, device=device)

    mapping = hungarian.hungarian_algorithm(cost_matrix)
    distance = caldistance(mapping.cpu().numpy(), cost_matrix.tolist())
    return distance


def col_work_fn(
    g1, g1_indexs, g2, g2_indexs, row_id, column_id, similarity_service=None
):
    src = obtain_edge_feature(g1, g1_indexs, row_id)
    dst = obtain_edge_feature(g2, g2_indexs, column_id)

    if src is None or dst is None:
        cost = 0
    else:
        cost = cal_edgecost(src, dst, similarity_service)

    if USE_WEIGHT:
        src_weight = obtain_edge_weight(g1, g1_indexs, row_id)
        dst_weight = obtain_edge_weight(g2, g2_indexs, column_id)
        cost_weight = (cost) * (src_weight + dst_weight) / 2
        cost = cost_weight
    return cost


def row_work_fn(
    row_id, matrix_len, g1, g1_indexs, g2, g2_indexs, similarity_service=None
):
    worker_list = []
    for column_id in range(matrix_len):
        worker_list.append(
            (g1, g1_indexs, g2, g2_indexs, row_id, column_id, similarity_service)
        )

    costs = cpu_heater.multithreads(
        col_work_fn, worker_list, max_workers=8, show_progress=False
    )

    return costs


def graph_edge_distance(g1, g2):
    cost_matrix = []
    g1_indexs = list(g1.edges())
    g2_indexs = list(g2.edges())
    matrix_len = max(len(g1), len(g2))
    min_len = min(len(g1), len(g2))
    if min_len == 0:
        return 0

    worker_list = []
    similarity_service = SimilarityService()
    for row_id in range(matrix_len):
        worker_list.append(
            (row_id, matrix_len, g1, g1_indexs, g2, g2_indexs, similarity_service)
        )

    cost_matrix = cpu_heater.multithreads(
        row_work_fn, worker_list, max_workers=8, show_progress=False
    )
    if len(cost_matrix) == 0:
        return -1
    cost_matrix = torch.tensor(cost_matrix, device=device)
    mapping = hungarian.hungarian_algorithm(cost_matrix)
    distance = caldistance(mapping.cpu().numpy(), cost_matrix.tolist())
    return distance


def cal_edgecost(edge1, edge2, similarity_service=None):
    src_cost = cal_nodecost(edge1[0], edge2[0], similarity_service)
    dst_cost = cal_nodecost(edge1[1], edge2[1], similarity_service)
    return (src_cost + dst_cost) / 2


def cal_nodecost(node1_vec, node2_vec, similarity_service=None):
    if node1_vec == node2_vec:
        return 0
    sim = node_dl_sim(node1_vec, node2_vec, similarity_service)
    val = 1 - sim
    return val


def obtain_edge_weight(g, g_indexes, edge_id):
    g_len = len(g_indexes)
    if edge_id <= (g_len - 1):
        edge = g_indexes[edge_id]
        if "weight" in g.nodes[edge[0]]:
            src = g.nodes[edge[0]]["weight"]
        else:
            src = 0
        if "weight" in g.nodes[edge[1]]:
            dst = g.nodes[edge[1]]["weight"]
        else:
            dst = 0
        return max(src, dst)
    else:
        return 0


def obtain_edge_feature(g, g_indexes, edge_id):
    g_len = len(g_indexes)
    if edge_id <= (g_len - 1):
        edge = g_indexes[edge_id]
        if "abs_node_string" in g.nodes[edge[0]]:
            src = g.nodes[edge[0]]["abs_node_string"]
        if "abs_node_string" in g.nodes[edge[1]]:
            dst = g.nodes[edge[1]]["abs_node_string"]
        return (src, dst)
    else:
        return None


def obtain_node_weight(g, g_indexes, node_id):
    if not USE_WEIGHT:
        return 1.0
    g_len = len(g_indexes)
    if node_id <= (g_len - 1):
        node = g_indexes[node_id]
        return g.nodes[node]["weight"]
    else:
        return 1.0


def obtain_node_feature(g, g_indexes, node_id):
    g_len = len(g_indexes)
    if node_id <= (g_len - 1):
        node = g_indexes[node_id]
        return g.nodes[node]["abs_node_string"]


def obtain_zero_cnt(g):
    g_indexes = list(g.nodes())
    zero_node_cnt = 0
    for index in g_indexes:
        node_v = g.nodes[index]["blines"]
        if len(node_v) == 0:
            zero_node_cnt += 1
    return zero_node_cnt


def caldistance(mapping, cost_matrix):
    cost = 0
    for i in range(min(len(cost_matrix), len(mapping[0]))):
        cost += cost_matrix[i][int(mapping[0][i])]
    return cost


def node_cos_sim(vector1, vector2):
    dot_product = 0.0
    normA = 0.0
    normB = 0.0
    for a, b in zip(vector1, vector2):
        dot_product += a * b
        normA += a**2
        normB += b**2
    if normA == 0.0 or normB == 0.0:
        return 0
    else:
        return dot_product / ((normA * normB) ** 0.5)


def node_ecul_sim(v1, v2):
    v1 = numpy.array(v1)
    v2 = numpy.array(v2)
    v1_norm = numpy.linalg.norm(v1)
    v2_norm = numpy.linalg.norm(v2)
    if v1_norm == 0 or v2_norm == 0:
        return 0
    dis = numpy.linalg.norm(v1 - v2)
    return 1.0 - float(dis) / (v1_norm * v2_norm)


def node_dl_sim(v1, v2, similarity_service=None):
    if v1 == "" or v2 == "":
        return 0
    global cachedUnixCoderSim
    if v1 not in cachedUnixCoderSim:
        cachedUnixCoderSim[v1] = {}
    if v2 not in cachedUnixCoderSim[v1]:
        cachedUnixCoderSim[v1][v2] = similarity_service.calculate_similarity(v1, v2)
        return cachedUnixCoderSim[v1][v2]

    else:
        return cachedUnixCoderSim[v1][v2]


def weighted_similarity(g_node1, g_node2, node_dis, edge_dis):
    feature_dis = (node_dis + math.sqrt(edge_dis)) / (g_node1 + g_node2)
    size_dis = abs(float(g_node1 - g_node2)) / (g_node1 + g_node2)

    alpha = 1.15
    beta = 0.05
    gamma = 0.05
    dis = feature_dis * alpha + size_dis * beta
    sim = 1 - dis
    return sim if sim > 0 else 0


def compare_wfg(subcfg1, subcfg2):
    cfg_node_cnt1 = len(subcfg1.nodes())
    cfg_node_cnt2 = len(subcfg2.nodes())
    if cfg_node_cnt1 == 0 or cfg_node_cnt2 == 0:
        return 0
    min_cnt = min([cfg_node_cnt1, cfg_node_cnt2])
    max_cnt = max([cfg_node_cnt1, cfg_node_cnt2])

    node_dis = graph_node_distance(subcfg1, subcfg2)

    edge_dis = graph_edge_distance(subcfg1, subcfg2)
    print("Node-distance:", node_dis)
    print("Edge-distance:", edge_dis)
    print("Edge-distance:", edge_dis)
    sim = weighted_similarity(cfg_node_cnt1, cfg_node_cnt2, node_dis, edge_dis)

    return round(sim, 3)


def load_wfg_from_dict(wfg_dict):
    id = 0
    graph_id_map = {}
    true_wfg_dict = {}
    true_wfg_dict["nodes"] = []
    true_wfg_dict["edges"] = []
    true_wfg_dict["node_dicts"] = {}
    for graph_id in wfg_dict["nodes"]:
        if (
            graph_id not in wfg_dict["node_dicts"]
            and str(graph_id) not in wfg_dict["node_dicts"]
        ):
            continue
        graph_id_map[graph_id] = id
        true_wfg_dict["nodes"].append(id)
        id += 1
    for edge in wfg_dict["edges"]:
        if (
            edge[0] not in wfg_dict["node_dicts"]
            and str(edge[0]) not in wfg_dict["node_dicts"]
        ) or (
            edge[1] not in wfg_dict["node_dicts"]
            and str(edge[1]) not in wfg_dict["node_dicts"]
        ):
            continue

        true_wfg_dict["edges"].append((graph_id_map[edge[0]], graph_id_map[edge[1]]))

    for key in wfg_dict["node_dicts"]:
        true_wfg_dict["node_dicts"][graph_id_map[int(key)]] = wfg_dict["node_dicts"][
            key
        ]

    wfg = dict2graph(true_wfg_dict)
    return wfg


def load_wfg(wfg_file):
    with open(wfg_file, "r") as fr:
        wfg_dict = json.load(fr)
    id = 0
    graph_id_map = {}
    true_wfg_dict = {}
    true_wfg_dict["nodes"] = []
    true_wfg_dict["edges"] = []
    true_wfg_dict["node_dicts"] = {}

    if min(wfg_dict["nodes"]) != 0:
        for graph_id in wfg_dict["nodes"]:
            graph_id_map[graph_id] = id
            true_wfg_dict["nodes"].append(id)
            id += 1
        for edge in wfg_dict["edges"]:
            true_wfg_dict["edges"].append(
                (graph_id_map[edge[0]], graph_id_map[edge[1]])
            )

        for key in wfg_dict["node_dicts"]:
            true_wfg_dict["node_dicts"][graph_id_map[int(key)]] = wfg_dict[
                "node_dicts"
            ][key]
    else:
        true_wfg_dict = wfg_dict

    wfg = dict2graph(true_wfg_dict)
    return wfg


def dict2graph(wfg_dict):
    graph = nx.DiGraph()
    graph_dict = wfg_dict
    nodes = graph_dict["nodes"]
    for index, edge in enumerate(graph_dict["edges"]):
        graph_dict["edges"][index] = tuple(edge)
    for index, edge in enumerate(graph_dict["edges"]):
        if (
            edge[0] not in graph_dict["node_dicts"]
            and str(edge[0]) not in graph_dict["node_dicts"]
        ):
            graph_dict["edges"].remove((edge[0], edge[1]))
            if edge[0] in nodes:
                nodes.remove(edge[0])
            if (
                edge[1] not in graph_dict["node_dicts"]
                and str(edge[1]) not in graph_dict["node_dicts"]
                and edge[1] in nodes
            ):
                nodes.remove(edge[1])

        elif (
            edge[1] not in graph_dict["node_dicts"]
            and str(edge[1]) not in graph_dict["node_dicts"]
        ):
            if edge[1] in nodes:
                nodes.remove(edge[1])
            graph_dict["edges"].remove((edge[0], edge[1]))
            if (
                edge[0] not in graph_dict["node_dicts"]
                and str(edge[0]) not in graph_dict["node_dicts"]
                and edge[0] in nodes
            ):
                nodes.remove(edge[0])

    edges = graph_dict["edges"]
    node_dict = graph_dict["node_dicts"]

    graph.add_nodes_from(nodes)
    graph.add_edges_from(edges)
    for node_id in nodes:
        if node_id not in node_dict and str(node_id) in node_dict:
            graph.nodes[node_id].update(node_dict[str(node_id)])
        elif node_id in node_dict:
            graph.nodes[node_id].update(node_dict[node_id])
    return graph


def simScore(githubGraph, jarGraph, cachedunixCoderSim):
    global cachedUnixCoderSim

    cachedUnixCoderSim = cachedunixCoderSim
    wfg1 = load_wfg(githubGraph)
    wfg2 = load_wfg(jarGraph)

    if wfg1 == None or wfg2 == None:
        raise ValueError
    sim = compare_wfg(wfg1, wfg2)
    print("Similarity of two WFGs: ", sim)
    return sim, cachedUnixCoderSim


if __name__ == "__main__":
    pass
