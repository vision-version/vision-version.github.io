import json
from collections import defaultdict


def build_graph(nodes, edges):
    graph = defaultdict(list)
    for edge in edges:
        u, v = edge
        graph[u].append(v)
        graph[v].append(u)
    return graph


def find_connected_components(graph, nodes):
    visited = set()
    connected_components = []

    for node in nodes:
        if node not in visited:
            component = []
            stack = [node]
            while stack:
                current = stack.pop()
                if current not in visited:
                    visited.add(current)
                    component.append(current)
                    stack.extend(graph[current])
            connected_components.append(component)
    return connected_components


def split_clusters(graph):
    clusters = {}
    clusters["pre"] = []
    clusters["post"] = []

    for cluster in graph:
        pre_graph = cluster["pre"]
        nodes = cluster["pre"]["nodes"]
        edges = cluster["pre"]["edges"]
        node_edge = build_graph(nodes, edges)
        connected_components = find_connected_components(node_edge, nodes)
        for connected_component in connected_components:
            pre_cluster = {}
            pre_cluster["nodes"] = []
            pre_cluster["edges"] = []
            pre_cluster["node_dicts"] = {}

            for node in connected_component:
                if (
                    node not in pre_graph["node_dicts"].keys()
                    and str(node) not in pre_graph["node_dicts"].keys()
                ):
                    continue
                pre_cluster["nodes"].append(node)
                for edge in edges:
                    if edge[0] == node:
                        pre_cluster["edges"].append(edge)
                if str(node) in pre_graph["node_dicts"].keys():
                    pre_cluster["node_dicts"][node] = pre_graph["node_dicts"][str(node)]
                else:
                    pre_cluster["node_dicts"][node] = pre_graph["node_dicts"][node]

            clusters["pre"].append(pre_cluster)

        post_graph = cluster["post"]
        nodes = cluster["post"]["nodes"]
        edges = cluster["post"]["edges"]
        node_edge = build_graph(nodes, edges)
        connected_components = find_connected_components(node_edge, nodes)
        for connected_component in connected_components:
            post_cluster = {}
            post_cluster["nodes"] = []
            post_cluster["edges"] = []
            post_cluster["node_dicts"] = {}

            for node in connected_component:
                if (
                    node not in post_graph["node_dicts"].keys()
                    and str(node) not in post_graph["node_dicts"].keys()
                ):
                    continue
                post_cluster["nodes"].append(node)
                for edge in edges:
                    if edge[0] == node:
                        post_cluster["edges"].append(edge)
                if str(node) in post_graph["node_dicts"].keys():
                    post_cluster["node_dicts"][node] = post_graph["node_dicts"][str(node)]
                else:
                    post_cluster["node_dicts"][node] = post_graph["node_dicts"][node]

            clusters["post"].append(post_cluster)

    return clusters


if __name__ == "__main__":
    pass
