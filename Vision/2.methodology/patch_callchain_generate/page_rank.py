import json
import os
import networkx as nx

def pagerank_algorithm(nodes, edges, max_iterations=100, convergence_threshold=1e-6):

    nodes_lst = [node["id"] for node in nodes]
    edges_lst = [(edge["source"], edge["target"]) for edge in edges]


    graph = nx.DiGraph()


    graph.add_nodes_from(nodes_lst)
    graph.add_edges_from(edges_lst)


    pagerank_scores = nx.pagerank(graph)


    for nodeid, score in pagerank_scores.items():
        for node in nodes:
            if node["id"] == nodeid: 
                print(node["index"], f": Pagerank Score = {score}")
            
if __name__ == "__main__":

    with open("2.methodology/patch_callchain_generate/CGs/CVE-2021-43797_new.json", "r") as fr:
        raw_graph = json.load(fr)
    nodes = raw_graph["nodes"]
    edges = raw_graph["edges"]

    pagerank_algorithm(nodes, edges)