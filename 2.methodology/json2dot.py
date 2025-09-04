import json

import networkx as nx


def convert_to_dot(input_path: str, output_path):
    fp = open(input_path)
    json_data = json.load(fp)
    fp.close()
    G = nx.DiGraph()

    for node_id in json_data["nodes"]:
        node_info = json_data["node_dicts"].get(str(node_id), {})
        label = node_info.get("node_string", str(node_id)).strip()
        G.add_node(node_id, label=label)

    for edge in json_data["edges"]:
        G.add_edge(edge[0], edge[1])

    nx.nx_agraph.write_dot(G, output_path)
