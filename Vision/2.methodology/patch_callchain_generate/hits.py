import json
import os
import networkx as nx




def hits_algorithm(nodes, edges, max_iterations=100, convergence_threshold=1e-6):
    '''

    '''

    nodes, edges = init(nodes, edges)
    nodes_lst = [node["id"] for node in nodes]
    edges_lst = [(edge["source"], edge["target"]) for edge in edges]
    nodes_id_index_map = {node["id"]: node["index"] for node in nodes}
    # nodes_id_color_map= {node["id"]: node["color"] for node in nodes}
    # print(nodes_lst)
    # print(edges_lst)
    # print(nodes_id_index_map)
    authority = {node["id"]: node["auth"] for node in nodes}
    hub = {node["id"]: node["hub"] for node in nodes}
    # print(authority)
    # print(hub)
    node_source = []
    node_sink = []
    
    for node in nodes_lst:
        source_flag = True
        sink_flag = True
        for edge_tuple in edges_lst:
            if node == edge_tuple[0]: sink_flag = False
            if node == edge_tuple[1]: source_flag = False
        if source_flag: node_source.append(node)
        if sink_flag: node_sink.append(node)
    for _ in range(max_iterations):
        prev_authority = authority.copy()
        prev_hub = hub.copy()


       
        for node in nodes_lst:
            source_flag = True
            for neighbor in nodes_lst:
                if (neighbor, node) in edges_lst:
                    source_flag = False
        
                    # if nodes_id_color_map[neighbor] == "grey":
                    #     authority[node] += 0.5 * prev_hub[neighbor]
                    # elif node in node_sink:
                    #     authority[node] += 3 * prev_hub[neighbor]
                    # else:
                    #     authority[node] += prev_hub[neighbor]
                    authority[node] += prev_hub[neighbor]

            if source_flag: 
                authority[node] = authority[node] * 2
                

        for node in nodes_lst:
            for neighbor in nodes_lst:
                if (node, neighbor) in edges_lst:
                    # if nodes_id_color_map[neighbor] == "grey":
                    #     hub[node] += 0.5 * prev_authority[neighbor]
                    # elif node in node_source:
                    #     hub[node] += 3 * prev_authority[neighbor]
                    # else:
                    #     hub[node] += prev_authority[neighbor]
                    hub[node] += prev_authority[neighbor]


        norm = max(max(authority.values()), max(hub.values()))
        for node in nodes_lst:
            authority[node] /= norm
            hub[node] /= norm


        authority_changes = sum(abs(authority[node] - prev_authority[node]) for node in nodes_lst)
        hub_changes = sum(abs(hub[node] - prev_hub[node]) for node in nodes_lst)

        if authority_changes < convergence_threshold and hub_changes < convergence_threshold:
            break
    
    score_sum = {}
    for node_index, value in authority.items():
        # print(nodes_id_index_map[node_index], ": ", value)
        score_sum[node_index] = value + hub[node_index]

    # print("hub:")
    # for node_index, value in hub.items():
    #     print(nodes_id_index_map[node_index], ": ", value)
    score_sum = dict(sorted(score_sum.items(), key=lambda item: item[1], reverse=True))
    return authority, hub, score_sum


def init(nodes, edges):
    for nodes_index, node in enumerate(nodes):

        # nodes[nodes_index]["auth"] = 2 if node["color"] != "grey" else 1

        indegree_flag = False
        outdegree_flag= False
        for edges_index, edge in enumerate(edges):
            if edge["source"] == node["id"]:
                outdegree_flag= True
            if edge["target"] == node["id"]:
                indegree_flag = True
 
        if not outdegree_flag:
            nodes[nodes_index]["auth"] = 2
        else:
            nodes[nodes_index]["auth"] = 1

        if not indegree_flag:
            nodes[nodes_index]["hub"] = 2
        else:
            nodes[nodes_index]["hub"] = 1
    return nodes, edges



if __name__ == "__main__":

    with open("2.methodology/patch_callchain_generate/CGs/CVE-2014-0050_new.json", "r") as fr:
        raw_graph = json.load(fr)
    nodes = raw_graph["nodes"]
    edges = raw_graph["edges"]

    nodes, edges = init(nodes, edges)
    authority, hub, score_sum = hits_algorithm(nodes, edges)
    print("authority: ")
    print(json.dumps(authority, indent=4))
    print("\nhub:")
    print(json.dumps(hub, indent=4))
    print("\nsum: ")
    print(json.dumps(score_sum, indent=4))
