import json
import networkx as nx
import matplotlib.pyplot as plt


def plot_cg(graph_data, cveid, status):
    nodes = graph_data['nodes']
    edges = graph_data['edges']


    G = nx.DiGraph()


    for node_data in nodes:
        # G.add_node(node_data['id'], name=node_data['name'])
        G.add_node(node_data['id'], name=node_data['index'])

    for edge_data in edges:
        G.add_edge(edge_data['source'], edge_data['target'], weight=edge_data['weight'])


    node_colors = [node['color'] for node in nodes]


    pos = nx.spring_layout(G, k = 1.0)
    edge_labels = {(u, v): d['weight'] for u, v, d in G.edges(data=True)}


    nx.draw(G, pos, with_labels=False, node_color=node_colors)
    nx.draw_networkx_labels(G, pos, labels={node: G.nodes[node]['name'] for node in G.nodes()})
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)
    plt.savefig(f'./CGs/{cveid}_{status}_graph_image.png')
    plt.close()  



if __name__ == '__main__':
    plot_cg()
    # graph_data = {
    #   "nodes": [
    #     {"id": "A", "name": "Node A", "color": "red"},
    #     {"id": "B", "name": "Node B", "color": "red"},
    #     {"id": "C", "name": "Node C", "color": "grey"},
    #     {"id": "D", "name": "Node D", "color": "red"},
    #     {"id": "E", "name": "Node E", "color": "grey"},
    #     {"id": "F", "name": "Node F", "color": "green"}
    #   ],
    #   "edges": [
    #     {"source": "A", "target": "B", "weight": 3},
    #     {"source": "B", "target": "C", "weight": 5},
    #     {"source": "C", "target": "D", "weight": 2},
    #     {"source": "D", "target": "A", "weight": 4},
    #     {"source": "D", "target": "E", "weight": 1}
    #   ]
    # }