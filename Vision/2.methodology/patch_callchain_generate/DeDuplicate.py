import json

with open("2.methodology/joern-cli/edges_test.json", 'r') as edge_f :
    edges = json.load(edge_f)

for d in edges:
    d = dict(tuple(sorted(d.items())))
    print(json.dumps(d, indent=4))

edges_set = {tuple(sorted((k, tuple(v) if isinstance(v, list) else v) for k, v in d.items())) for d in edges}

