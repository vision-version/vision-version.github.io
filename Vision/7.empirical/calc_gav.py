import json

import requests
from tqdm import tqdm

with open("cve_ga.json") as f:
    data = json.load(f)

cve_gav = {}
for cveid, ga in tqdm(data.items()):
    g = ga.split(":")[0]
    a = ga.split(":")[1]
    query_url = f"https://search.maven.org/solrsearch/select?q=g:{g}+AND+a:{a}&core=gav&rows=20&wt=json"
    resp = requests.get(query_url).content.decode()
    meta = json.loads(resp)
    v = []
    for ga in meta["response"]["docs"]:
        v.append(ga["v"])
    cve_gav[cveid] = v
with open("cve_gav.json", "w") as f:
    json.dump(cve_gav, f, indent=4)
