import json
from datetime import datetime

import requests
from tqdm import tqdm

data_path = "trueresult original.json"
info_path = "versions.json"

with open(data_path) as f:
    data = json.load(f)
with open(info_path) as f:
    info = json.load(f)

jars_gav = set()
for cveid, cve_data in data.items():
    gav = info[cveid]["JarDownloadPath"].split("/")[-1]
    jars_gav.add(gav)

time_dict = {}
new_jar = set()
for jar in tqdm(jars_gav):
    g = jar[:jar.index("-")]
    a = jar[jar.index("-") + 1:]
    query_url = f"https://search.maven.org/solrsearch/select?q=g:{g}+AND+a:{a}&core=gav&rows=20&wt=json"
    resp = requests.get(query_url).content.decode()
    meta = json.loads(resp)
    try:
        timestamp = meta["response"]["docs"][0]["timestamp"]
    except IndexError:
        print(f"no timestamp found for {jar}")
        continue
    date = datetime.fromtimestamp(timestamp / 1000)
    if date >= datetime(2024, 7, 1):
        new_jar.add(jar)
    print(f"{jar}: {date}")
print(f"total: {len(jars_gav)}, new: {len(new_jar)}")
with open("new_jar.txt", "w") as f:
    f.write("\n".join(new_jar))