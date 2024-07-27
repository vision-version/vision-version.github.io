import json
import requests
from lxml import html
from tqdm import tqdm


def ga_get(CVE_ID):
    url = f"https://security.snyk.io/vuln/maven?search={CVE_ID}"

    response = requests.get(url)
    response.raise_for_status()
    tree = html.fromstring(response.content)
    elements = tree.xpath('//*[@id="sortable-table"]/tbody/tr/td[2]/a/text()')
    for element in elements:
        return element.strip()


with open("sim_patch.json") as f:
    data: dict[str, dict] = json.load(f)

cve_ga_map = {}
for cveid in tqdm(data):
    try:
        ga = ga_get(cveid)
    except:
        ga = None
    if ga != None and ga != "":
        cve_ga_map[cveid] = ga

with open("cve_ga.json", "w") as f:
    json.dump(cve_ga_map, f, indent=4)
