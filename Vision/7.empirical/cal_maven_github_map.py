import json

with open("cve_ga_map.json") as f:
    cve_ga_map = json.load(f)
with open("cve_github_map.json") as f:
    cve_github_map = json.load(f)

maven_github_map = {}
for cveid, ga in cve_ga_map.items():
    if cveid not in cve_github_map:
        continue
    maven_github_map[ga] = cve_github_map[cveid]
with open("maven_github_map.json", "w") as f:
    json.dump(maven_github_map, f, indent=4)
