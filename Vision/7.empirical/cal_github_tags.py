import json

with open("cve_tags_format.json") as f:
    cve_tags_format = json.load(f)

with open("cve_github_map.json") as f:
    cve_github_map = json.load(f)

github_tags_map = {}
for cveid, tags in cve_tags_format.items():
    if cveid not in cve_github_map:
        continue
    github_tags_map[cve_github_map[cveid]] = tags
with open("github_tags_map.json", "w") as f:
    json.dump(github_tags_map, f, indent=4)
