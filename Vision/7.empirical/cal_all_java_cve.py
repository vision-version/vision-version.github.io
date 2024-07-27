import json

with open("cve_gav_format.json") as f:
    cve_gav = json.load(f)
with open("cve_ga.json") as f:
    cve_ga = json.load(f)

ga_v = {}
for cveid, tags in cve_gav.items():
    if cveid not in cve_ga:
        continue
    ga_v[cve_ga[cveid]] = tags
with open("ga_v.json", "w") as f:
    json.dump(ga_v, f, indent=4)
