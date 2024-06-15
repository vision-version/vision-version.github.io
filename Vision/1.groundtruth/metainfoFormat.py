import json


with open("cve_metainfo_all.json", "r") as fr:
    metainfo = json.load(fr)
metainfos = {}
for cve, patch in metainfo.items():
    metainfos[cve] = {
        "patch": patch
    }

with open("cves_metainfo.json", "w") as fw:
    json.dump(metainfos, fw, indent = 4)