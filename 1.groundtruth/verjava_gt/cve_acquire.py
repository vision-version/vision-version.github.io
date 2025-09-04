import os
import json


files = [f for f in os.listdir('.') if f.endswith('.json')]


keys_lst = []


for file in files:
    with open(file, 'r', encoding='utf-8') as fr:
        data = json.load(fr)

        keys_lst += list(data.keys())

with open("0.groundtruth/vszz_gt/verified_cve_with_versions_Java.json", "r") as fr:
    vszz_dic = json.load(fr)
for project in vszz_dic:
    keys_lst.append(project["cve_id"])

with open("6.evaluate/trueresult original.json", "r") as fr:
    gt = json.load(fr)

gt_keys  = list(gt.keys())
print(gt_keys)
# print(len(list(set(gt_keys) & set(keys_lst))))
