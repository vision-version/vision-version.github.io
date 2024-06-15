import os
import zipfile

import json
from cwe2.database import Database

cve_list = []
db = Database()

class CVE:
    def __init__(
        self,
        cve_id: str = None,
        cwe_id: str = None,
        cvss_version: str = None,
        cvss_score: float = None,
        references: list = None,
    ):
        self.cve_id = cve_id
        self.cwe_id = cwe_id
        self.cvss_version = cvss_version
        self.cvss_score = cvss_score
        self.references = references
        self.patch_like_url = []

    def parse_cve(self, cve):
        self.cve_id = cve["cve"]["CVE_data_meta"]["ID"]
        try:
            self.cwe_id = cve["cve"]["problemtype"]["problemtype_data"][0][
                "description"
            ][0]["value"]
        except:
            self.cwe_id = None

def number_evaluate():
    tools = ["vszz", "verjava_github", "verjava_maven","v0finder", "MVP", "vuddy", "our_tool_github" , "our_tool"]

    with open("cve_number_map.json", "r") as fr:
        number_map_cve = json.load(fr)
    with open("results_overview.json", "r") as fr:
        results_overview = json.load(fr)
    with open("results_perfect.json", "r") as fr:
        prefect_overview = json.load(fr)
    line_types = list(number_map_cve.keys())
    line_type_dic = { tool : {each: {"fp": 0, "fn": 0, "tp": 0, "tn": 0, "num":0, "prefect": 0 } for each in line_types} for tool in tools}
    # 循环每一个cve
    for cve in results_overview:
        hit_flag = False
        for number_type in number_map_cve:
            if cve not in number_map_cve[number_type]:
                continue
            hit_flag = True
            for tool in tools:
                hybird_cve = 0
                add_cve = 0
                del_cve = 0

                if tool in results_overview[cve]:
                    line_type_dic[tool][number_type]["num"] += 1
                    line_type_dic[tool][number_type]["tp"] += results_overview[cve][tool]["tp"]
                    line_type_dic[tool][number_type]["tn"] += results_overview[cve][tool]["tn"]
                    line_type_dic[tool][number_type]["fp"] += results_overview[cve][tool]["fp"]
                    line_type_dic[tool][number_type]["fn"] += results_overview[cve][tool]["fn"]
                    if cve in prefect_overview[tool]:
                        line_type_dic[tool][number_type]["prefect"] += 1
    for line_type in line_types:
        for tool, result in line_type_dic.items():
            print(tool)
            typenum = result[line_type]["num"]
            typepernum = result[line_type]["prefect"]
            type_fp = result[line_type]["fp"]
            type_tp = result[line_type]["tp"]
            type_fn = result[line_type]["fn"]
            type_pre = type_tp / (type_tp + type_fp + 0.0001)
            type_rec = type_tp / (type_tp + type_fn + 0.0001)
            print(f" {line_type} & {typenum} & {typepernum} & {type_tp} & {type_fp} & {type_fn} & {type_pre:.2f} & {type_rec:.2f} \\\\")
    print("\\\\")

    # with open("cve_vultype.json", "w") as fw:
    #     json.dump(line_type_dic, fw, indent = 4)

if __name__ == "__main__":
    number_evaluate()
