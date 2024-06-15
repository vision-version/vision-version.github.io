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

def cwe_cve_map():
    all_cves = {}
    for i in reversed(range(2002, 2024)):
        with open(f"./cve_feed/nvdcve-1.1-{i}.json", "r") as f:
            data = json.load(f)
            cve_json_list = data["CVE_Items"]
            for cve_json in cve_json_list:
                repo_cve = CVE()
                repo_cve.parse_cve(cve_json)
                all_cves[repo_cve.cve_id] = repo_cve.cwe_id

    with open(f"./cve_feed/nvdcve-1.1-recent.json", "r") as f:
        data = json.load(f)
        cve_json_list = data["CVE_Items"]
        for cve_json in cve_json_list:
            repo_cve = CVE()
            repo_cve.parse_cve(cve_json)
            all_cves[repo_cve.cve_id] = repo_cve.cwe_id

    with open('cve_list.json') as f:
        data = json.load(f)

    # cve_cwe_list: dict[str, int] = {}
    cve_cwe_list = {"other": []}
    for cve_id in data:
        if cve_id not in all_cves:
            cve_cwe_list["other"].append(cve_id)
            print(f"Missing cve_id: {cve_id}")
            continue
        cwe_id = all_cves[cve_id]
        if cwe_id == "NVD-CWE-noinfo" or cwe_id == "NVD-CWE-Other":
            cve_cwe_list["other"].append(cve_id)
        else:
            if cwe_id not in cve_cwe_list:
                cve_cwe_list[cwe_id] = [cve_id]
            else:
                cve_cwe_list[cwe_id].append(cve_id)

    # sort and report
    sorted_cwe_list = sorted(cve_cwe_list.items(), key=lambda x: x[1], reverse=True)
    for cwe_id, count in sorted_cwe_list:
        if cwe_id == "other":
            des = "Other"
        else:
            cwe_id_num = int(cwe_id.split("-")[1])
            if cwe_id_num == 19:
                des = "Data Processing Errors"
            elif cwe_id_num == 417:
                des = "Communication Channel Errors"
            elif cwe_id_num == 399:
                des = "Small Seed Space in PRNG"
            elif cwe_id_num == 310:
                des = "Cryptographic Issues"
            elif cwe_id_num == 264:
                des = "Permissions, Privileges, and Access Controls"
            else:
                try:
                    des = db.get(cwe_id_num).name
                except:
                    des = "Other"
        print(f"{cwe_id}: {count} ({des})")

    print(len(sorted_cwe_list))

    with open("cwe_cve_map.json", "w") as fw:
        json.dump(cve_cwe_list, fw, indent = 4)

def cwe_evaluate():
    # tools = ["our_tool", "github", "gitlab", "snyk", "veracode", "vszz", "verjava_github", "verjava_maven", "vuddy", "v0finder"]
    tools = ["vszz", "verjava_github", "verjava_maven","v0finder", "MVP", "vuddy", "our_tool_github" , "our_tool"]


    with open("cwe_cve_map.json", "r") as fr:
        CWE_map_cve = json.load(fr)
    # print(list(CWE_map_cve.keys()))
    with open("cwe_type.json", "r") as fr:
        CWE_type = json.load(fr)
    with open("results_overview.json", "r") as fr:
        results_overview = json.load(fr)

    line_types = list(CWE_type.keys())
    print(line_types)
    line_type_dic = { tool : {each: {"fp": 0, "fn": 0, "tp": 0, "tn": 0, "num":0 } for each in line_types} for tool in tools}

    for cve in results_overview:
        hit_flag = False
        for cwe_type in CWE_map_cve:
            if cve not in CWE_map_cve[cwe_type]:continue
            hit_flag = True
            cve_cwe = cwe_type
        if not hit_flag: raise ValueError("cve cwe type not found")
        for vul_type in CWE_type:
            if cve_cwe in CWE_type[vul_type]:
                target_vul_type = vul_type
                for tool in tools:
                    hybird_cve = 0
                    add_cve = 0
                    del_cve = 0
                    if tool in results_overview[cve]:
                        line_type_dic[tool][target_vul_type]["num"] += 1
                        line_type_dic[tool][target_vul_type]["tp"] += results_overview[cve][tool]["tp"]
                        line_type_dic[tool][target_vul_type]["tn"] += results_overview[cve][tool]["tn"]
                        line_type_dic[tool][target_vul_type]["fp"] += results_overview[cve][tool]["fp"]
                        line_type_dic[tool][target_vul_type]["fn"] += results_overview[cve][tool]["fn"]
    for tool, result in line_type_dic.items():
        # for line_type in line_types:
        #     typenum = result[line_type]["num"]
        #     type_fp = result[line_type]["fp"]
        #     type_tp = result[line_type]["tp"]
        #     type_pre = type_tp / (type_tp + type_fp + 0.0001)
        #     print(f"& {typenum} ", end='')
        # print("\\\\")
        print(tool, end=' ')
        for line_type in line_types:
            typenum = result[line_type]["num"]
            type_fp = result[line_type]["fp"]
            type_tp = result[line_type]["tp"]
            type_pre = type_tp / (type_tp + type_fp + 0.0001)
            print(f" & {type_pre:.2f} ", end='')
        print("\\\\")
        print(tool, end=' ')
        for line_type in line_types:
            typenum = result[line_type]["num"]
            type_fn = result[line_type]["fn"]
            type_tp = result[line_type]["tp"]
            type_rec = type_tp / (type_tp + type_fn + 0.0001)
            print(f" & {type_rec:.2f} ", end='')
        print("\\\\")

    # with open("cve_vultype.json", "w") as fw:
    #     json.dump(line_type_dic, fw, indent = 4)

if __name__ == "__main__":
    # cwe_cve_map()
    cwe_evaluate()
