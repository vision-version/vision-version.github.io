import json
import os
import sys

def modified_line_map():
    modified_methods_all = {}
    with open("2.methodology/patch_callchain_generate/cves_methods.json","r") as fr:
        cve_methods = json.load(fr)
    
    for cve in cve_methods:
        modified_methods_all[cve] = {
            "old": lines_locate("delete",cve_methods[cve]["old_methods_info"]),
            "new": lines_locate("add", cve_methods[cve]["new_methods_info"])
        }
    return modified_methods_all

def lines_locate(status, cve_status_modified):
    pairLst = []
    for modifiedfiles in cve_status_modified:
        for methodsName, medofiedmethods in modifiedfiles[status + "MethodFull"].items():
            for lineDict in medofiedmethods["lineNumber"]:
                lineNumber, lineContent = next(iter(lineDict.items()))
                pairLst.append((lineNumber, lineContent))
    return pairLst

def locate_assign():
    directory_path = '2.methodology/patch_featuregraph_generate/weighted_graph_final'
    new_directory_path = '2.methodology/patch_featuregraph_generate/weighted_graph_lineweight'
    modified_methods_all = modified_line_map()
    for dirpath, dirnames, _ in os.walk(directory_path):
        status = ["old", "new"]
        for status in status:
            for dirname in dirnames:
                json_path = os.path.join(dirpath, dirname, f"{dirname}_{status}.json")
                new_json_path = os.path.join(new_directory_path, dirname, f"{dirname}_{status}.json")

                os.makedirs(os.path.dirname(new_json_path), exist_ok=True)

                with open(json_path, "r") as fr:
                    weighted_graph = json.load(fr)
                if not any(weighted_graph): continue
                for fullSignature, lineMeta in weighted_graph["node_dicts"].items():
                    if (fullSignature.split("__split__")[-1], lineMeta["node_string"]) in modified_methods_all[dirname][status]:
                        lineMeta["weight"] = 5
                with open(new_json_path, "w") as fw:
                    json.dump(weighted_graph, fw, indent=4)
def graph_resave():
    pass
    
if __name__ == "__main__":
    locate_assign()