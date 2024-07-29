import json
import os

raw_result_file = "./results_Java_tree_rebuttal.txt"
raw_result_eval = "./versions_yiheng_20240607.json"
cve_gav_map = "gav_cve_overlap_generality.json"
target_Repo = "targetRepo_java/"

def get_matched_func():
    fp = open(raw_result_file)
    lines = fp.readlines()
    fp.close()

    results = {}
    gt_method = {}
    with open(raw_result_file, "r") as f:
        lines = f.readlines()
        i = 0
        while i < len(lines):
            if lines[i].startswith("Found "):
                cve = lines[i].split(" ")[1].replace(".txt","")
                if cve not in gt_method.keys():
                    gt_method[cve] = []
                repo = lines[i].split(" ")[3]
                method = lines[i].split(" ")[2]
                
                try:
                    gt_method[cve][repo]["methods"].append(method)
                except:
                    gt_method[cve][repo]["methods"] = [method]
            i += 1
            
    return gt_method
    
def get_critical_function_selective_results():
    if not os.path.exists("../results.json"):
        os.system(f"cp {raw_result_eval} ../results.json")
    fp = open("../critial_all.json")
    critical_method_list = json.load(fp)
    fp.close()
    gt_method = get_matched_func()
    fp = open("../results.json")
    result_eval = json.load(fp)
    fp.close()

    fp = open(cve_gav_map)
    ga_cve = json.load(fp)
    fp.close()

    cve_gav = {}

    for ga in ga_cve:
        for cve in ga_cve[ga]["cve"]:
            cve_gav[cve] = ga


    for cve in gt_method:
        for av in gt_method[cve]:
            a = cve_gav[cve].split(":")[1]
            v = av.replace(a + "-","")
            matched = False

            for method in gt_method[cve][av]["methods"]:
                for hits_method in critical_method_list[f"critical_{cve}"]["old_info"]["hits"]:
                    if hits_method.split(".")[-1] == method:
                        if critical_method_list[f"critical_{cve}"]["old_info"]["hits"][method] >= 0.6:
                            matched = True

            if matched:
                result_eval[cve]["JarVersions"][v]["vuddy"] = 1
            else:
                result_eval[cve]["JarVersions"][v]["vuddy"] = 0

    fp = open("../results.json","w")
    json.dump(result_eval, fp, index=4)
    fp.close()

    

if __name__ == "__main__":
    get_critical_function_selective_results()
    

