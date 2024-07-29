import json
import os

raw_result_file = "./clone_detection_res_version"
raw_result_eval = "./versions_results_20240607.json"
cve_gav_map = "gav_cve_overlap_generality.json"

def get_matched_func():
    fp = open(raw_result_file)
    lines = fp.readlines()
    fp.close()
    
    i = 0
    gt_method = {}

    for line in lines:
        cve = line.split("\t")[0]
        if cve not in gt_method:
            gt_method[cve] = {}
        av = line.split("\t")[-1].strip()
        if av not in gt_method[cve]:
            gt_method[cve][av] = {}
        method = line.split("\t")[-3].split("_")[2].split("@@")[-1]
        try:
            gt_method[cve][av]["methods"].append(method)
        except:
            gt_method[cve][av]["methods"] = [method]

    with open("MVP_results.json","w") as f:
        json.dump(gt_method, f)
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
                result_eval[cve]["JarVersions"][v]["v0finder"] = 1
            else:
                result_eval[cve]["JarVersions"][v]["v0finder"] = 0

    fp = open("../results.json","w")
    json.dump(result_eval, fp, index=4)
    fp.close()

    

if __name__ == "__main__":
    get_critical_function_selective_results()
    

