import json
import os

raw_result_file = "./resultMultiSnippetVersion.txt"
raw_result_eval = "./versions_results.json"
cve_gav_map = "1.empirical/gav_cve_overlap_generality.json"

def get_matched_func():
    fp = open(raw_result_file)
    lines = fp.readlines()
    fp.close()
    
    i = 0
    gt_method = {}

    while i < len(lines):
        
        if lines[i].startswith("Found"):                
            cve = lines[i].split(" ")[1]
            if cve not in gt_method:
                gt_method[cve] = {}
            repoName = "/".join(lines[i].split(" ")[3].strip().split("/")[-2:])
            if repoName not in gt_method[cve]:
                gt_method[cve][repoName] = {}
            i += 1
            
            while i<len(lines) and lines[i] != "\n":
                
                while i < len(lines) and "matches the following methods" not in lines[i]:
                    i += 1
                if i+1 < len(lines) and "matches the following methods" not in lines[i+1] and lines[i+1] != "\n":
                    if "methods" not in gt_method[cve][repoName].keys():
                        gt_method[cve][repoName]["methods"] = {}
                    method = lines[i].replace("Method ","").replace(" matches the following methods:","").strip().split("__split__")[1]
                    gt_method[cve][repoName]["methods"][method] = []
                    j = i+1
                    while j < len(lines) and ("matches the following methods" not in lines[j] and lines[j] != "\n"):
                        tar_methods = " ".join(lines[j].replace("Method ","").split(" ")[0:-6])
                        gt_method[cve][repoName]["methods"][method].append(tar_methods)
                        j += 1
                    i = j-1
                i += 1
            i += 1            
        else:
            print(line)
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
        for gav in gt_method[cve]:
            ga = gav.split("/")[0]
            av = gav.split("/")[-1].strip()
            a = cve_gav[cve].split(":")[1]
            v = av.replace(a + "-","")
            matched = False

            for method in gt_method[cve][gav]["methods"]:
                if critical_method_list[f"critical_{cve}"]["old_info"]["hits"][method] >= 0.6:
                    matched = True

            if matched:
                result_eval[cve]["JarVersions"][v]["MVP"] = 1
            else:
                result_eval[cve]["JarVersions"][v]["MVP"] = 0

    fp = open("../results.json","w")
    json.dump(result_eval, fp, index=4)
    fp.close()

    

if __name__ == "__main__":
    get_critical_function_selective_results()
    

