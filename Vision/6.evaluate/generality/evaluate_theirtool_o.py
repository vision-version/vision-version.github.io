import os, json
from icecream import ic

vszz_verjava_gpt_db_path = "versions_20240725.json"
v0finer_vuddy_mvp_path = "versions_20240725.json"
gt_path = "./trueresult_o.json"

with open(gt_path, "r") as fr:
    gt = json.load(fr)

with open(vszz_verjava_gpt_db_path, "r") as fr:
    vszz_verjava_gpt_db = json.load(fr)

with open(v0finer_vuddy_mvp_path, "r") as fr:
    v0finer_vuddy_mvp = json.load(fr)

def versiontool_evaluate():
    with open("results_perfect.json", "r") as fr:
        results_perfect = json.load(fr)
    tool_lst = ["verjava_github","verjava_maven","vszz"] 
    tool_results = []
    for tool in tool_lst:
        results_perfect[tool] = []
        with open("results_overview.json", "r") as fr:
            results_overview = json.load(fr)
        tool_tp = 0
        tool_fp = 0
        tool_tn = 0
        tool_fn = 0
        prefect_cve = 0
        cve_num = 0
        for cve, result in gt.items():

            tool_cve_tp = 0
            tool_cve_fp = 0
            tool_cve_tn = 0
            tool_cve_fn = 0     
            
            fp_flag = True
            fn_flag = True
            for version in result["affected"]:
                if version not in vszz_verjava_gpt_db[cve]["JarVersions"]:
                    tool_cve_fn += 1
                    fn_flag = False              
                    continue

                if vszz_verjava_gpt_db[cve]["JarVersions"][version][tool] == 1:
                    tool_cve_tp += 1

                if vszz_verjava_gpt_db[cve]["JarVersions"][version][tool] == 0:
                    tool_cve_fn += 1
                    fn_flag = False      
   
                if vszz_verjava_gpt_db[cve]["JarVersions"][version][tool] == -1:
                    if tool in ["vszz", "verjava_github", "verjava_maven"]:
                        pass
                        # tool_tn += 1
                    else:
                        pass
            for version in result["unaffected"]:
                if version not in vszz_verjava_gpt_db[cve]["JarVersions"]:
                    tool_cve_tn += 1
                    continue
                if vszz_verjava_gpt_db[cve]["JarVersions"][version][tool] == 1:
                    tool_cve_fp += 1
                    fp_flag = False
                elif vszz_verjava_gpt_db[cve]["JarVersions"][version][tool] == 0:
                    tool_cve_tn += 1
                elif vszz_verjava_gpt_db[cve]["JarVersions"][version][tool] == -1:
                    pass
            results_overview[cve][tool] = {
                "tp": tool_cve_tp,
                "fp": tool_cve_fp,
                "tn": tool_cve_tn,
                "fn": tool_cve_fn
            }

            if fp_flag and fn_flag: 
                prefect_cve += 1
                results_perfect[tool].append(cve)
            tool_tp += tool_cve_tp
            tool_fp += tool_cve_fp
            tool_tn += tool_cve_tn
            tool_fn += tool_cve_fn        
        precision = round(tool_tp / (tool_tp + tool_fp + 0.000001), 3)
        recall = round(tool_tp / (tool_fn + tool_tp + 0.000001), 3)
        ic(tool, cve_num, prefect_cve, tool_tp, tool_fp, tool_tn, tool_fn, precision, recall)
        tool_results.append([tool, cve_num, prefect_cve, tool_tp, tool_fp, tool_fn, precision, recall])
        with open("results_overview.json", "w") as fw:
            json.dump(results_overview, fw, indent = 4)
    with open("results_perfect.json", "w") as fw:
        json.dump(results_perfect, fw, indent = 4)
    return tool_results
    
def codewclone_evaluate():
    with open("results_perfect.json", "r") as fr:
        results_perfect = json.load(fr)
    tool_lst = ["vuddy", "v0finder", "MVP"]
    tool_results = []
    for tool in tool_lst:
        results_perfect[tool] = []
        with open("results_overview.json", "r") as fr:
            results_overview = json.load(fr)
        tool_tp = 0
        tool_fp = 0
        tool_tn = 0
        tool_fn = 0
        prefect_cve = 0
        cve_num = 0
        for cve, result in gt.items():
            tool_cve_tp = 0
            tool_cve_fp = 0
            tool_cve_tn = 0
            tool_cve_fn = 0     
            
            fp_flag = True
            fn_flag = True

            cve_num += 1
            for version in list(set(result["affected"])):
                if version not in v0finer_vuddy_mvp[cve]["JarVersions"]:
                    tool_cve_fn += 1
                    fn_flag = False              
                    continue
                if v0finer_vuddy_mvp[cve]["JarVersions"][version][tool] == 1:
                    tool_cve_tp += 1
                if v0finer_vuddy_mvp[cve]["JarVersions"][version][tool] == 0:
                    tool_cve_fn += 1
                    fn_flag = False      
                if v0finer_vuddy_mvp[cve]["JarVersions"][version][tool] == -1:
                    if tool in ["vszz", "verjava_github"]:
                        pass
                        # tool_tn += 1
                    else:
                        pass
            for version in result["unaffected"]:
                if version not in v0finer_vuddy_mvp[cve]["JarVersions"]:
                    tool_cve_tn += 1
                    continue
                if v0finer_vuddy_mvp[cve]["JarVersions"][version][tool] == 1:
                    tool_cve_fp += 1
                    fp_flag = False
                else:
                    tool_cve_tn += 1
            results_overview[cve][tool] = {
                "tp": tool_cve_tp,
                "fp": tool_cve_fp,
                "tn": tool_cve_tn,
                "fn": tool_cve_fn
            }

            if fp_flag and fn_flag: 
                prefect_cve += 1
                results_perfect[tool].append(cve)
            tool_tp += tool_cve_tp
            tool_fp += tool_cve_fp
            tool_tn += tool_cve_tn
            tool_fn += tool_cve_fn        
        precision = round(tool_tp / (tool_tp + tool_fp + 0.000001), 3)
        recall = round(tool_tp / (tool_fn + tool_tp + 0.000001), 3)
        ic(tool, cve_num, prefect_cve, tool_tp, tool_fp, tool_tn, tool_fn, precision, recall)
        tool_results.append([tool, cve_num, prefect_cve, tool_tp, tool_fp, tool_fn, precision, recall])
        with open("results_overview.json", "w") as fw:
            json.dump(results_overview, fw, indent = 4)
    with open("results_perfect.json", "w") as fw:
        json.dump(results_perfect, fw, indent = 4)
    return tool_results

if __name__ == "__main__":
    versiontool_evaluate()
    codewclone_evaluate()