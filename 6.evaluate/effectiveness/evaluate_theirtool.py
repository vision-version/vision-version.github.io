import os, json
from icecream import ic

vszz_verjava_gpt_db_path = "../versions_sota1.json"
v0finer_vuddy_mvp_path = "../versions_sota2.json"
gt_path = "../trueresult.json"

with open(gt_path, "r") as fr:
    gt = json.load(fr)

with open(vszz_verjava_gpt_db_path, "r") as fr:
    vszz_verjava_gpt_db = json.load(fr)

with open(v0finer_vuddy_mvp_path, "r") as fr:
    v0finer_vuddy_mvp = json.load(fr)

def database_evaluate():
    db_lst = ["nvd", "veracode", "github", "gitlab", "snyk"]
    db_results = []
    with open("results_perfect.json", "r") as fr:
        results_perfect = json.load(fr)
    for db in db_lst:
        print(db)
        with open("results_overview.json", "r") as fr:
            results_overview = json.load(fr)
        results_perfect[db] = []
        db_tp = 0
        db_fp = 0
        db_tn = 0
        db_fn = 0
        prefect_cve = 0
        cve_num = 0
        missing_cve_num = 0
        for cve, result in gt.items():
            fp_flag = True
            fn_flag = True

            db_cve_tp = 0
            db_cve_fp = 0
            db_cve_tn = 0
            db_cve_fn = 0            
            
            if db in vszz_verjava_gpt_db[cve]["Failed"]:
                missing_cve_num += 1
                continue
            else:
                cve_num += 1

            for version in result["affected"]:

                if version not in vszz_verjava_gpt_db[cve]["JarVersions"]:

                    db_cve_fn += 1 
                    fn_flag = False                     
                    continue

                if vszz_verjava_gpt_db[cve]["JarVersions"][version][db] == 1:
                    db_cve_tp += 1

                if vszz_verjava_gpt_db[cve]["JarVersions"][version][db] == 0:
                    db_cve_fn += 1
                    fn_flag = False 

                if vszz_verjava_gpt_db[cve]["JarVersions"][version][db] == -1:
                    raise ValueError("漏洞库为空")
                vszz_verjava_gpt_db[cve]["JarVersions"][version][db]
            
            for version in result["unaffected"]:
    
                if version not in vszz_verjava_gpt_db[cve]["JarVersions"]:

                    continue

                if vszz_verjava_gpt_db[cve]["JarVersions"][version][db] == 1:
                    db_cve_fp += 1
                    fp_flag = False 
                else:
                    db_cve_tn += 1

            if fp_flag and fn_flag: 
                prefect_cve += 1
                results_perfect[db].append(cve)
            # else:
            #     print(cve)
            results_overview[cve][db] = {
                "tp": db_cve_tp,
                "fp": db_cve_fp,
                "tn": db_cve_tn,
                "fn": db_cve_fn
            }
            db_tp += db_cve_tp
            db_fp +=db_cve_fp
            db_tn +=db_cve_tn
            db_fn += db_cve_fn
        
        precision = round(db_tp / (db_tp + db_fp), 3)
        recall = round(db_tp / (db_fn + db_tp), 3)
        ic(db, missing_cve_num, cve_num, prefect_cve, db_tp, db_fp, db_tn, db_fn, precision, recall)
        db_results.append([db, cve_num - missing_cve_num, prefect_cve, db_tp, db_fp, db_fn, precision, recall])
        with open("results_overview.json", "w") as fw:
            json.dump(results_overview, fw, indent = 4)
        with open("results_perfect.json", "w") as fw:
            json.dump(results_perfect, fw, indent = 4)
    return db_results

def versiontool_evaluate():
    with open("results_perfect.json", "r") as fr:
        results_perfect = json.load(fr)
    tool_lst = ["verjava_github","verjava_maven","vszz","vszz+", "our_tool_github"] 
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

            if tool in vszz_verjava_gpt_db[cve]["Failed"]:

                continue
            else:
                cve_num += 1

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
                    if tool in ["vszz", "verjava_github", "vszz+", "our_tool_github"]:
                        pass
           
                    else:
                        raise ValueError(f"")
  
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
                    if tool in ["vszz", "verjava_github", "vszz+"]:
                        pass
                        # tool_tn += 1
                    else:
                        raise ValueError(f"工具{tool}CVE{cve}版本{version}为空")

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
    database_evaluate()
    versiontool_evaluate()
    codewclone_evaluate()