import os, json
from icecream import ic


gt_path = "../trueresult.json"

with open(gt_path, "r") as fr:
    gt = json.load(fr)

def db_evaluate():
    tool_lst = ["nvd", "veracode",  "github", "gitlab", "snyk"] 
    tool_results = []
    for tool in tool_lst:
        db_ourtool_path = f"our_tool_db_{tool}.json"
        with open(db_ourtool_path, "r") as fr:
            db_ourtool = json.load(fr)

        our_tool = f"our_tool_{tool}"
        with open("../effectiveness/results_overview.json", "r") as fr:
            results_overview = json.load(fr)
        tool_tp = 0
        tool_fp = 0
        tool_tn = 0
        tool_fn = 0

        our_tool_tp = 0
        our_tool_fp = 0
        our_tool_tn = 0
        our_tool_fn = 0

        prefect_cve = 0
        our_prefect_cve = 0
        cve_num = 0
        for cve, result in gt.items():
            
            tool_cve_tp = 0
            tool_cve_fp = 0
            tool_cve_tn = 0
            tool_cve_fn = 0

            our_tool_cve_tp = 0
            our_tool_cve_fp = 0
            our_tool_cve_tn = 0
            our_tool_cve_fn = 0

            fp_flag = True
            fn_flag = True
            
            our_fp_flag = True
            our_fn_flag = True

            if cve not in db_ourtool:
                continue
            else:
                cve_num += 1

            # db
            for version in result["affected"]:
                # if tool == "nvd" and cve == "CVE-2021-27568": print(db_ourtool[cve][version][tool])
                if version not in db_ourtool[cve]:
                    tool_cve_fn += 1
                    fn_flag = False
                else:
                    if db_ourtool[cve][version][tool] == 1:
                        tool_cve_tp += 1
                    if db_ourtool[cve][version][tool] == 0:
                        tool_cve_fn += 1
                        fn_flag = False      
                    if db_ourtool[cve][version][tool] == -1:
                        raise ValueError(f"")
            # ours
            for version in result["affected"]:
                if version not in db_ourtool[cve]:
                    our_tool_cve_fn += 1
                    our_fn_flag = False
                else:

                    if db_ourtool[cve][version]["ourtool"] == 1:
                        our_tool_cve_tp += 1
   
                    if db_ourtool[cve][version]["ourtool"] == 0:
                        our_tool_cve_fn += 1
                        our_fn_flag = False      
              
                    if db_ourtool[cve][version]["ourtool"] == -1:
                        raise ValueError(f"")
            
            # db
        
            for version in result["unaffected"]:
                # if tool == "nvd" and cve == "CVE-2021-27568": print(db_ourtool[cve][version][tool])

                if version not in db_ourtool[cve]:
     
                    tool_cve_tn += 1
                    continue
           
                if db_ourtool[cve][version][tool] == 1:
                    tool_cve_fp += 1
                    fp_flag = False
                elif db_ourtool[cve][version][tool] == 0:
                    tool_cve_tn += 1
           
                elif db_ourtool[cve][version][tool] == -1:
                    pass
            # ours
            for version in result["unaffected"]:
            
                if version not in db_ourtool[cve]:
        
                    our_tool_cve_tn += 1
                    continue
        
                if db_ourtool[cve][version]["ourtool"] == 1:
                    our_tool_cve_fp += 1
                    our_fp_flag = False
                elif db_ourtool[cve][version]["ourtool"] == 0:
                    our_tool_cve_tn += 1
    
                elif db_ourtool[cve][version]["ourtool"] == -1:
                    pass

            results_overview[cve][tool] = {
                "tp": tool_cve_tp,
                "fp": tool_cve_fp,
                "tn": tool_cve_tn,
                "fn": tool_cve_fn
            }
            results_overview[cve][our_tool] = {
                "tp": our_tool_cve_tp,
                "fp": our_tool_cve_fp,
                "tn": our_tool_cve_tn,
                "fn": our_tool_cve_fn
            }
            if fp_flag and fn_flag: 
                prefect_cve += 1
            if our_fp_flag and our_fn_flag: 
                our_prefect_cve += 1
            tool_tp += tool_cve_tp
            tool_fp += tool_cve_fp
            tool_tn += tool_cve_tn
            tool_fn += tool_cve_fn        

            our_tool_tp += our_tool_cve_tp
            our_tool_fp += our_tool_cve_fp
            our_tool_tn += our_tool_cve_tn
            our_tool_fn += our_tool_cve_fn     
            # if tool_cve_tp + tool_cve_fn != our_tool_cve_tp + our_tool_cve_fn:
            #     print(cve)
        precision = round(tool_tp / (tool_tp + tool_fp + 1e-5), 3)
        recall = round(tool_tp / (tool_fn + tool_tp + 1e-5), 3)

        our_precision = round(our_tool_tp / (our_tool_tp + our_tool_fp + 1e-5), 3)
        our_recall = round(our_tool_tp / (our_tool_fn + our_tool_tp + 1e-5), 3)

        # print(" &", tool, " &", cve_num, " &", prefect_cve, " &", tool_tp, " &", tool_fp, " &", tool_fn, " &",precision, " &", recall, "\\\\")
        # print(" &", our_tool, " &", cve_num, " &", our_prefect_cve, f"/+{our_prefect_cve - prefect_cve} &", our_tool_tp, f"$\\uparrow$({our_tool_tp - tool_tp} &", our_tool_fp, f"/-{tool_fp - our_tool_fp} &", our_tool_fn, f"/-{tool_fn - our_tool_fn} &", our_precision, f"/+{our_precision - precision:.3f} &", our_recall, f"/+{our_recall - recall:.3f}", "\\\\")
        print(" &", tool, " &", cve_num, " &", f"{prefect_cve}/+{our_prefect_cve - prefect_cve} &", f"{tool_tp}/+{our_tool_tp - tool_tp} &", f"{tool_fp}/-{tool_fp - our_tool_fp} &", f"{tool_fn}/-{tool_fn - our_tool_fn} &", f"{precision:.2f}/+{our_precision - precision:.2f} &", f"{recall:.2f}/+{our_recall - recall:.2f}", "\\\\")
        with open("results_overview.json", "w") as fw:
            json.dump(results_overview, fw, indent = 4)

if __name__ == "__main__":
    db_evaluate()