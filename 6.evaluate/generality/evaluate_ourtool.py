import os, json
from icecream import ic
RUNPATH = os.getcwd()

def json_loader(path):
    with open(path, "r") as fr:
        return json.load(fr)
def eval_ourtool():
    gt_result_path = os.path.join(RUNPATH, "./trueresult_og.json")
    our_result_path = os.path.join(RUNPATH, "./sortresults_og.json")
    with open(gt_result_path, "r") as fr:
        gt_result = json.load(fr)
        
    with open(our_result_path, "r") as fr:
        our_result = json.load(fr)
    gt_result_o = json_loader("trueresult_o.json")
    our_result_o = json_loader("sortresults_o.json")

    gt_result_g = json_loader("trueresult_g.json")
    our_result_g = json_loader("sortresults_g.json")

    results = evaluate(gt_result_o, our_result_o)
    # results = evaluate(gt_result_g, our_result_g)
    # results = evaluate(gt_result, our_result)
    return results
def evaluate(gt_result, our_result):
    with open("results_overview.json", "r") as fr:
        results_overview = json.load(fr)
    
    with open("results_perfect.json", "r") as fr:
        results_perfect = json.load(fr)
    results_perfect["our_tool"] = []
    tp_lib_all = 0
    tn_lib_all = 0
    fp_lib_all = 0
    fn_lib_all = 0
    cve_num = 0
    prefect_cve = 0
    for cve in gt_result:
        if cve not in our_result:
            continue
        if cve not in results_overview:
            results_overview[cve] = {}

        tp_lib, fp_lib, fn_lib, tn_lib= calculate_metrics(our_result[cve], gt_result[cve])

        cve_num += 1
        tp_lib_all += tp_lib
        fp_lib_all += fp_lib
        fn_lib_all += fn_lib
        tn_lib_all += tn_lib
        results_overview[cve]["our_tool"] = {
            "tp": tp_lib,
            "fp": fp_lib,
            "tn": tn_lib,
            "fn": fn_lib
        }
        if fn_lib == 0 and fp_lib == 0:
            results_perfect["our_tool"].append(cve)
            prefect_cve += 1
        if fp_lib > 20 or fn_lib > 20:
            print(cve, fp_lib + fn_lib)
    precision = round(tp_lib_all / (tp_lib_all+fp_lib_all), 3)
    recall = round(tp_lib_all / (tp_lib_all + fn_lib_all), 3)
    ic(tp_lib_all, fp_lib_all, fn_lib_all, tn_lib_all, 2 * (precision * recall) / (precision + recall))
    ic(prefect_cve)

    with open("results_overview.json", "w") as fw:
        json.dump(results_overview, fw, indent = 4)
    with open("results_perfect.json", "w") as fw:
        json.dump(results_perfect, fw, indent = 4)
    return [[cve_num, prefect_cve, tp_lib_all, fp_lib_all, fn_lib_all, precision, recall]]
def calculate_metrics(our_result, gt_result):
    affected = set(our_result["affected"])
    unaffected = set(our_result["unaffected"])
    gt_affected = set(gt_result["affected"])
    gt_unaffected = set(gt_result["unaffected"])
    if len(list(affected & unaffected)) > 0:
        raise(ValueError("xxxxxx"))

    tp = len(affected.intersection(gt_affected))
    
    fp = len(affected - gt_affected)
    fn = len(gt_affected - affected)
    tn = len(unaffected.intersection(gt_unaffected))
    
    return tp, fp, fn, tn

if __name__ == "__main__":
    eval_ourtool()