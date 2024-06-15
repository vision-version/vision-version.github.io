import os, json
from icecream import ic
RUNPATH = os.getcwd()
import re
def multimethod_acquire():

    directory = '../../2.methodology/patch_callchain_generate/CGs'


    files = os.listdir(directory)


    filtered_files = [file for file in files if file.startswith('critical_') and file.endswith('.json')]


    cve_identifiers = [re.search('critical_(.+)\.json', file).group(1) for file in filtered_files]
    return cve_identifiers
# multi_cve = multimethod_acquire()

def eval_ourtool(trueresult_path, sortresults_path, ablation_type):
    gt_result_path = os.path.join(RUNPATH, trueresult_path)
    our_result_path = os.path.join(RUNPATH, sortresults_path)
    with open(gt_result_path, "r") as fr:
        gt_result = json.load(fr)
        
    with open(our_result_path, "r") as fr:
        our_result = json.load(fr)
    results = evaluate(gt_result, our_result, ablation_type)
    return results

def evaluate(gt_result, our_result, ablation_type):
    # with open("results_overview.json", "w") as fw: json.dump({}, fw, indent = 4)
    with open("results_overview.json", "r") as fr:
        results_overview = json.load(fr)
    tp_lib_all = 0
    tn_lib_all = 0
    fp_lib_all = 0
    fn_lib_all = 0
    cve_num = 0
    prefect_cve = 0
    for cve in our_result:

        # if cve not in multi_cve: continue
        # if cve in multi_cve: continue
        if cve not in gt_result: continue
        if cve not in results_overview:
            results_overview[cve] = {}
        tp_lib, fp_lib, fn_lib, tn_lib= calculate_metrics(our_result[cve], gt_result[cve])
        cve_num += 1
        tp_lib_all += tp_lib
        fp_lib_all += fp_lib
        fn_lib_all += fn_lib
        tn_lib_all += tn_lib
        results_overview[cve][ablation_type] = {
            "tp": tp_lib,
            "fp": fp_lib,
            "tn": tn_lib,
            "fn": fn_lib
        }
        if fn_lib == 0 and fp_lib == 0:
            prefect_cve += 1
    precision = round(tp_lib_all / (tp_lib_all+fp_lib_all), 3)
    recall = round(tp_lib_all / (tp_lib_all + fn_lib_all), 3)
    ic(tp_lib_all, fp_lib_all, fn_lib_all, tn_lib_all)
    ic(prefect_cve)
    ic(precision, recall)
    with open("results_overview.json", "w") as fw:
        json.dump(results_overview, fw, indent = 4)
    return [cve_num, prefect_cve, tp_lib_all, fp_lib_all, tn_lib_all, fn_lib_all, precision, recall, 2 * (precision * recall) / (precision + recall)]
def calculate_metrics(our_result, gt_result):
    affected = set(our_result["affected"])
    unaffected = set(our_result["unaffected"])
    gt_affected = set(gt_result["affected"])
    gt_unaffected = set(gt_result["unaffected"])
    
    tp = len(affected.intersection(gt_affected))

    fp = len(affected - gt_affected)

    fn = len(gt_affected - affected)

    tn = len(unaffected.intersection(gt_unaffected))
    
    return tp, fp, fn, tn

if __name__ == "__main__":
    
    types = ["without_cg", "without_ref", "without_all", "intra_1", "without_unixcoder"]
    for ablation_type in types:
        cve_num, prefect_cve, tp_lib_all, fp_lib_all, tn_lib_all, fn_lib_all, precision, recall, f1 = eval_ourtool("../trueresult.json", ic(f"sortresults_{ablation_type}.json"),ablation_type)