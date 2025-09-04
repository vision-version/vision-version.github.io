import json

def get_cwe_type_results():
    fp = open("final_results.json","r")
    results = json.load(fp)
    fp.close()
    cwe_type = {}
    fp = open("./cwe_cve_category.json")
    cwe_cve_category = json.load(fp)
    fp.close()
    for cve in results.keys():
        if len(results[cve]['cwe']) == 0:
            if 'other' not in cwe_type.keys():
                cwe_type['other'] = []
            cwe_type['other'].append(cve)
            continue
        flag = False
        for type in cwe_cve_category.keys():
            if results[cve]['cwe'][0] in cwe_cve_category[type].keys():
                if type not in cwe_type.keys():
                    cwe_type[type] = []
                cwe_type[type].append(cve)
                flag = True
                break
        if not flag:
            if 'other' not in cwe_type.keys():
                cwe_type['other'] = []

    results_cwe = {}
    for cwe in cwe_type.keys():
        results_cwe[cwe] = {}
        results_cwe[cwe]['cve_list'] = cwe_type[cwe]
        results_cwe[cwe]['cve_num'] = len(cwe_type[cwe])
        results_cwe[cwe]['tp_vuddy'] = 0
        results_cwe[cwe]['fp_vuddy'] = 0
        results_cwe[cwe]['fn_vuddy'] = 0
        results_cwe[cwe]['tn_vuddy'] = 0
        results_cwe[cwe]['tp_v0finder'] = 0
        results_cwe[cwe]['fp_v0finder'] = 0
        results_cwe[cwe]['fn_v0finder'] = 0
        results_cwe[cwe]['tn_v0finder'] = 0
        results_cwe[cwe]['tp_visionpro'] = 0
        results_cwe[cwe]['fp_visionpro'] = 0
        results_cwe[cwe]['fn_visionpro'] = 0
        results_cwe[cwe]['tn_visionpro'] = 0
        results_cwe[cwe]['tp_mvp'] = 0
        results_cwe[cwe]['fp_mvp'] = 0
        results_cwe[cwe]['fn_mvp'] = 0
        results_cwe[cwe]['tn_mvp'] = 0
        for cve in cwe_type[cwe]:
            results_cwe[cwe]['tp_vuddy'] += len(set(results[cve]['vuddy']['affected']).intersection(set(results[cve]['groundtruth']['affected'])))
            results_cwe[cwe]['fp_vuddy'] += len(set(results[cve]['vuddy']['affected']).intersection(set(results[cve]['groundtruth']['unaffected'])))
            results_cwe[cwe]['fn_vuddy'] += len(set(results[cve]['vuddy']['unaffected']).intersection(set(results[cve]['groundtruth']['affected'])))
            results_cwe[cwe]['tn_vuddy'] += len(set(results[cve]['vuddy']['unaffected']).intersection(set(results[cve]['groundtruth']['unaffected'])))
            results_cwe[cwe]['tp_v0finder'] += len(set(results[cve]['v0finder']['affected']).intersection(set(results[cve]['groundtruth']['affected'])))
            results_cwe[cwe]['fp_v0finder'] += len(set(results[cve]['v0finder']['affected']).intersection(set(results[cve]['groundtruth']['unaffected'])))
            results_cwe[cwe]['fn_v0finder'] += len(set(results[cve]['v0finder']['unaffected']).intersection(set(results[cve]['groundtruth']['affected'])))
            results_cwe[cwe]['tn_v0finder'] += len(set(results[cve]['v0finder']['unaffected']).intersection(set(results[cve]['groundtruth']['unaffected'])))
            results_cwe[cwe]['tp_visionpro'] += len(set(results[cve]['VisionPro']['affected']).intersection(set(results[cve]['groundtruth']['affected'])))
            results_cwe[cwe]['fp_visionpro'] += len(set(results[cve]['VisionPro']['affected']).intersection(set(results[cve]['groundtruth']['unaffected'])))
            results_cwe[cwe]['fn_visionpro'] += len(set(results[cve]['VisionPro']['unaffected']).intersection(set(results[cve]['groundtruth']['affected'])))
            results_cwe[cwe]['tn_visionpro'] += len(set(results[cve]['VisionPro']['unaffected']).intersection(set(results[cve]['groundtruth']['unaffected'])))
            results_cwe[cwe]['tp_mvp'] += len(set(results[cve]['mvp']['affected']).intersection(set(results[cve]['groundtruth']['affected'])))
            results_cwe[cwe]['fp_mvp'] += len(set(results[cve]['mvp']['affected']).intersection(set(results[cve]['groundtruth']['unaffected'])))
            results_cwe[cwe]['fn_mvp'] += len(set(results[cve]['mvp']['unaffected']).intersection(set(results[cve]['groundtruth']['affected'])))
            results_cwe[cwe]['tn_mvp'] += len(set(results[cve]['mvp']['unaffected']).intersection(set(results[cve]['groundtruth']['unaffected'])))
        try:
            results_cwe[cwe]['precision_vuddy'] = results_cwe[cwe]['tp_vuddy'] / (results_cwe[cwe]['tp_vuddy'] + results_cwe[cwe]['fp_vuddy'])
        except:
            results_cwe[cwe]['precision_vuddy'] = 0
        try:    
            results_cwe[cwe]['recall_vuddy'] = results_cwe[cwe]['tp_vuddy'] / (results_cwe[cwe]['tp_vuddy'] + results_cwe[cwe]['fn_vuddy'])
        except:
            results_cwe[cwe]['recall_vuddy'] = 0
        try:
            results_cwe[cwe]['f1_score_vuddy'] = 2 * results_cwe[cwe]['precision_vuddy'] * results_cwe[cwe]['recall_vuddy'] / (results_cwe[cwe]['precision_vuddy'] + results_cwe[cwe]['recall_vuddy'])
        except:
            results_cwe[cwe]['f1_score_vuddy'] = 0
        
        
        try:
            results_cwe[cwe]['precision_v0finder'] = results_cwe[cwe]['tp_v0finder'] / (results_cwe[cwe]['tp_v0finder'] + results_cwe[cwe]['fp_v0finder'])
        except:
            results_cwe[cwe]['precision_v0finder'] = 0
        try:
            results_cwe[cwe]['recall_v0finder'] = results_cwe[cwe]['tp_v0finder'] / (results_cwe[cwe]['tp_v0finder'] + results_cwe[cwe]['fn_v0finder'])
        except:
            results_cwe[cwe]['recall_v0finder'] = 0
        try:
            results_cwe[cwe]['f1_score_v0finder'] = 2 * results_cwe[cwe]['precision_v0finder'] * results_cwe[cwe]['recall_v0finder'] / (results_cwe[cwe]['precision_v0finder'] + results_cwe[cwe]['recall_v0finder'])
        except:
            results_cwe[cwe]['f1_score_v0finder'] = 0
        try:
            results_cwe[cwe]['precision_visionpro'] = results_cwe[cwe]['tp_visionpro'] / (results_cwe[cwe]['tp_visionpro'] + results_cwe[cwe]['fp_visionpro'])
        except:
            results_cwe[cwe]['precision_visionpro'] = 0
        try:
            results_cwe[cwe]['recall_visionpro'] = results_cwe[cwe]['tp_visionpro'] / (results_cwe[cwe]['tp_visionpro'] + results_cwe[cwe]['fn_visionpro'])
        except:
            results_cwe[cwe]['recall_visionpro'] = 0
        try:
            results_cwe[cwe]['f1_score_visionpro'] = 2 * results_cwe[cwe]['precision_visionpro'] * results_cwe[cwe]['recall_visionpro'] / (results_cwe[cwe]['precision_visionpro'] + results_cwe[cwe]['recall_visionpro'])
        except:
            results_cwe[cwe]['f1_score_visionpro'] = 0
        try:
            results_cwe[cwe]['precision_mvp'] = results_cwe[cwe]['tp_mvp'] / (results_cwe[cwe]['tp_mvp'] + results_cwe[cwe]['fp_mvp'])
        except:
            results_cwe[cwe]['precision_mvp'] = 0
        try:
            results_cwe[cwe]['recall_mvp'] = results_cwe[cwe]['tp_mvp'] / (results_cwe[cwe]['tp_mvp'] + results_cwe[cwe]['fn_mvp'])
        except:
            results_cwe[cwe]['recall_mvp'] = 0
    results_cwe = dict(sorted(results_cwe.items(), key=lambda x: x[1]['cve_num'], reverse=True))
    with open("results_cwe_results.json","w") as f:
        json.dump(results_cwe, f, indent=4)

def get_table_1():
    others = [
        "CWE-190",
        "CWE-125",
        "CWE-369",
        "CWE-416",
        "CWE-122",
        "CWE-617",
        "CWE-20",
        "CWE-119",
        "CWE-22",
        "CWE-366",
        "CWE-384",
        "CWE-680"
        ]
    fp = open("results_cwe_results.json","r")
    results_cwe = json.load(fp)
    fp.close()

    results_true = {}
    for cwe in results_cwe.keys():
        if cwe in others:
            results_true[cwe] = results_cwe[cwe]
            continue
        if "others" not in results_true.keys():
            results_true["others"] = results_cwe[cwe]
        else:
            
            for cve in results_cwe[cwe]['cve_list']:
                if cve not in results_true["others"]['cve_list']:
                    results_true["others"]['cve_list'].append(cve)
            results_true["others"]['cve_num'] += results_cwe[cwe]['cve_num']
            results_true["others"]['tp_vuddy'] += results_cwe[cwe]['tp_vuddy']
            results_true["others"]['fp_vuddy'] += results_cwe[cwe]['fp_vuddy']
            results_true["others"]['fn_vuddy'] += results_cwe[cwe]['fn_vuddy']
            results_true["others"]['tn_vuddy'] += results_cwe[cwe]['tn_vuddy']
            results_true["others"]['tp_v0finder'] += results_cwe[cwe]['tp_v0finder']
            results_true["others"]['fp_v0finder'] += results_cwe[cwe]['fp_v0finder']
            results_true["others"]['fn_v0finder'] += results_cwe[cwe]['fn_v0finder']
            results_true["others"]['tn_v0finder'] += results_cwe[cwe]['tn_v0finder']
            results_true["others"]['tp_visionpro'] += results_cwe[cwe]['tp_visionpro']
            results_true["others"]['fp_visionpro'] += results_cwe[cwe]['fp_visionpro']
            results_true["others"]['fn_visionpro'] += results_cwe[cwe]['fn_visionpro']
            results_true["others"]['tn_visionpro'] += results_cwe[cwe]['tn_visionpro']
            results_true["others"]['tp_mvp'] += results_cwe[cwe]['tp_mvp']
            results_true["others"]['fp_mvp'] += results_cwe[cwe]['fp_mvp']
            results_true["others"]['fn_mvp'] += results_cwe[cwe]['fn_mvp']
            results_true["others"]['tn_mvp'] += results_cwe[cwe]['tn_mvp']
            results_true["others"]['precision_vuddy'] = results_true["others"]['tp_vuddy'] / (results_true["others"]['tp_vuddy'] + results_true["others"]['fp_vuddy'])
            results_true["others"]['recall_vuddy'] = results_true["others"]['tp_vuddy'] / (results_true["others"]['tp_vuddy'] + results_true["others"]['fn_vuddy'])
            results_true["others"]['f1_score_vuddy'] = 2 * results_true["others"]['precision_vuddy'] * results_true["others"]['recall_vuddy'] / (results_true["others"]['precision_vuddy'] + results_true["others"]['recall_vuddy'])
            results_true["others"]['precision_v0finder'] = results_true["others"]['tp_v0finder'] / (results_true["others"]['tp_v0finder'] + results_true["others"]['fp_v0finder'])
            results_true["others"]['recall_v0finder'] = results_true["others"]['tp_v0finder'] / (results_true["others"]['tp_v0finder'] + results_true["others"]['fn_v0finder'])
            results_true["others"]['f1_score_v0finder'] = 2 * results_true["others"]['precision_v0finder'] * results_true["others"]['recall_v0finder'] / (results_true["others"]['precision_v0finder'] + results_true["others"]['recall_v0finder'])
            results_true["others"]['precision_visionpro'] = results_true["others"]['tp_visionpro'] / (results_true["others"]['tp_visionpro'] + results_true["others"]['fp_visionpro'])
            results_true["others"]['recall_visionpro'] = results_true["others"]['tp_visionpro'] / (results_true["others"]['tp_visionpro'] + results_true["others"]['fn_visionpro'])
            results_true["others"]['f1_score_visionpro'] = 2 * results_true["others"]['precision_visionpro'] * results_true["others"]['recall_visionpro'] / (results_true["others"]['precision_visionpro'] + results_true["others"]['recall_visionpro'])
            results_true["others"]['precision_mvp'] = results_true["others"]['tp_mvp'] / (results_true["others"]['tp_mvp'] + results_true["others"]['fp_mvp'])
            results_true["others"]['recall_mvp'] = results_true["others"]['tp_mvp'] / (results_true["others"]['tp_mvp'] + results_true["others"]['fn_mvp'])
            results_true["others"]['f1_score_mvp'] = 2 * results_true["others"]['precision_mvp'] * results_true["others"]['recall_mvp'] / (results_true["others"]['precision_mvp'] + results_true["others"]['recall_mvp'])
    results_true = dict(sorted(results_true.items(), key=lambda x: x[1]['cve_num'], reverse=True))
    with open("results_cwe_results.json","w") as f:
        json.dump(results_true, f, indent=4)


if __name__ == "__main__":
    get_cwe_type_results()
    get_table_1()