import json

# tools = ["github", "gitlab", "snyk", "veracode", "vszz", "vszz+", "verjava_github", "verjava_maven", "vuddy", "v0finder", "our_tool", "our_tool_github"]
tools = ["vszz", "verjava_github", "verjava_maven","v0finder", "MVP", "vuddy", "our_tool", "our_tool_github"]
with open("missingCVE.json", "r") as fr:
    missingCVE = json.load(fr)

with open("results_overview.json", "r") as fr:
    results_overview = json.load(fr)

line_types = ["hybrid", "new"]
line_type_dic = { tool : {each: {"fp": 0, "fn": 0, "tp": 0, "tn": 0, "num":0 } for each in line_types} for tool in tools}

for cve in results_overview:
    for tool in tools:
        hybird_cve = 0
        add_cve = 0
        del_cve = 0
        if tool in results_overview[cve]:
            if cve not in missingCVE:
                line_type_dic[tool]["hybrid"]["num"] += 1
                line_type_dic[tool]["hybrid"]["tp"] += results_overview[cve][tool]["tp"]
                line_type_dic[tool]["hybrid"]["tn"] += results_overview[cve][tool]["tn"]
                line_type_dic[tool]["hybrid"]["fp"] += results_overview[cve][tool]["fp"]
                line_type_dic[tool]["hybrid"]["fn"] += results_overview[cve][tool]["fn"]
            else:
                if results_overview[cve][tool]["tp"] != 0 and tool == "vszz+" and status == "new":
                    print(cve)
                status = missingCVE[cve]
                line_type_dic[tool][status]["num"] += 1
                line_type_dic[tool][status]["tp"] += results_overview[cve][tool]["tp"]
                line_type_dic[tool][status]["tn"] += results_overview[cve][tool]["tn"]
                line_type_dic[tool][status]["fp"] += results_overview[cve][tool]["fp"]
                line_type_dic[tool][status]["fn"] += results_overview[cve][tool]["fn"]

for tool, result in line_type_dic.items():
    print(tool, end=' ')
    for line_type in line_types:
        typenum = result[line_type]["num"]
        type_fp = result[line_type]["fp"]
        type_fn = result[line_type]["fn"]
        type_tp = result[line_type]["tp"]
        type_tn = result[line_type]["tn"]
        type_pre = type_tp / (type_tp + type_fp + 0.0001)
        type_rec = type_tp / (type_tp + type_fn + 0.0001)
        # print(f"& {typenum} & {type_tp} & {type_fp} & {type_fn} & {type_pre:.2f} & {type_rec:.2f} ", end='')
        print(f"& {type_tp} & {type_fp} & {type_fn} & {type_pre:.2f} & {type_rec:.2f} ", end='')
    print("\\\\")
with open("cve_pure.json", "w") as fw:
    json.dump(line_type_dic, fw, indent = 4)
