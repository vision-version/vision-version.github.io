import json
import os
from icecream import ic
import re
def githubVersionPreProcess(versions):
    for version_index, version_contnet in enumerate(versions):

        # pattern = re.compile(r'^[a-zA-Z]+-')

        # version_contnet = re.sub(pattern, '', version_contnet)
        preVersion = version_contnet.replace("netty-", "").replace("rel/v", "").replace("jackson-databind-", "").replace("r1rv","1.").replace("commons-","").replace("junrar-", "").strip("v").replace("fileupload-","").replace("maven-shared-utils-", "").replace("pac4j-", "").replace("json-sanitizer-", "").replace("release-","").replace("commons-","").replace("REL_",  "").replace("XSTREAM_", "")
        preVersion = preVersion.replace("FILEUPLOAD_", "").replace("_", ".").replace("commons-fileupload-", "")
        preVersion = preVersion.lower()
        versions[version_index] = preVersion
        
    return list(set(versions))

def versionCompare(gt_versions, tool_versions):

    correct_matches = set(gt_versions) & set(tool_versions)
    # ic(gt_versions)
    # ic(tool_versions)

    precision = len(correct_matches) / len(tool_versions) if len(tool_versions) > 0 else 0.0
    

    recall = len(correct_matches) / len(gt_versions) if len(gt_versions) > 0 else 0.0
    
    return len(correct_matches), precision, recall

def toolEval(tool, cve_baseline, tagged_gts):
    pre_cve = 0
    recall_cve = 0
    cve_num = 0
    
    correct_version_num = 0
    gt_versions_num = 0
    tool_versions_num = 0
    
    nottagged_cves = []
    notool_cves = []
    for cve in tagged_gts:  
        # if cve !=   "CVE-2022-22976": continue      
        # ic(cve)
        if "gt_branch" not in tagged_gts[cve] or not any (tagged_gts[cve]["gt_branch"]): 
            nottagged_cves.append(cve)
            continue
        if tool not in cve_baseline[cve]:
            notool_cves.append(cve)
            continue

        # if not any(cve_baseline[cve][tool]) or cve_baseline[cve][tool][0] == "No earliest induce commit found":
        #     notool_cves.append(cve)
        #     continue
   
        tool_versions = cve_baseline[cve][tool]
        tool_versions = githubVersionPreProcess(tool_versions)
        affected_versions = []

        
        branches = tagged_gts[cve]["gt_branch"]
        for branch_name in branches:
            affected_versions += branches[branch_name]
        affected_versions = githubVersionPreProcess(affected_versions)
        # ic(affected_versions)
        correct_matches, precision, recall= versionCompare(affected_versions, tool_versions)
        cve_num += 1
        recall_cve += recall
        pre_cve += precision
        
        correct_version_num += correct_matches
        gt_versions_num += len(list(set(affected_versions)))
        tool_versions_num += len(list(set(tool_versions)))
    # ic(nottagged_cves)
    # ic(notool_cves)
    print(f"{tool} pre_cve is {pre_cve* 1.0/cve_num}, recall_cve is {recall_cve * 1.0/cve_num}, pre_version is {correct_version_num * 1.0 / tool_versions_num}, recall_version is {correct_version_num * 1.0 / gt_versions_num}")

def main():
    with open("cve_analysis_baseline.json", "r") as fr:
        cve_baseline = json.load(fr)

    with open("cve_analysis.json", "r") as fr:
        tagged_gts = json.load(fr)
    toolEval("verjava-jar", cve_baseline, tagged_gts)
    toolEval("verjava-git", cve_baseline, tagged_gts)
    toolEval("vszz-5", cve_baseline, tagged_gts)
    toolEval("vszz", cve_baseline, tagged_gts)

if __name__ == "__main__":
    main()
    