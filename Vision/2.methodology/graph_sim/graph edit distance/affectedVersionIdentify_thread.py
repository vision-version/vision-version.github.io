import os, json
import subprocess
import logging
from GraphSimCore import simScore
from icecream import ic
from tqdm import tqdm
import multiprocessing
RUNPATH = os.getcwd()
# base
# jarGraphPath = RUNPATH + "/../../patch_featuregraph_generate/jar_graph"
# patchGraphPath = RUNPATH + "/../../patch_featuregraph_generate/weighted_graph"

jarGraphPath = RUNPATH + "/../../patch_featuregraph_generate/critical_jar_graph"
patchGraphPath = RUNPATH + "/../../patch_featuregraph_generate/critical_github_graph"


# jarGraphPath = RUNPATH + "/../../patch_featuregraph_generate/critical_jar_graph_withoutref"
# patchGraphPath = RUNPATH + "/../../patch_featuregraph_generate/critical_github_graph_withoutref"


# jarGraphPath = RUNPATH + "/../../patch_featuregraph_generate/critical_github_graph_withoutcg"
# patchGraphPath = RUNPATH + "/../../patch_featuregraph_generate/critical_github_graph_withoutcg"

# jarGraphPath = RUNPATH + "/../../patch_featuregraph_generate/critical_jar_graph_0.1"
# patchGraphPath = RUNPATH + "/../../patch_featuregraph_generate/critical_github_graph_0.1"



def githubGraphPath(cve:str):
    postPatchGraphPath = os.path.join(patchGraphPath, cve, f"{cve}_new.json")
    prePatchGraphPath = os.path.join(patchGraphPath, cve, f"{cve}_old.json")
    return prePatchGraphPath, postPatchGraphPath

def jarGraphLoad(cve:str):
    jarCVEGraphPath = os.path.join(jarGraphPath, cve)
    all_files = os.listdir(jarCVEGraphPath)
    matched_files = {}
    for file_name in all_files:
        if file_name.startswith(cve) and file_name.endswith(".json"):
            version = "_".join(file_name.lstrip(cve).rstrip(".json").strip("_").split("_")[:-1])
            status = file_name.lstrip(cve).rstrip(".json").strip("_").split("_")[-1]
            if version not in matched_files:
                matched_files[version] = {}
            if status == "old":
                matched_files[version]["old"] = os.path.join(jarCVEGraphPath, file_name)
            if status == "new":
                matched_files[version]["new"] = os.path.join(jarCVEGraphPath, file_name)
    return matched_files

def traverseJarVersion(three_tuple):
    cve, results, cachedunixCoderSim = three_tuple
    ic(cve)
    # ic(dict(results))
    # ic(cachedunixCoderSim)
    prePatchGraphPath, postPatchGraphPath = githubGraphPath(cve)
    matched_files = jarGraphLoad(cve)
    # ic(prePatchGraphPath)
    # ic(postPatchGraphPath)
    # ic(matched_files)
    temp_dict = {}
    
    for jarV, graphPath in matched_files.items():
        # ic(jarV)
        temp_dict[jarV] = {}
        if "old" not in graphPath or "new" not in graphPath:
            continue
        if not os.path.exists(prePatchGraphPath):
            pass
        else:
            simscore, cachedunixCoderSim = simScore(prePatchGraphPath, graphPath["old"], cachedunixCoderSim)
            temp_dict[jarV]["old"] = simscore
        if not os.path.exists(postPatchGraphPath):
            pass
        else:
            simscore, cachedunixCoderSim = simScore(postPatchGraphPath, graphPath["new"], cachedunixCoderSim)
            temp_dict[jarV]["new"] = simscore
    # with open("./cache/unixCoderSim copy.json", "w") as fw:
    #     json.dump(cachedunixCoderSim, fw, indent = 4)
    results[cve] = temp_dict
if __name__ == "__main__":
    # with open("results original.json", "r") as fr:
    #     results = json.load(fr)
    suffix = "hits_0.3"
    results = {}
    with open("./cache/unixCoderSim copy.json", "r") as fr:
        cachedunixCoderSim = json.load(fr)

    cveLst = []

    for item in os.listdir(jarGraphPath):

        full_path = os.path.join(jarGraphPath, item)

        if os.path.isdir(full_path):
   
            cveLst.append(item)


    manager = multiprocessing.Manager()

    shared_dict = manager.dict(results)  
    three_tuple_lst = []
    for i in range(len(cveLst)):
        # if cveLst[i] not in ["CVE-2023-51080"]: continue
        # three_tuple_lst.append((cveLst[i], shared_dict))
        three_tuple_lst.append((cveLst[i], shared_dict, cachedunixCoderSim))


    with multiprocessing.Pool(30) as pool:
        pool.map(traverseJarVersion, three_tuple_lst)
    results = dict(shared_dict)

    sortresults = {}

    for cve, versionResults in results.items():
        vulnerable_versions = []
        fix_versions = []
        unrelated_versions = []

        for v, versionResult in versionResults.items():
            if "old" not in versionResult or "new" not in versionResult: continue
            vulnerable_score = versionResult["old"]
            fix_score = versionResult["new"]
            if vulnerable_score >= 0.6 and vulnerable_score >= fix_score:
                vulnerable_versions.append(v)
            else:
                unrelated_versions.append(v)

        # print(sorted(vulnerable_versions), sorted(fix_versions), sorted(unrelated_versions))
        sortresults[cve] = {
            "affected": sorted(vulnerable_versions),
            "unaffected":sorted(fix_versions) + sorted(unrelated_versions)
        }
    # with open("sortresults_final.json", "w") as fw:
    #     json.dump(sortresults, fw, indent = 4)
    with open(f"sortresults_{suffix}.json", "w") as fw:
        json.dump(sortresults, fw, indent = 4)