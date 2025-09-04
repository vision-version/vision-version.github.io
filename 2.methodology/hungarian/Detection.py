import json
import os
import sys

import cpu_heater
import torch.multiprocessing as mp
from GraphSimCore import compare_wfg, load_wfg_from_dict

sys.path.append("../")
from sim_model.SimilarityService import SimilarityService

TARGET = "/path/to/target"
SIGNATURE = "/path/to/signature"
RESULT_CACHE = "/path/to/results"


def detect(target, cve):
    results = {}
    results[target] = {}
    results[target][cve] = {}
    fp = open(f"{SIGNATURE}/{cve}/graph_cluster.json")
    signature = json.load(fp)
    fp.close()

    fp = open(f"{TARGET}/{cve}/graph_cluster.json")
    target_pre = json.load(fp)
    fp.close()
    pre = 0
    post = 0
    target_pre_cluster = target_pre["pre"]
    target_post_cluster = target_pre["post"]
    for sig_graph_cluster in signature["pre"]:
        if sig_graph_cluster is None:
            continue

        wfg1 = load_wfg_from_dict(sig_graph_cluster)
        for target_graph_cluster in target_pre_cluster:
            if target_graph_cluster is None:
                continue

            wfg2 = load_wfg_from_dict(target_graph_cluster)

            if wfg1 == None or wfg2 == None:
                results[target][cve] = "pre sim error"
                return results

            pre_score = compare_wfg(wfg1, wfg2)
            if pre_score >= 0.6:
                pre += 1
                target_pre_cluster.remove(target_graph_cluster)

    if pre / len(signature["pre"]) < 0.7:
        results[target][cve]["label"] = "not vul"
    else:
        for sig_graph_cluster in signature["post"]:
            if sig_graph_cluster is None:
                continue

            wfg1 = load_wfg_from_dict(sig_graph_cluster)
            for target_graph_cluster in target_post_cluster:
                if target_graph_cluster is None:
                    continue

                wfg2 = load_wfg_from_dict(target_graph_cluster)

                if wfg1 == None or wfg2 == None:
                    results[target][cve] = "pre sim error"
                    return results

                pre_score = compare_wfg(wfg1, wfg2)
                if pre_score >= 0.6:
                    post += 1
                    target_post_cluster.remove(target_graph_cluster)
        if post / len(signature["post"]) < 0.7:
            results[target][cve]["label"] = "vul"
        else:
            results[target][cve]["label"] = "not vul"

    return results


def work_fn(
    repoName,
    cve,
    before_origin_code,
    after_origin_code,
    target_code,
    similarity_service,
    origin_name,
    target_name,
):
    pre = similarity_service.calculate_similarity(before_origin_code, target_code)
    post = similarity_service.calculate_similarity(after_origin_code, target_code)
    pre_post = similarity_service.calculate_similarity(
        after_origin_code, before_origin_code
    )
    return repoName, cve, pre, post, pre_post


def get_whole_func_similarity(tar, cve):
    fp = open("transfer_code.json")
    target = json.load(fp)
    fp.close()

    fp = open("cve_origin_code.json")
    extract = json.load(fp)
    fp.close()
    results = {}
    similarity_service = SimilarityService()
    cnt = 0
    worker_list = []
    for target_repo in target[cve]:
        repo = target_repo.split("##")[1]
        tag = target_repo.split("##")[2]
        repoName = f"{repo}-{tag.replace('/','_')}"
        if repoName != tar:
            continue
        if repoName not in results:
            results[repoName] = {}
        if cve not in results[repoName]:
            results[repoName][cve] = {}
        target_method = target_repo.split("##")[3]
        origin_method = target_repo.split("##")[4]
        for patch_method in extract[cve]["patch"]:
            method_name = patch_method.split("#")[1]
            if method_name == origin_method.replace("void", "").replace(
                "int", ""
            ).replace("static", ""):
                worker_list.append(
                    (
                        repoName,
                        cve,
                        extract[cve]["patch"][patch_method]["before_func_code"],
                        extract[cve]["patch"][patch_method]["after_func_code"],
                        target[cve][target_repo],
                        similarity_service,
                        method_name,
                        target_method,
                    )
                )

    mp.set_start_method("spawn", force=True)
    returns = cpu_heater.multithreads(
        work_fn, worker_list, max_workers=128, show_progress=True
    )

    for res in returns:
        repoName, cve, pre, post, pre_post = res
        if repoName not in results:
            results[repoName] = {}
        if cve not in results[repoName]:
            results[repoName][cve] = {}
        try:
            results[repoName][cve]["score"].append(
                {"pre": pre, "post": post, "pre_post": pre_post}
            )
        except:
            results[repoName][cve]["score"] = [
                {"pre": pre, "post": post, "pre_post": pre_post}
            ]
        if pre >= post and pre >= 0.9 and post <= pre_post:
            results[repoName][cve]["label"] = "vul"

    return results


if __name__ == "__main__":
    tar = sys.argv[1]
    results = {}
    results[tar] = {}
    for cve in os.listdir(f"{TARGET}/{tar}"):
        results[tar][cve] = {}
        results.update(get_whole_func_similarity(tar, cve))
        if results[tar]["label"] == "not vul":
            results.update(detect(tar, cve))

    with open(f"{RESULT_CACHE}/{tar}/results.json", "w") as fp:
        json.dump(results, fp, indent=4)
