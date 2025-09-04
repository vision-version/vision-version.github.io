import json
import logging
import os
import subprocess
import sys
import time
from re import L

import cpu_heater
from tqdm import tqdm

import code_transformation
import format_code
import joern
from ast_parser import ASTParser
from codefile import CodeFile, create_code_tree
from common import Language
from json2dot import convert_to_dot
from patch import Patch
from project import Method, Project
from split_clusters import split_clusters
from target import Target

SAGA_CACHE_DIR = "path/to/filemap/cache"
VULFILECACHE = "/path/to/vulFile"
REPO_PATH = "/path/to/target/repo"
FILE_MAPPING = "/path/to/filemap"
METHOD_MAPPING = "/path/to/methodmap"
LINE_MAPPING = "/path/to/linemap"
SIGNATURE_REPO_PATH = "/path/to/signature/repo"
TARGET_SLICING = "/path/to/target/slicing"
JOERN_PATH = "/path/to/joern"


def levenshtein_distance(str1, str2):
    m = len(str1)
    n = len(str2)

    dp = [[0] * (n + 1) for _ in range(m + 1)]

    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if str1[i - 1] == str2[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]
            else:
                dp[i][j] = min(dp[i - 1][j - 1], dp[i][j - 1], dp[i - 1][j]) + 1

    distance = dp[m][n]
    max_length = max(m, n)
    similarity = 1 - distance / max_length
    return similarity


def filemapping_matching(repo_path, language):
    repoName = repo_path.split("/")[-1]
    cache_exists = False
    repo_file_cve_map = {}
    if os.path.exists(f"{SAGA_CACHE_DIR}/{repoName}/saga_time.json"):
        try:
            cache_exists = True
        except:
            cache_exists = False

    if not cache_exists:
        if os.path.exists(f"cache/{repo_path.split('/')[-1]}"):
            os.system(f"rm -r cache/{repo_path.split('/')[-1]}")
        result = subprocess.check_output(
            f"mkdir -pv cache/{repo_path.split('/')[-1]}",
            stderr=subprocess.STDOUT,
            shell=True,
        ).decode("utf-8", errors="replace")
        if language == Language.CPP:
            result = subprocess.check_output(
                f"cp -r saga cache/{repo_path.split('/')[-1]}",
                stderr=subprocess.STDOUT,
                shell=True,
            ).decode("utf-8", errors="replace")
        elif language == Language.JAVA:
            result = subprocess.check_output(
                f"cp -r saga-java cache/{repo_path.split('/')[-1]}",
                stderr=subprocess.STDOUT,
                shell=True,
            ).decode("utf-8", errors="replace")

        os.chdir(f"{SAGA_CACHE_DIR}/{repo_path.split('/')[-1]}/saga")
        os.system("rm -r ./logs")
        os.system("rm -r ./result")
        os.system("rm -r ./tokenData")
        if os.path.exists(f"{repo_path}/vulFile"):
            os.system(f"rm -r {repo_path}/vulFile")
        result = (
            subprocess.check_output("cp -r " + VULFILECACHE + repo_path, shell=True)
            .decode("utf-8", errors="replace")
            .strip()
        )
        subprocess.check_output(
            "java -jar ./SAGACloneDetector-small.jar " + repo_path, shell=True
        ).decode("utf-8", errors="replace").strip()
        os.system(f"rm -r {repo_path}/vulFile")
    fileIndex = {}
    index_file_map = {}
    CVE_dict = {}
    CVE_dict_line_number = {}
    file_hash_line_number_to_index_dict = {}
    with open(
        "/infoFile/sagaMulti.json",
        "r",
    ) as f:
        cves = json.load(f)
        for cve in cves:
            CVE_dict[cve] = cves[cve]
    os.chdir(f"{SAGA_CACHE_DIR}/{repo_path.split('/')[-1]}/saga")
    with open("./result/MeasureIndex.csv", "r") as f:
        lines = f.readlines()
        for line in lines:
            id = line.split(",")[0]
            fileName = line.split(",")[1]
            endLine = line.split(",")[-1]
            startLine = line.split(",")[-2]
            fileIndex[id] = fileName
            if "vulFile" in fileName:
                file_hash = fileName.split("/")[-1]
                file_hash_line_number_to_index_dict[
                    file_hash + "__split__" + endLine.strip()
                ] = id
            index_file_map[id] = [startLine, endLine]

    for CVE in CVE_dict.keys():
        CVE_dict_line_number[CVE] = []
        for ele in CVE_dict[CVE].keys():
            for name in CVE_dict[CVE][ele].keys():
                if (
                    CVE_dict[CVE][ele][name]["lineEnd"]
                    - CVE_dict[CVE][ele][name]["lineStart"]
                    <= 2
                ):
                    continue
                if (
                    ele + "__split__" + str(CVE_dict[CVE][ele][name]["lineEnd"])
                    in file_hash_line_number_to_index_dict.keys()
                ):
                    CVE_dict_line_number[CVE].append(
                        file_hash_line_number_to_index_dict[
                            ele + "__split__" + str(CVE_dict[CVE][ele][name]["lineEnd"])
                        ]
                    )
    zero_CVE_set = set()
    for CVE in CVE_dict_line_number.keys():
        if len(CVE_dict_line_number[CVE]) == 0:
            zero_CVE_set.add(CVE)
    for CVE in zero_CVE_set:
        del CVE_dict_line_number[CVE]

    clone_dict = {}
    with open("./result/type12_snippet_result.csv", "r", encoding="utf8") as f:
        lines = f.readlines()
        i = 0
        while i < len(lines):
            temp = i
            while temp < len(lines) and lines[temp] != "\n":
                temp += 1
            repo_set = set()
            clone_set = set()
            for cur in range(i, temp):
                file_name = fileIndex[lines[cur].split(",")[1]]
                if "vulFile" in file_name:
                    clone_set.add(lines[cur].split(",")[1])
                else:
                    repo_set.add(lines[cur].split(",")[1])

            for id in clone_set:
                if id not in clone_dict.keys():
                    clone_dict[id] = set()
                for repo_id in repo_set:
                    clone_dict[id].add(repo_id)
            i = temp + 1
    i = 0
    with open("./result/type3_snippet_result.csv", "r", encoding="utf8") as f:
        lines = f.readlines()
        i = 0
        while i < len(lines):
            temp = i
            while temp < len(lines) and lines[temp] != "\n":
                temp += 1
            repo_set = set()
            clone_set = set()
            for cur in range(i, temp):
                file_name = fileIndex[lines[cur].split(",")[1]]
                if "vulFile" in file_name:
                    clone_set.add(lines[cur].split(",")[1])
                else:
                    repo_set.add(lines[cur].split(",")[1])

            for id in clone_set:
                if id not in clone_dict.keys():
                    clone_dict[id] = set()
                for repo_id in repo_set:
                    clone_dict[id].add(repo_id)
            i = temp + 1
    filtered_dict = dict()
    filtered_file_set = set()
    for cve in CVE_dict_line_number.keys():
        file_set = set()
        for id in CVE_dict_line_number[cve]:
            if id in clone_dict.keys():
                for clone_id in clone_dict[id]:
                    file_name = fileIndex[clone_id]
                    if "vulFile" not in file_name:
                        file_set.add(file_name)
                        filtered_file_set.add(file_name)
                        if cve not in repo_file_cve_map:
                            repo_file_cve_map[cve] = {}
                        if file_name not in repo_file_cve_map[cve]:
                            repo_file_cve_map[cve][file_name] = {}
                            repo_file_cve_map[cve][file_name] = {}

                        repo_file_cve_map[cve][file_name][
                            f"{index_file_map[clone_id][0]}__split__{index_file_map[clone_id][1].strip()}"
                        ] = f"{fileIndex[id]}__split__{index_file_map[id][0]}__split__{index_file_map[id][1].strip()}"

        if len(file_set) != 0:
            filtered_dict[cve] = list(file_set)

    return repo_file_cve_map


def get_repo_file_mapping(tar, language):
    repo_file_mapping = {}
    repo_path = f"{REPO_PATH}/{tar}"
    repo_file_mapping[tar] = filemapping_matching(repo_path, language)
    fp = open(f"{FILE_MAPPING}/repo_file_mapping_{tar}.json", "w")
    json.dump(repo_file_mapping, fp, indent=4)
    fp.close()


def get_pre_post_methods(
    patch: Patch, pre_post_projects: tuple[Project, Project], signature: str
):
    pre_project, post_project = pre_post_projects

    pre_method = pre_project.get_method(signature)
    if signature in patch.change_method_map_dict.keys():
        post_method = post_project.get_method(
            patch.change_method_map_dict[signature][0]
        )
    else:
        post_method = post_project.get_method(signature)
    if pre_method is None:
        return
    if post_method is None:
        return
    return pre_method, post_method


def extract_cve_patch_info(worker_id, cve, dataset, language):
    error_code = {}
    error_code[cve] = {}
    patch_info = {}
    patch_info[cve] = {}
    try:
        repo = os.path.join(
            SIGNATURE_REPO_PATH,
            dataset[cve]["repo"].replace("https://github.com/", "").replace("/", "@@")
            + "_"
            + cve,
        )
        try:
            patch = Patch(f"{repo}", dataset[cve]["commitId"], language)
        except Exception as e:
            error_code[cve]["summary"] = "Patch failed"
            error_code[cve]["detail"] = str(e)
            return error_code, worker_id, patch_info
        try:
            pre_post_projects = (patch.pre_project, patch.post_project)
        except Exception as e:
            error_code[cve]["summary"] = "Project failed"
            error_code[cve]["detail"] = str(e)
            return error_code, worker_id, patch_info
        try:
            for method_signature in patch.changed_methods:
                if method_signature == "ttssh2/ttxssh/ssh.c#handle_pty_failure":
                    continue
                pre_post_method = get_pre_post_methods(
                    patch, pre_post_projects, method_signature
                )
                if pre_post_method is None:
                    continue
                pre_method, post_method = pre_post_method
                pre_method.counterpart = post_method
                post_method.counterpart = pre_method
                patch_info[cve][method_signature] = {}
                patch_info[cve][method_signature]["deleteline"] = {}
                patch_info[cve][method_signature]["addline"] = {}
                patch_info[cve][method_signature]["deletemethod"] = {}
                patch_info[cve][method_signature]["addmethod"] = {}
                for line in pre_method.diff_lines:
                    patch_info[cve][method_signature]["deleteline"][line] = {}
                    patch_info[cve][method_signature]["deleteline"][line]["code"] = (
                        pre_method.lines[line]
                    )
                    patch_info[cve][method_signature]["deleteline"][line][
                        "abs_code"
                    ] = pre_method.abs_lines[line]
                for line in post_method.diff_lines:
                    patch_info[cve][method_signature]["addline"][line] = {}
                    patch_info[cve][method_signature]["addline"][line]["code"] = (
                        post_method.lines[line]
                    )
                    patch_info[cve][method_signature]["addline"][line]["abs_code"] = (
                        post_method.abs_lines[line]
                    )
                for line in pre_method.lines:
                    patch_info[cve][method_signature]["deletemethod"]["code"] = (
                        pre_method.lines
                    )
                    patch_info[cve][method_signature]["deletemethod"]["abs_code"] = (
                        pre_method.abs_lines
                    )
                    patch_info[cve][method_signature]["addmethod"]["code"] = (
                        post_method.lines
                    )
                    patch_info[cve][method_signature]["addmethod"]["abs_code"] = (
                        post_method.abs_lines
                    )
        except Exception as e:
            error_code[cve]["summary"] = "diff line failed"
            error_code[cve]["detail"] = str(e)
            return error_code, worker_id, patch_info

    except Exception as e:
        error_code[cve]["summary"] = "Overall failed"
        error_code[cve]["detail"] = str(e)
        return error_code, worker_id, patch_info
    error_code[cve]["summary"] = "SUCCESS"
    error_code[cve]["detail"] = "SUCCESS"
    return error_code, worker_id, patch_info


def get_cve_patch_info(language):
    if language == Language.CPP:
        file_path = "empirical/dataset/emperical_cve_list.json"
    elif language == Language.JAVA:
        file_path = "empirical/dataset/dataset_java.json"
    fp = open(file_path)
    dataset = json.load(fp)
    fp.close()

    fp = open("patch_info.json")
    patch_info = json.load(fp)
    fp.close()

    time1 = time.time()
    flag = False

    worker_list = []

    errors = {}
    for cve in tqdm(dataset):
        worker_list.append((cve, cve, dataset, language))

    results = cpu_heater.multiprocess(
        extract_cve_patch_info,
        worker_list,
        max_workers=256,
        show_progress=True,
        timeout=1800,
    )
    finished = set()
    for error_code, worker_id, res in tqdm(results):
        for cve in error_code:
            errors[cve] = {}
            for key in error_code[cve]:
                errors[cve][key] = str(error_code[cve][key])
        patch_info.update(res)
        finished.add(worker_id)

    fp = open("patch_info.json", "w")
    json.dump(patch_info, fp, indent=4)
    fp.close()

    fp = open("error_cve_patch_info.json", "w")
    json.dump(errors, fp, indent=4)
    fp.close()


def worker_fn(cve, file, repo_file_mapping, repoName, CVE_dict, language):
    repo_method_mapping = {}
    repo_method_mapping[cve] = {}
    repo_method_mapping[cve][file] = {}
    fp = open(file)
    file_code = fp.read()
    fp.close()
    codefile = CodeFile(file, file_code, isformat=False)
    target_project = Project(f"target", [codefile], language)
    for st_ed in repo_file_mapping[repoName][cve][file]:
        st = int(st_ed.split("__split__")[0])
        ed = int(st_ed.split("__split__")[1])
        target_method = ""
        for method_signature in target_project.methods_signature_set:
            method = target_project.get_method(method_signature)
            if method is None:
                continue
            if st >= method.start_line and ed <= method.end_line:
                target_method = method_signature
                break
        if target_method == "":
            continue
        vul_file = (
            repo_file_mapping[repoName][cve][file][st_ed]
            .split("__split__")[0]
            .split("/")[-1]
        )
        vul_st = int(
            repo_file_mapping[repoName][cve][file][st_ed].split("__split__")[1]
        )
        vul_ed = int(
            repo_file_mapping[repoName][cve][file][st_ed].split("__split__")[2]
        )
        vul_method = ""
        for method in CVE_dict[cve][vul_file]:
            if (
                vul_st >= CVE_dict[cve][vul_file][method]["lineStart"]
                and vul_ed <= CVE_dict[cve][vul_file][method]["lineEnd"]
            ):
                vul_method = method.split("(")[0]
                break
        if vul_method == "":
            continue
        repo_method_mapping[cve][file][target_method] = vul_method

    return repo_method_mapping


def method_mapping_matching(repo_path, language):
    repoName = repo_path.split("/")[-1]

    fp = open(f"{FILE_MAPPING}/repo_file_mapping_{repoName}.json", "w")
    repo_file_mapping = json.load(fp)
    fp.close()

    CVE_dict = {}
    repo_method_mapping = {}

    with open(
        "./infoFile/sagaMulti.json",
        "r",
    ) as f:
        cves = json.load(f)
        for cve in cves:
            CVE_dict[cve] = cves[cve]

    if repoName not in repo_file_mapping:
        return None

    worker_list = []
    for cve in repo_file_mapping[repoName]:
        repo_method_mapping[cve] = {}
        for file in repo_file_mapping[repoName][cve]:
            worker_list.append(
                (cve, file, repo_file_mapping, repoName, CVE_dict, language)
            )

    results = cpu_heater.multiprocess(worker_fn, worker_list, show_progress=True)
    for res in results:
        repo_method_mapping.update(res)

    return repo_method_mapping


def get_repo_method_mapping(tar, language):
    repo_path = f"{REPO_PATH}/{tar}"
    repo_method_mapping = {}
    method_mapping = method_mapping_matching(repo_path, language)
    repo_method_mapping[tar] = method_mapping

    fp = open(f"{METHOD_MAPPING}/repo_method_mapping_{tar}.json", "w")
    json.dump(repo_method_mapping, fp, indent=4)
    fp.close()


def line_mapping_matching(repo_path, language):
    repoName = repo_path.split("/")[-1]
    error_code = {}
    error_code[repo_path] = {}

    fp = open(f"{METHOD_MAPPING}/repo_method_mapping_{repoName}.json")
    repo_method_mapping = json.load(fp)
    fp.close()

    repo_line_mapping = {}
    fp = open("patch_info.json")
    patch_info = json.load(fp)
    fp.close()

    if repoName not in repo_method_mapping:
        error_code[repo_path]["summary"] = "not exists in GT"
        error_code[repo_path]["detail"] = "not exists in GT"
        return None, error_code

    worker_list = []
    error_code = {}
    error_code[repo_path] = {}
    for cve in repo_method_mapping[repoName]:
        repo_line_mapping[cve] = {}
        error_code[repo_path][cve] = {}
        for origin_method in repo_method_mapping[repoName][cve]:
            error_code[repo_path][cve][origin_method] = {}
            target_method_info = ""
            true_target_method = None
            patch_method_info = patch_info[cve][origin_method]
            if len(repo_method_mapping[repoName][cve][origin_method]) == 1:
                target_method_info = repo_method_mapping[repoName][cve][origin_method][
                    0
                ]
                file = target_method_info.split("#")[0]
                if not os.path.exists(os.path.join(repo_path, file)):
                    error_code[repo_path][cve][origin_method]["summary"] = (
                        "target_project error"
                    )
                    error_code[repo_path][cve][origin_method]["detail"] = (
                        "target_project error"
                    )
                    continue
                fp = open(os.path.join(repo_path, file), errors="ignore")
                file_code = fp.read()
                fp.close()
                codefiles = []
                extracted_macros_codes = code_transformation.extraction_macros(
                    file_code, repo_path, file
                )
                assert extracted_macros_codes is not None
                source_code_before = code_transformation.code_transformation(
                    extracted_macros_codes, language
                )
                source_code_before = extracted_macros_codes
                codefile = CodeFile(file, source_code_before, isformat=False)
                codefiles.append(codefile)
                try:
                    target_project = Project(f"target", codefiles, language)
                except Exception as e:
                    error_code[repo_path][cve][origin_method]["summary"] = (
                        "target_project error"
                    )
                    error_code[repo_path][cve][origin_method]["detail"] = str(e)
                    continue
                true_target_method = target_project.get_method(target_method_info)
            else:
                max_score_sum = 0.0
                min_score_sum = 65536
                fileList = set()
                for target_method in repo_method_mapping[repoName][cve][origin_method]:
                    file = target_method.split("#")[0]
                    if not os.path.exists(os.path.join(repo_path, file)):
                        continue
                    if (
                        target_method.split("#")[1].lower()
                        == origin_method.split("#")[1].lower()
                    ):
                        target_method_info = target_method
                        fp = open(os.path.join(repo_path, file), errors="ignore")
                        file_code = fp.read()
                        fp.close()
                        codefiles = []
                        extracted_macros_codes = code_transformation.extraction_macros(
                            file_code, repo_path, file
                        )
                        assert extracted_macros_codes is not None
                        source_code_before = code_transformation.code_transformation(
                            extracted_macros_codes, language
                        )
                        codefile = CodeFile(
                            file, extracted_macros_codes, isformat=False
                        )
                        codefiles.append(codefile)
                        try:
                            target_project = Project(f"target", codefiles, language)
                        except Exception as e:
                            error_code[repo_path][cve][origin_method]["summary"] = (
                                "target_project error"
                            )
                            error_code[repo_path][cve][origin_method]["detail"] = str(e)
                            continue
                        true_target_method = target_project.get_method(
                            target_method_info
                        )
                        break
                    fileList.add(file)
                if target_method_info == "":
                    codefiles = []
                    for file in fileList:
                        fp = open(os.path.join(repo_path, file), errors="ignore")
                        file_code = fp.read()
                        fp.close()
                        extracted_macros_codes = code_transformation.extraction_macros(
                            file_code, repo_path, file
                        )
                        assert extracted_macros_codes is not None
                        source_code_before = code_transformation.code_transformation(
                            extracted_macros_codes, language
                        )
                        codefile = CodeFile(
                            file, extracted_macros_codes, isformat=False
                        )
                        codefiles.append(codefile)
                    try:
                        target_project = Project(f"target", codefiles, language)
                    except Exception as e:
                        error_code[repo_path][cve][origin_method]["summary"] = (
                            "target_project error"
                        )
                        error_code[repo_path][cve][origin_method]["detail"] = str(e)
                        continue
                    for method_signature in repo_method_mapping[repoName][cve][
                        origin_method
                    ]:
                        target_method = target_project.get_method(method_signature)
                        if target_method is None:
                            continue
                        score_sum = 0.0
                        delete_line = patch_info[cve][origin_method]["deleteline"]
                        delete_methods = patch_info[cve][origin_method]["deletemethod"][
                            "abs_code"
                        ]
                        for line in delete_line:
                            if delete_line[line]["abs_code"].strip().replace(
                                " ", ""
                            ) in ["", "(", ")", "{", "}"]:
                                continue
                            if delete_line[line]["abs_code"].strip().replace(
                                ";", ""
                            ) in ["continue", "return", "break"]:
                                delete_methods_lines = [
                                    int(x) for x in delete_methods.keys()
                                ]
                                min_patch_method_line = sorted(delete_methods_lines)[0]
                                max_patch_method_line = sorted(delete_methods_lines)[-1]
                                st_patch = (
                                    min_patch_method_line
                                    if int(line) - 2 < min_patch_method_line
                                    else int(line) - 2
                                )
                                ed_patch = (
                                    max_patch_method_line
                                    if int(line) + 2 > max_patch_method_line
                                    else int(line) + 2
                                )
                                patch_code = ""
                                for i in range(st_patch, ed_patch + 1):
                                    patch_code += delete_methods[str(i)]
                            else:
                                patch_code = delete_line[line]["abs_code"]

                            max_score = 0.0
                            for l in target_method.abs_lines:
                                if target_method.abs_lines[l].strip().replace(
                                    " ", ""
                                ) in ["", "(", ")", "{", "}"]:
                                    continue
                                if delete_line[line]["abs_code"].strip().replace(
                                    ";", ""
                                ) in ["continue", "return", "break"]:
                                    st = (
                                        target_method.start_line
                                        if l - 2 < target_method.start_line
                                        else l - 2
                                    )
                                    ed = (
                                        target_method.start_line
                                        if l + 2 > target_method.end_line
                                        else l + 2
                                    )
                                    target_code = ""
                                    for i in range(st, ed + 1):
                                        target_code += target_method.abs_lines[i]
                                else:
                                    target_code = target_method.abs_lines[l]
                                sim = levenshtein_distance(target_code, patch_code)
                                if sim > max_score:
                                    max_score = sim
                            score_sum += max_score
                        if score_sum > max_score_sum:
                            max_score_sum = score_sum
                            target_method_info = method_signature
                            true_target_method = target_method

                    if true_target_method is None:
                        for method_signature in repo_method_mapping[repoName][cve][
                            origin_method
                        ]:
                            target_method = target_project.get_method(method_signature)
                            if target_method is None:
                                continue
                            score_sum = 0.0
                            add_line = patch_info[cve][origin_method]["addline"]
                            delete_methods = patch_info[cve][origin_method][
                                "addmethod"
                            ]["abs_code"]
                            for line in add_line:
                                if add_line[line]["abs_code"].strip().replace(
                                    " ", ""
                                ) in ["", "(", ")", "{", "}"]:
                                    continue
                                if add_line[line]["abs_code"].strip().replace(
                                    ";", ""
                                ) in ["continue", "return", "break"]:
                                    delete_methods_lines = [
                                        int(x) for x in delete_methods.keys()
                                    ]
                                    min_patch_method_line = sorted(
                                        delete_methods_lines
                                    )[0]
                                    max_patch_method_line = sorted(
                                        delete_methods_lines
                                    )[-1]
                                    st_patch = (
                                        min_patch_method_line
                                        if int(line) - 2 < min_patch_method_line
                                        else int(line) - 2
                                    )
                                    ed_patch = (
                                        max_patch_method_line
                                        if int(line) + 2 > max_patch_method_line
                                        else int(line) + 2
                                    )
                                    patch_code = ""
                                    for i in range(st_patch, ed_patch + 1):
                                        patch_code += delete_methods[str(i)]
                                else:
                                    patch_code = add_line[line]["abs_code"]

                                max_score = 0.0
                                for l in target_method.abs_lines:
                                    if target_method.abs_lines[l].strip().replace(
                                        " ", ""
                                    ) in ["", "(", ")", "{", "}"]:
                                        continue
                                    if add_line[line]["abs_code"].strip().replace(
                                        ";", ""
                                    ) in ["continue", "return", "break"]:
                                        st = (
                                            target_method.start_line
                                            if l - 2 < target_method.start_line
                                            else l - 2
                                        )
                                        ed = (
                                            target_method.start_line
                                            if l + 2 > target_method.end_line
                                            else l + 2
                                        )
                                        target_code = ""
                                        for i in range(st, ed + 1):
                                            target_code += target_method.abs_lines[i]
                                    else:
                                        target_code = target_method.abs_lines[l]
                                    sim = levenshtein_distance(target_code, patch_code)
                                    if sim > max_score:
                                        max_score = sim
                                score_sum += max_score
                            if score_sum < min_score_sum:
                                min_score_sum = score_sum
                                target_method_info = method_signature
                                true_target_method = target_method

            if true_target_method is None:
                error_code[repo_path][cve][origin_method]["summary"] = (
                    "target method error"
                )
                error_code[repo_path][cve][origin_method]["detail"] = (
                    "target method error"
                )
                continue
            file = target_method_info.split("#")[0]
            if file not in repo_line_mapping[cve]:
                repo_line_mapping[cve][file] = {}

            try:
                repo_line_mapping[cve][file][target_method_info] = {}
                repo_line_mapping[cve][file][target_method_info]["deleteline"] = []
                repo_line_mapping[cve][file][target_method_info]["addline"] = []
                delete_line = patch_method_info["deleteline"]
                add_line = patch_method_info["addline"]
                delete_methods = patch_method_info["deletemethod"]["abs_code"]
                add_methods = patch_method_info["addmethod"]["abs_code"]
                max_score = 0.0
                for line in delete_line:
                    if delete_line[line]["abs_code"].strip().replace(" ", "") in [
                        "",
                        "(",
                        ")",
                        "{",
                        "}",
                    ]:
                        continue
                    linecontentMap = {
                        "linemap": (int(line), None),
                        "contentmap": (line, None),
                        "similarity": max_score,
                        "patch_method": origin_method,
                    }
                    if delete_line[line]["abs_code"].strip().replace(";", "") in [
                        "continue",
                        "return",
                        "break",
                    ]:
                        delete_methods_lines = [int(x) for x in delete_methods.keys()]
                        min_patch_method_line = sorted(delete_methods_lines)[0]
                        max_patch_method_line = sorted(delete_methods_lines)[-1]
                        st_patch = (
                            min_patch_method_line
                            if int(line) - 2 < min_patch_method_line
                            else int(line) - 2
                        )
                        ed_patch = (
                            max_patch_method_line
                            if int(line) + 2 > max_patch_method_line
                            else int(line) + 2
                        )
                        patch_code = ""
                        for i in range(st_patch, ed_patch + 1):
                            patch_code += delete_methods[str(i)]
                    else:
                        patch_code = delete_line[line]["abs_code"]

                    max_score = 0.0
                    for l in true_target_method.abs_lines:
                        if true_target_method.abs_lines[l].strip().replace(" ", "") in [
                            "",
                            "(",
                            ")",
                            "{",
                            "}",
                        ]:
                            continue
                        if delete_line[line]["abs_code"].strip().replace(";", "") in [
                            "continue",
                            "return",
                            "break",
                        ]:
                            st = (
                                true_target_method.start_line
                                if l - 2 < true_target_method.start_line
                                else l - 2
                            )
                            ed = (
                                true_target_method.start_line
                                if l + 2 > true_target_method.end_line
                                else l + 2
                            )
                            target_code = ""
                            for i in range(st, ed + 1):
                                target_code += true_target_method.abs_lines[i]
                        else:
                            target_code = true_target_method.abs_lines[l]
                        sim = levenshtein_distance(target_code, patch_code)
                        if sim > max_score:
                            max_score = sim
                            linecontentMap = {
                                "linemap": (int(line), l),
                                "abs_contentmap": (
                                    delete_line[line]["abs_code"],
                                    true_target_method.abs_lines[l],
                                ),
                                "contentmap": (
                                    delete_line[line]["code"],
                                    true_target_method.lines[l],
                                ),
                                "similarity": max_score,
                                "patch_method": origin_method,
                            }

                    repo_line_mapping[cve][file][target_method_info][
                        "deleteline"
                    ].append(linecontentMap)

                for line in add_line:
                    if add_line[line]["abs_code"].strip().replace(" ", "") in [
                        "",
                        "(",
                        ")",
                        "{",
                        "}",
                    ]:
                        continue
                    linecontentMap = {
                        "linemap": (int(line), None),
                        "contentmap": (line, None),
                        "similarity": max_score,
                        "patch_method": origin_method,
                    }
                    if add_line[line]["abs_code"].strip().replace(";", "") in [
                        "continue",
                        "return",
                        "break",
                    ]:
                        add_methods_lines = [int(x) for x in add_methods.keys()]
                        min_patch_method_line = sorted(add_methods_lines)[0]
                        max_patch_method_line = sorted(add_methods_lines)[-1]
                        st_patch = (
                            min_patch_method_line
                            if int(line) - 2 < min_patch_method_line
                            else int(line) - 2
                        )
                        ed_patch = (
                            max_patch_method_line
                            if int(line) + 2 > max_patch_method_line
                            else int(line) + 2
                        )
                        patch_code = ""
                        for i in range(st_patch, ed_patch + 1):
                            patch_code += add_methods[str(i)]
                    else:
                        patch_code = add_line[line]["abs_code"]

                    max_score = 0.0
                    for l in true_target_method.abs_lines:
                        if true_target_method.abs_lines[l].strip().replace(" ", "") in [
                            "",
                            "(",
                            ")",
                            "{",
                            "}",
                        ]:
                            continue
                        if add_line[line]["abs_code"].strip().replace(";", "") in [
                            "continue",
                            "return",
                            "break",
                        ]:
                            st = (
                                true_target_method.start_line
                                if l - 2 < true_target_method.start_line
                                else l - 2
                            )
                            ed = (
                                true_target_method.start_line
                                if l + 2 > true_target_method.end_line
                                else l + 2
                            )
                            target_code = ""
                            for i in range(st, ed + 1):
                                target_code += true_target_method.abs_lines[i]
                        else:
                            target_code = true_target_method.abs_lines[l]
                        sim = levenshtein_distance(target_code, patch_code)
                        if sim > max_score:
                            max_score = sim
                            if l not in true_target_method.lines:
                                linecontentMap = {
                                    "linemap": (int(line), l),
                                    "abs_contentmap": (
                                        add_line[line]["abs_code"],
                                        true_target_method.abs_lines[l],
                                    ),
                                    "contentmap": (
                                        add_line[line]["code"],
                                        true_target_method.abs_lines[l],
                                    ),
                                    "similarity": max_score,
                                    "patch_method": origin_method,
                                }
                            else:
                                linecontentMap = {
                                    "linemap": (int(line), l),
                                    "abs_contentmap": (
                                        add_line[line]["abs_code"],
                                        true_target_method.abs_lines[l],
                                    ),
                                    "contentmap": (
                                        add_line[line]["code"],
                                        true_target_method.lines[l],
                                    ),
                                    "similarity": max_score,
                                    "patch_method": origin_method,
                                }

                    repo_line_mapping[cve][file][target_method_info]["addline"].append(
                        linecontentMap
                    )
            except Exception as e:
                error_code[repo_path][cve][origin_method]["summary"] = "mapping error"
                error_code[repo_path][cve][origin_method]["detail"] = str(e)
                continue

            error_code[repo_path][cve][origin_method]["summary"] = "SUCCESS"
            error_code[repo_path][cve][origin_method]["detail"] = "SUCCESS"

    return repo_line_mapping, error_code


def repo_line_mapping_work_fn(worker_id, tar, language):
    repo_line_mapping = {}
    repo_path = f"{REPO_PATH}/{tar}"
    line_mapping, error_code = line_mapping_matching(repo_path, language)
    if line_mapping is None:
        return None, error_code, worker_id
    repo_line_mapping[tar] = line_mapping
    return repo_line_mapping, error_code, worker_id


def get_repo_line_mapping(tar, language):
    repo_line_mapping = {}
    res, error_code, worker_id = repo_line_mapping_work_fn(tar, tar, language)
    if res is not None:
        repo_line_mapping.update(res)

    fp = open(f"{LINE_MAPPING}/repo_line_mapping_{tar}.json", "w")
    json.dump(repo_line_mapping, fp, indent=4)
    fp.close()

    return repo_line_mapping


def call_worker_fn(pre_project: Project, ref_id, cnt):
    if cnt > 3:
        return None
    callees = pre_project.get_callee(ref_id)
    return callees, cnt + 1, ref_id


def get_callgraph(repo, project):
    edges = set()
    points = set()
    step = 0
    worker_list = []
    for method_signature in repo.matching_methods:
        points.add(method_signature)
        worker_list.append((project, method_signature, step))
    if len(repo.matching_methods) >= 10:
        return points, edges

    while worker_list != []:
        results = cpu_heater.multithreads(
            call_worker_fn, worker_list, max_workers=256, show_progress=False
        )
        worker_list = []
        for res in results:
            if res is None:
                continue
            callee, cnt, ref_id = res
            if cnt > 3:
                continue
            for point in callee:
                points.add(ref_id)
                points.add(point["callee_method_name"])
                point["caller_method_name"] = ref_id
                edges.add(
                    (
                        ref_id,
                        point["callee_method_name"],
                        point["callee_linenumber"],
                        point["method_line_number"],
                    )
                )
                if point["callee_method_name"] in points:
                    continue
                worker_list.append((project, point["callee_method_name"], cnt))

    return points, edges


def get_call(target, project, cache_dir):
    worker_list = []
    points, edges = get_callgraph(target, project)
    call = {}
    call["points"] = list(points)
    call["edges"] = list(edges)
    fp = open(f"{cache_dir}/call.json", "w")
    json.dump(call, fp, indent=4)
    fp.close()

    return call


def init_single_method_dir(method, cache_dir):
    method_dir = f"{cache_dir}/method/{method.signature_r}"
    dot_dir = f"{cache_dir}/method/{method.signature_r}/dot"

    os.makedirs(dot_dir, exist_ok=True)
    os.makedirs(method_dir, exist_ok=True)

    method.method_dir = method_dir
    method.write_code(method_dir)
    method.write_dot(dot_dir)

    return method_dir


def slicing_single_method(
    target_repo: Target, method_signature, target_project: Project, cache_dir
):
    method = target_project.get_method(method_signature)
    assert method is not None

    method_dir = init_single_method_dir(method, cache_dir)
    method.counterpart = method
    logging.info(f"🔄 begin single method slicing")
    pre_slice_results = method.slice_by_diff_lines_detect(
        target_repo.deleteline_matching[method_signature],
        target_repo.addline_matching[method_signature],
        need_criteria_identifier=True,
        write_dot=True,
        role="pre",
    )
    post_slice_results = method.slice_by_diff_lines_detect(
        target_repo.addline_matching[method_signature],
        target_repo.deleteline_matching[method_signature],
        need_criteria_identifier=True,
        write_dot=True,
        role="post",
    )

    return pre_slice_results, post_slice_results


def slice_per_callee(
    target_repo: Target,
    target_project: Project,
    cache_dir: str,
    callgraph: dict,
    sliced_results,
    method_signature,
    visited,
    level,
    is_pre,
    language,
):
    sliced_graph = {}
    sliced_graph["nodes"] = []
    sliced_graph["edges"] = []
    sliced_graph["node_dicts"] = {}
    (
        slice_result_lines,
        slice_result_weight,
        slice_result_edges,
        lines,
        abs_lines,
        criteria_identifier,
    ) = (
        sliced_results[0],
        sliced_results[5],
        sliced_results[6],
        sliced_results[7],
        sliced_results[8],
        sliced_results[9],
    )
    if level > 3:
        return None, visited
    if is_pre:
        call_edges = callgraph["edges"]
    else:
        call_edges = callgraph["edges"]

    for call_edge in call_edges:
        if int(call_edge[2]) in slice_result_lines and call_edge[0] == method_signature:
            callee_mathod = target_project.get_method(call_edge[1])
            if callee_mathod is None:
                continue
            if call_edge[1] in target_repo.matching_methods:
                if call_edge[1] in visited:
                    continue
                visited.add(call_edge[1])
                pre_slice_callee_results, post_slice_callee_results = (
                    slicing_single_method(
                        target_repo, call_edge[1], target_project, cache_dir
                    )
                )
                if (
                    pre_slice_callee_results is None
                    or post_slice_callee_results is None
                ):
                    continue
                if is_pre:
                    (
                        pre_slice_callee_result_lines,
                        pre_slice_callee_result_weight,
                        pre_slice_callee_result_edges,
                        pre_callee_lines,
                        pre_callee_abs_lines,
                    ) = (
                        pre_slice_callee_results[0],
                        pre_slice_callee_results[5],
                        pre_slice_callee_results[6],
                        pre_slice_callee_results[7],
                        pre_slice_callee_results[8],
                    )
                    callee_results = pre_slice_callee_results
                else:
                    (
                        pre_slice_callee_result_lines,
                        pre_slice_callee_result_weight,
                        pre_slice_callee_result_edges,
                        pre_callee_lines,
                        pre_callee_abs_lines,
                    ) = (
                        post_slice_callee_results[0],
                        post_slice_callee_results[5],
                        post_slice_callee_results[6],
                        post_slice_callee_results[7],
                        post_slice_callee_results[8],
                    )
                    callee_results = post_slice_callee_results

                for line in pre_slice_callee_result_lines:
                    try:
                        sliced_graph["nodes"].append(f"{call_edge[1]}#{line}")
                    except:
                        sliced_graph["nodes"] = [f"{call_edge[1]}#{line}"]
                for edge in pre_slice_callee_result_edges:
                    try:
                        sliced_graph["edges"].append(
                            (f"{call_edge[1]}#{edge[0]}", f"{call_edge[1]}#{edge[1]}")
                        )
                    except:
                        sliced_graph["edges"] = [
                            (f"{call_edge[1]}#{edge[0]}", f"{call_edge[1]}#{edge[1]}")
                        ]

                sliced_graph["node_dicts"] = {}
                for line in pre_slice_callee_result_lines:
                    sliced_graph["node_dicts"][f"{call_edge[1]}#{line}"] = {}
                    sliced_graph["node_dicts"][f"{call_edge[1]}#{line}"]["weight"] = (
                        pre_slice_callee_result_weight[line]
                    )
                    sliced_graph["node_dicts"][f"{call_edge[1]}#{line}"][
                        "node_string"
                    ] = pre_callee_lines[line]
                    sliced_graph["node_dicts"][f"{call_edge[1]}#{line}"][
                        "abs_node_string"
                    ] = pre_callee_abs_lines[line]

                caller_line = f"{method_signature}#{call_edge[2]}"
                callee_line = f"{callee_mathod.signature}#{sorted(pre_slice_callee_result_lines)[0]}"
                sliced_graph["edges"].append((caller_line, callee_line))
                res, visited = slice_per_callee(
                    target_repo,
                    target_project,
                    cache_dir,
                    callgraph,
                    callee_results,
                    call_edge[1],
                    visited,
                    level + 1,
                    is_pre,
                )
                if res is None:
                    continue
                sliced_graph["nodes"].extend(res["nodes"])
                sliced_graph["edges"].extend(res["edges"])
                sliced_graph["node_dicts"].update(res["node_dicts"])
        elif (
            call_edge[1] == method_signature
            and call_edge[0] in target_repo.matching_methods
        ):
            visited.add(call_edge[0])
            pre_slice_caller_results, post_slice_caller_results = slicing_single_method(
                target_repo, call_edge[0], target_project, cache_dir
            )
            if pre_slice_caller_results is None or post_slice_caller_results is None:
                continue
            if is_pre:
                (
                    pre_slice_caller_result_lines,
                    pre_slice_caller_result_weight,
                    pre_slice_caller_result_edges,
                    pre_callee_lines,
                    pre_callee_abs_lines,
                ) = (
                    pre_slice_caller_results[0],
                    pre_slice_caller_results[5],
                    pre_slice_caller_results[6],
                    pre_slice_caller_results[7],
                    pre_slice_caller_results[8],
                )
                caller_results = pre_slice_caller_results
            else:
                (
                    pre_slice_caller_result_lines,
                    pre_slice_caller_result_weight,
                    pre_slice_caller_result_edges,
                    pre_callee_lines,
                    pre_callee_abs_lines,
                ) = (
                    post_slice_caller_results[0],
                    post_slice_caller_results[5],
                    post_slice_caller_results[6],
                    post_slice_caller_results[7],
                    post_slice_caller_results[8],
                )
                caller_results = post_slice_caller_results
            for line in pre_slice_caller_result_lines:
                try:
                    sliced_graph["nodes"].append(f"{call_edge[0]}#{line}")
                except:
                    sliced_graph["nodes"] = [f"{call_edge[0]}#{line}"]
            for edge in pre_slice_caller_result_edges:
                try:
                    sliced_graph["edges"].append(
                        (f"{call_edge[0]}#{edge[0]}", f"{call_edge[0]}#{edge[1]}")
                    )
                except:
                    sliced_graph["edges"] = [
                        (f"{call_edge[0]}#{edge[0]}", f"{call_edge[0]}#{edge[1]}")
                    ]

            sliced_graph["node_dicts"] = {}
            for line in pre_slice_caller_result_lines:
                sliced_graph["node_dicts"][f"{call_edge[0]}#{line}"] = {}
                sliced_graph["node_dicts"][f"{call_edge[0]}#{line}"]["weight"] = (
                    pre_slice_caller_result_weight[line]
                )
                sliced_graph["node_dicts"][f"{call_edge[0]}#{line}"]["node_string"] = (
                    pre_callee_lines[line]
                )
                sliced_graph["node_dicts"][f"{call_edge[0]}#{line}"][
                    "abs_node_string"
                ] = pre_callee_abs_lines[line]
            res, visited = slice_per_callee(
                target_repo,
                target_project,
                cache_dir,
                callgraph,
                caller_results,
                call_edge[0],
                visited,
                level + 1,
                is_pre,
            )
            if res is None:
                continue
            sliced_graph["nodes"].extend(res["nodes"])
            sliced_graph["edges"].extend(res["edges"])
            sliced_graph["node_dicts"].update(res["node_dicts"])
        elif int(call_edge[2]) in slice_result_lines:
            callee_method: Method | None = target_project.get_method(call_edge[1])
            init_single_method_dir(callee_method, cache_dir)
            if callee_method is None:
                continue
            logging.info(call_edge[1])
            parser = ASTParser(lines[int(call_edge[2])], language)
            nodes = parser.query_all("(call_expression)@name")
            for node in nodes:
                child = node.child_by_field_name("function")
                args = []
                if child is None or child.text is None:
                    continue
                if child.text.decode() == call_edge[1].split("#")[1]:
                    arguments_node = node.child_by_field_name("arguments")
                    if arguments_node is None:
                        continue
                    for arg in arguments_node.children:
                        if arg.type != "," and arg.type != "(" and arg.type != ")":
                            assert arg.text is not None
                            arg_value = arg.text.decode("utf-8")
                            args.append(arg_value)
                    if call_edge[2] in criteria_identifier:
                        slice_callee_results = (
                            callee_method.slice_by_header_line_vul_detect(
                                args, criteria_identifier[call_edge[2], True, True]
                            )
                        )
                    else:
                        slice_callee_results = (
                            callee_method.slice_by_header_line_vul_detect(
                                args, set(), True, True
                            )
                        )

                    (
                        slice_callee_results_lines,
                        slice_callee_results_weight,
                        slice_callee_results_edges,
                        slice_callee_lines,
                        slice_callee_results_abs_lines,
                    ) = (
                        slice_callee_results[0],
                        slice_callee_results[5],
                        slice_callee_results[6],
                        slice_callee_results[7],
                        slice_callee_results[8],
                    )
                    caller_line = f"{method_signature}#{call_edge[2]}"
                    callee_line = f"{callee_method.signature}#{sorted(slice_callee_results_lines)[0]}"
                    callee_codes = ""
                    abs_callee_codes = ""
                    for line in slice_callee_results_lines:
                        callee_codes += slice_callee_lines[line]
                        abs_callee_codes += slice_callee_results_abs_lines[line]
                    sliced_graph["edges"].append((caller_line, callee_line))
                    sliced_graph["nodes"].append(callee_line)
                    sliced_graph["node_dicts"][callee_line] = {}
                    sliced_graph["node_dicts"][callee_line]["weight"] = 1 / level
                    sliced_graph["node_dicts"][callee_line]["node_string"] = (
                        callee_codes
                    )
                    sliced_graph["node_dicts"][callee_line]["abs_node_string"] = (
                        abs_callee_codes
                    )

    return sliced_graph, visited


def slicing_multi_method(
    target_repo: Target, target_project: Project, cache_dir, callgraph
):
    visited = set()
    graph_clusters = []
    for method_signature in target_repo.matching_methods:
        graph_cluster = {}
        pre_sliced_graph = {}
        pre_sliced_graph["nodes"] = []
        pre_sliced_graph["edges"] = []
        pre_sliced_graph["node_dicts"] = {}

        post_sliced_graph = {}
        post_sliced_graph["nodes"] = []
        post_sliced_graph["edges"] = []
        post_sliced_graph["node_dicts"] = {}
        if method_signature in visited:
            continue
        visited.add(method_signature)
        pre_slice_results, post_slice_results = slicing_single_method(
            target_repo, method_signature, target_project, cache_dir
        )
        if pre_slice_results is None or post_slice_results is None:
            continue
        (
            pre_slice_result_lines,
            pre_slice_result_weight,
            pre_slice_result_edges,
            pre_lines,
            pre_abs_lines,
        ) = (
            pre_slice_results[0],
            pre_slice_results[5],
            pre_slice_results[6],
            pre_slice_results[7],
            pre_slice_results[8],
        )
        (
            post_slice_result_lines,
            post_slice_result_weight,
            post_slice_result_edges,
            post_lines,
            post_abs_lines,
        ) = (
            post_slice_results[0],
            post_slice_results[5],
            post_slice_results[6],
            post_slice_results[7],
            post_slice_results[8],
        )
        for line in pre_slice_result_lines:
            try:
                pre_sliced_graph["nodes"].append(f"{method_signature}#{line}")
            except:
                pre_sliced_graph["nodes"] = [f"{method_signature}#{line}"]
        for edge in pre_slice_result_edges:
            try:
                pre_sliced_graph["edges"].append(
                    (f"{method_signature}#{edge[0]}", f"{method_signature}#{edge[1]}")
                )
            except:
                pre_sliced_graph["edges"] = [
                    (f"{method_signature}#{edge[0]}", f"{method_signature}#{edge[1]}")
                ]

        for line in pre_slice_result_lines:
            pre_sliced_graph["node_dicts"][f"{method_signature}#{line}"] = {}
            pre_sliced_graph["node_dicts"][f"{method_signature}#{line}"]["weight"] = (
                pre_slice_result_weight[line]
            )
            pre_sliced_graph["node_dicts"][f"{method_signature}#{line}"][
                "node_string"
            ] = pre_lines[line]
            pre_sliced_graph["node_dicts"][f"{method_signature}#{line}"][
                "abs_node_string"
            ] = pre_abs_lines[line]
        res, visited = slice_per_callee(
            target_repo,
            target_project,
            cache_dir,
            callgraph,
            pre_slice_results,
            method_signature,
            visited,
            1,
            True,
        )
        if res is None:
            continue
        pre_sliced_graph["nodes"].extend(res["nodes"])
        pre_sliced_graph["nodes"] = list(set(pre_sliced_graph["nodes"]))
        pre_sliced_graph["edges"].extend(res["edges"])
        pre_sliced_graph["edges"] = list(set(pre_sliced_graph["edges"]))
        pre_sliced_graph["node_dicts"].update(res["node_dicts"])

        id_graph_id_map = {}
        pre_sliced_graph_true = {}
        pre_sliced_graph_true["node_dicts"] = {}
        pre_sliced_graph_true["nodes"] = []
        pre_sliced_graph_true["edges"] = []
        id = 0
        for graph_id in pre_sliced_graph["nodes"]:
            id_graph_id_map[graph_id] = id
            pre_sliced_graph_true["nodes"].append(id)
            id += 1
        for edge in pre_sliced_graph["edges"]:
            pre_sliced_graph_true["edges"].append(
                (id_graph_id_map[edge[0]], id_graph_id_map[edge[1]])
            )

        for key in pre_sliced_graph["node_dicts"]:
            pre_sliced_graph_true["node_dicts"][id_graph_id_map[key]] = (
                pre_sliced_graph["node_dicts"][key]
            )

        for line in post_slice_result_lines:
            try:
                post_sliced_graph["nodes"].append(f"{method_signature}#{line}")
            except:
                post_sliced_graph["nodes"] = [f"{method_signature}#{line}"]
        for edge in post_slice_result_edges:
            try:
                post_sliced_graph["edges"].append(
                    (f"{method_signature}#{edge[0]}", f"{method_signature}#{edge[1]}")
                )
            except:
                post_sliced_graph["edges"] = [
                    (f"{method_signature}#{edge[0]}", f"{method_signature}#{edge[1]}")
                ]

        for line in post_slice_result_lines:
            post_sliced_graph["node_dicts"][f"{method_signature}#{line}"] = {}
            post_sliced_graph["node_dicts"][f"{method_signature}#{line}"]["weight"] = (
                post_slice_result_weight[line]
            )
            post_sliced_graph["node_dicts"][f"{method_signature}#{line}"][
                "node_string"
            ] = post_lines[line]
            post_sliced_graph["node_dicts"][f"{method_signature}#{line}"][
                "abs_node_string"
            ] = post_abs_lines[line]
        res, visited = slice_per_callee(
            target_repo,
            target_project,
            cache_dir,
            callgraph,
            pre_slice_results,
            method_signature,
            visited,
            1,
            False,
        )
        if res is None:
            continue
        post_sliced_graph["nodes"].extend(res["nodes"])
        post_sliced_graph["edges"].extend(res["edges"])
        post_sliced_graph["node_dicts"].update(res["node_dicts"])

        post_sliced_graph["nodes"].extend(res["nodes"])
        post_sliced_graph["nodes"] = list(set(post_sliced_graph["nodes"]))
        post_sliced_graph["edges"].extend(res["edges"])
        post_sliced_graph["edges"] = list(set(post_sliced_graph["edges"]))
        post_sliced_graph["node_dicts"].update(res["node_dicts"])

        id_graph_id_map = {}
        post_sliced_graph_true = {}
        post_sliced_graph_true["node_dicts"] = {}
        post_sliced_graph_true["nodes"] = []
        post_sliced_graph_true["edges"] = []
        id = 0
        for graph_id in post_sliced_graph["nodes"]:
            id_graph_id_map[graph_id] = id
            post_sliced_graph_true["nodes"].append(id)
            id += 1
        for edge in post_sliced_graph["edges"]:
            post_sliced_graph_true["edges"].append(
                (id_graph_id_map[edge[0]], id_graph_id_map[edge[1]])
            )

        for key in post_sliced_graph["node_dicts"]:
            post_sliced_graph_true["node_dicts"][id_graph_id_map[key]] = (
                post_sliced_graph["node_dicts"][key]
            )

        graph_cluster["pre"] = pre_sliced_graph_true
        graph_cluster["post"] = post_sliced_graph_true
        graph_clusters.append(graph_cluster)

    clusters = split_clusters(graph_clusters)
    fp = open(f"{cache_dir}/graph_clusters.json", "w")
    json.dump(clusters, fp, indent=4)
    fp.close()


def target_slicing(worker_id, tar, repo_line_mapping, language):
    repo_path = f"{REPO_PATH}/{tar}"
    cache_dir = f"{TARGET_SLICING}/{tar}"
    error_code = {}
    error_code[tar] = {}
    for cve in repo_line_mapping[tar]:
        error_code[tar][cve] = {}
        detect_dir = os.path.join(cache_dir, cve)
        if os.path.exists(f"{detect_dir}/graph_clusters.json"):
            error_code[tar][cve]["summary"] = "SUCCESS"
            error_code[tar][cve]["detail"] = "already slicing"
            continue

        fileList = set()
        matching_method = []
        add_line_map = {}
        del_line_map = {}
        for file in repo_line_mapping[tar][cve]:
            if repo_path in file:
                true_file = os.path.relpath(file, repo_path)
            else:
                true_file = file
            fileList.add(true_file)
            for method in repo_line_mapping[tar][cve][file]:
                if method.split("#")[0].startswith(repo_path):
                    true_method = f"{os.path.relpath(method.split('#')[0], repo_path)}#{method.split('#')[1]}"
                else:
                    true_method = method
                matching_method.append(true_method)
                add_line_map[true_method] = set()
                del_line_map[true_method] = set()

                for line_map_dict in repo_line_mapping[tar][cve][file][method][
                    "deleteline"
                ]:
                    del_line_map[true_method].add(int(line_map_dict["linemap"][1]))
                for line_map_dict in repo_line_mapping[tar][cve][file][method][
                    "addline"
                ]:
                    add_line_map[true_method].add(int(line_map_dict["linemap"][1]))

        try:
            target_repo = Target(
                cve,
                repo_path,
                fileList,
                matching_method,
                language,
                add_line_map,
                del_line_map,
            )
            analysis_files = target_repo.analysis_files
            create_code_tree(analysis_files, detect_dir)
            target_proj = target_repo.project
            assert target_proj is not None
        except Exception as e:
            error_code[tar][cve]["summary"] = "TARGET PROJ ERROR"
            error_code[tar][cve]["detail"] = str(e)
            continue
        try:
            joern.export_with_preprocess_and_merge(
                f"{detect_dir}/code", detect_dir, language, False, True
            )

        except Exception as e:
            error_code[tar][cve]["summary"] = "PDG ERROR"
            error_code[tar][cve]["detail"] = str(e)
            continue
        target_proj.load_joern_graph(f"{detect_dir}/cpg", f"{detect_dir}/pdg")
        try:
            callgraph = get_call(target_repo, target_proj, detect_dir)

        except Exception as e:
            error_code[tar][cve]["summary"] = "CALL ERROR"
            error_code[tar][cve]["detail"] = str(e)
            continue
        graph_clusters = []

        try:
            if len(target_repo.matching_methods) == 1:
                graph_cluster = {}
                pre_slice_results, post_slice_results = slicing_single_method(
                    target_repo,
                    list(target_repo.matching_methods)[0],
                    target_proj,
                    detect_dir,
                )
                if pre_slice_results is None or post_slice_results is None:
                    return None, worker_id
                (
                    pre_slice_result_lines,
                    pre_slice_result_weight,
                    pre_slice_result_edges,
                    pre_lines,
                    pre_abs_lines,
                ) = (
                    pre_slice_results[0],
                    pre_slice_results[5],
                    pre_slice_results[6],
                    pre_slice_results[7],
                    pre_slice_results[8],
                )
                (
                    post_slice_result_lines,
                    post_slice_result_weight,
                    post_slice_result_edges,
                    post_lines,
                    post_abs_lines,
                ) = (
                    post_slice_results[0],
                    post_slice_results[5],
                    post_slice_results[6],
                    post_slice_results[7],
                    post_slice_results[8],
                )
                pre_sliced_graph = {}
                pre_sliced_graph["nodes"] = list(pre_slice_result_lines)
                pre_sliced_graph["edges"] = list(pre_slice_result_edges)
                pre_sliced_graph["node_dicts"] = {}
                for line in pre_slice_result_lines:
                    pre_sliced_graph["node_dicts"][line] = {}
                    pre_sliced_graph["node_dicts"][line]["weight"] = (
                        pre_slice_result_weight[line]
                    )
                    pre_sliced_graph["node_dicts"][line]["node_string"] = pre_lines[
                        line
                    ]
                    pre_sliced_graph["node_dicts"][line]["abs_node_string"] = (
                        pre_abs_lines[line]
                    )

                fp = open(f"{detect_dir}/pre_sliced_wfg.json", "w")
                json.dump(pre_sliced_graph, fp, indent=4)
                fp.close()
                convert_to_dot(
                    f"{detect_dir}/pre_sliced_wfg.json",
                    f"{detect_dir}/pre_sliced_wfg.dot",
                )
                post_sliced_graph = {}
                post_sliced_graph["nodes"] = list(post_slice_result_lines)
                post_sliced_graph["edges"] = list(post_slice_result_edges)
                post_sliced_graph["node_dicts"] = {}
                for line in post_slice_result_lines:
                    post_sliced_graph["node_dicts"][line] = {}
                    post_sliced_graph["node_dicts"][line]["weight"] = (
                        post_slice_result_weight[line]
                    )
                    post_sliced_graph["node_dicts"][line]["node_string"] = post_lines[
                        line
                    ]
                    post_sliced_graph["node_dicts"][line]["abs_node_string"] = (
                        post_abs_lines[line]
                    )
                fp = open(f"{detect_dir}/post_sliced_wfg.json", "w")
                json.dump(pre_sliced_graph, fp, indent=4)
                fp.close()
                convert_to_dot(
                    f"{detect_dir}/post_sliced_wfg.json",
                    f"{detect_dir}/post_sliced_wfg.dot",
                )
                graph_cluster["pre"] = pre_sliced_graph
                graph_cluster["post"] = post_sliced_graph
                graph_clusters.append(graph_cluster)
                clusters = split_clusters(graph_clusters)
                fp = open(f"{detect_dir}/graph_cluster.json", "w")
                json.dump(clusters, fp, indent=4)
                fp.close()

            else:
                slicing_multi_method(target_repo, target_proj, detect_dir, callgraph)
        except Exception as e:
            error_code[tar][cve]["summary"] = "slicing error"
            error_code[tar][cve]["detail"] = str(e)
            continue

        error_code[tar][cve]["summary"] = "SUCCESS"
        error_code[tar][cve]["detail"] = "SUCCESS"
    return error_code, worker_id


if __name__ == "__main__":
    joern.set_joern_env(JOERN_PATH)

    tar = sys.argv[1]
    language = sys.argv[2]
    get_cve_patch_info(language)
    get_repo_file_mapping(tar, language)
    get_repo_method_mapping(tar, language)
    repo_line_mapping = get_repo_line_mapping(tar, language)
    target_slicing(tar, tar, repo_line_mapping, language)
