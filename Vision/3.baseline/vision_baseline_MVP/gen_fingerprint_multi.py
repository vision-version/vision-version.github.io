from slicing_multi import slicing, getcdg_ddg
from parse_commit_multi import readCommit,get_old_new_map
import sys
import os
import json
import hashlib
from informationCalc import informationCalc
import functools
from multiprocessing import Pool
import os
import traceback
import pandas as pd
import numpy as np
from tqdm import tqdm
import joern_session
import config


def signature_generate_vul_patch(old_file, new_file, methodFullName,sess):    
    worker_id = sess.worker_id.replace("/","_")
    old_file_location = (
        old_file[: old_file[: old_file.rfind("/")].rfind("/")]
        + "/normalized_" + worker_id
        + old_file[old_file.rfind("/") :]
    )
    new_file_location = (
        new_file[: new_file[: new_file.rfind("/")].rfind("/")]
        + "/normalized_" + worker_id
        + new_file[new_file.rfind("/") :]
    )
    old_filePath = old_file
    new_filePath = new_file
    old_file = old_file.split("/")[-1]
    new_file = new_file.split("/")[-1]
    signature_dict = {}
    add_line = []
    delete_line = []
    add_lines = []
    
    oldMethodFullName = methodFullName
    newMethodFullName = methodFullName
    with open(f"method_info_{worker_id}.json", "r") as f:
        json_object = json.load(f)
        for pair in json_object:
            if old_file == pair["oldFile"]:
                
                if methodFullName in pair["old2newChange"].keys():
                    oldMethodFullName = methodFullName
                    newMethodFullName = pair["old2newChange"][methodFullName]
                elif methodFullName in pair["new2oldChange"].keys():
                    newMethodFullName = methodFullName
                    oldMethodFullName = pair["old2newChange"][methodFullName]
                delete_lines = pair["delete"]
                add_lines = pair["add"]
                add_line = pair["addMethodFull"][newMethodFullName]["lineNumber"]
                delete_line = pair["deleteMethodFull"][oldMethodFullName]["lineNumber"]
                
                signature_dict["deleteLines"] = pair["deleteMethodFull"][
                    oldMethodFullName
                ]["lineNumber"]
                oldLineBegin = pair["deleteMethodBegin"][oldMethodFullName]
                newLineBegin = pair["addMethodBegin"][newMethodFullName]
                old_new_map,new_old_map = get_old_new_map(delete_lines,add_lines)
    i = oldMethodFullName.find("(")
    methodName = oldMethodFullName[:i].split(".")[-1]
    old_cdg, old_ddg, old_slicing_set = slicing(
        old_filePath, methodName, oldLineBegin, oldMethodFullName,sess
    )

    i = newMethodFullName.find("(")
    methodName = newMethodFullName[:i].split(".")[-1]
    vul_syn = old_slicing_set
    new_cdg, new_ddg, new_slicing_set = slicing(
        new_filePath, methodName, newLineBegin, newMethodFullName,sess
    )
    indirect_vul_syn = set()
    direct_vul_syn = set()
    
    for line in new_slicing_set:
        if line not in add_lines:
            if new_old_map[line] not in vul_syn:
                vul_syn.add(new_old_map[line])
    
    
    for line in old_slicing_set:
        for vul in delete_line:
            direct_vul_syn.add(vul)
            if (vul in old_cdg.keys() and line in old_cdg[vul]) or (vul in old_ddg.keys() and line in old_ddg[vul]) or (line in old_cdg.keys() and vul in old_cdg[line]) or (line in old_ddg.keys() and vul in old_ddg[line]):
                direct_vul_syn.add(line)
                break

    for new_line in new_slicing_set:
        for pat in add_line:
            if (pat in new_cdg.keys() and new_line in new_cdg[pat]) or (pat in new_ddg.keys() and new_line in new_ddg[pat]) or (new_line in new_cdg.keys() and pat in new_cdg[new_line]) or (new_line in new_ddg.keys() and pat in new_ddg[new_line]):
                if new_line not in add_lines:
                    direct_vul_syn.add(new_old_map[new_line])
                    break
    indirect_vul_syn = vul_syn.difference(direct_vul_syn)


    vul_syn,new_slicing_set = informationCalc(add_line,delete_line,list(vul_syn),list(indirect_vul_syn),list(new_slicing_set),old_file_location,old_new_map)
    vul_sem = []
    
    for line1 in vul_syn:
        for line2 in vul_syn:
            if line1 in old_cdg.keys():
                if line2 in old_cdg[line1]:
                    vul_sem.append([line1, line2, "control"])
            if line1 in old_ddg.keys():
                if line2 in old_ddg[line1]:
                    vul_sem.append([line1, line2, "data"])
    pat_syn = add_line
    pat_sem = []

    for line1 in new_slicing_set:
        for line2 in new_slicing_set:
            if line1 not in add_line and line2 not in add_line:
                continue
            if line1 in new_cdg.keys():
                if line2 in new_cdg[line1]:
                    pat_sem.append([line1, line2, "control"])
            if line1 in new_ddg.keys():
                if line2 in new_ddg[line1]:
                    pat_sem.append([line1, line2, "data"])
    vul_syn = list(vul_syn)
    vul_sem = list(vul_sem)
    m = hashlib.md5()
    hash_delete_lines = []
    hash_vul_syn = []
    hash_vul_sem = []
    hash_pat_syn = []
    hash_pat_sem = []

    with open(old_file_location, "r") as f:
        lines = f.readlines()
        while oldLineBegin != 0 and lines[oldLineBegin - 1].strip().replace(
            " ", ""
        ).startswith("@"):
        
            oldLineBegin += 1
        vul_syn = [
            x
            for x in vul_syn
            if x > oldLineBegin
            and lines[x - 1]
            .replace(" ", "")
            .replace("{", "")
            .replace("}", "")
            .replace("\t", "")
            .replace("\n", "")
            != ""
        ]
        
        vul_sem = [
            x
            for x in vul_sem
            if x[0] > oldLineBegin
            and x[1] > oldLineBegin
            and lines[x[0] - 1]
            .replace(" ", "")
            .replace("{", "")
            .replace("}", "")
            .replace("\t", "")
            .replace("\n", "")
            != ""
            and lines[x[1] - 1]
            .replace(" ", "")
            .replace("{", "")
            .replace("}", "")
            .replace("\t", "")
            .replace("\n", "")
            != ""
        ]
        
        signature_dict["deleteLines"] = [
            x
            for x in signature_dict["deleteLines"]
            if x > oldLineBegin
            and lines[x - 1]
            .replace(" ", "")
            .replace("{", "")
            .replace("}", "")
            .replace("\t", "")
            .replace("\n", "")
            != ""
        ]

        for i in range(len(signature_dict["deleteLines"])):
            signature_dict["deleteLines"][i] = (
                lines[signature_dict["deleteLines"][i] - 1]
                .replace(" ", "")
                .replace("{", "")
                .replace("}", "")
                .replace("\t", "")
                .replace("\n", "")
            )
            if signature_dict["deleteLines"][i] != "":
                
                m = hashlib.md5()
                m.update(signature_dict["deleteLines"][i].encode("utf8"))
                hash_delete_lines.append(m.hexdigest()[:6])
                
        for i in range(len(vul_syn)):
            vul_syn[i] = (
                lines[vul_syn[i] - 1]
                .replace(" ", "")
                .replace("{", "")
                .replace("}", "")
                .replace("\t", "")
                .replace("\n", "")
            )
            if vul_syn[i] != "":
                m = hashlib.md5()
                m.update(vul_syn[i].encode("utf8"))
                hash_vul_syn.append(m.hexdigest()[:6])
                
        for i in range(len(vul_sem)):
            tuple1 = vul_sem[i]
            tuple1[0] = (
                lines[tuple1[0] - 1]
                .replace(" ", "")
                .replace("{", "")
                .replace("}", "")
                .replace("\t", "")
                .replace("\n", "")
            )
            tuple1[1] = (
                lines[tuple1[1] - 1]
                .replace(" ", "")
                .replace("{", "")
                .replace("}", "")
                .replace("\t", "")
                .replace("\n", "")
            )
            if tuple1[0] != "" and tuple1[1] != "":
                tuple2 = []
                m = hashlib.md5()
                m.update(tuple1[0].encode("utf8"))
                tuple2.append(m.hexdigest()[:6])
                m = hashlib.md5()
                m.update(tuple1[1].encode("utf8"))
                tuple2.append(m.hexdigest()[:6])
                tuple2.append(tuple1[2])
                hash_vul_sem.append(tuple2)
    with open(new_file_location, "r") as f:
        lines = f.readlines()
        while newLineBegin != 0 and lines[newLineBegin - 1].strip().replace(
            " ", ""
        ).startswith("@"):
            newLineBegin += 1
        pat_syn = [
            x
            for x in pat_syn
            if x > newLineBegin
            and lines[x - 1]
            .replace(" ", "")
            .replace("{", "")
            .replace("}", "")
            .replace("\t", "")
            .replace("\n", "")
            != ""
        ]
        pat_sem = [
            x
            for x in pat_sem
            if x[0] > newLineBegin
            and x[1] > newLineBegin
            and lines[x[0] - 1]
            .replace(" ", "")
            .replace("{", "")
            .replace("}", "")
            .replace("\t", "")
            .replace("\n", "")
            != ""
            and lines[x[1] - 1]
            .replace(" ", "")
            .replace("{", "")
            .replace("}", "")
            .replace("\t", "")
            .replace("\n", "")
            != ""
        ]
        for i in range(len(pat_syn)):
            pat_syn[i] = (
                lines[pat_syn[i] - 1]
                .replace(" ", "")
                .replace("{", "")
                .replace("}", "")
                .replace("\t", "")
                .replace("\n", "")
            )
            if pat_syn[i] != "":
                m = hashlib.md5()
                m.update(pat_syn[i].encode("utf8"))
                hash_pat_syn.append(m.hexdigest()[:6])
        for i in range(len(pat_sem)):
            tuple1 = pat_sem[i]
            tuple1[0] = (
                lines[tuple1[0] - 1]
                .replace(" ", "")
                .replace("{", "")
                .replace("}", "")
                .replace("\t", "")
                .replace("\n", "")
            )
            tuple1[1] = (
                lines[tuple1[1] - 1]
                .replace(" ", "")
                .replace("{", "")
                .replace("}", "")
                .replace("\t", "")
                .replace("\n", "")
            )
            if tuple1[0] != "" and tuple1[1] != "":
                tuple2 = []
                m = hashlib.md5()
                m.update(tuple1[0].encode("utf8"))
                tuple2.append(m.hexdigest()[:6])
                m = hashlib.md5()
                m.update(tuple1[1].encode("utf8"))
                tuple2.append(m.hexdigest()[:6])
                tuple2.append(tuple1[2])
                hash_pat_sem.append(tuple2)

    signature_dict["deleteLines"] = hash_delete_lines
    signature_dict["vul_syn"] = hash_vul_syn
    signature_dict["vul_sem"] = hash_vul_sem
    signature_dict["pat_syn"] = hash_pat_syn
    signature_dict["pat_sem"] = hash_pat_sem

    return signature_dict

def getMethodPrint(file_location, lineNumber, lineNumberEnd, method_name, sess):
    worker_id = sess.worker_id.replace("/","_")
    sess.import_code(file_location)
    sess.run_script("slice", params={"line": lineNumber, "i":str(worker_id)})
    slicing_set = set()
    cdg_map,ddg_map = getcdg_ddg(f"PDG/PDG_{worker_id}.json")
   
    criterion_set = set(range(lineNumber, lineNumberEnd + 1))
    syn = criterion_set
    sem = []
    for line1 in syn:
        for line2 in syn:
            if line1 in cdg_map.keys():
                if line2 in cdg_map[line1]:
                    sem.append([line1, line2, "control"])
            if line1 in ddg_map.keys():
                if line2 in ddg_map[line1]:
                    sem.append([line1, line2, "data"])
    hash_syn = []
    hash_sem = []
    file_location = (
        file_location[: file_location[: file_location.rfind("/")].rfind("/")]
        + "/normalized_" + worker_id
        + file_location[file_location.rfind("/") :]
    )
    with open(file_location, "r") as f:
        lines = f.readlines()
        if len(lines)==0:
            signature_dict["syn"] = hash_syn
            signature_dict["sem"] = hash_sem
            return signature_dict
        while lineNumber != 0 and lines[lineNumber - 1].strip().replace(
            " ", ""
        ).startswith("@"):
            lineNumber += 1
        syn = [
            x
            for x in syn
            if x > lineNumber
            and lines[x - 1]
            .replace(" ", "")
            .replace("{", "")
            .replace("}", "")
            .replace("\t", "")
            .replace("\n", "")
            != ""
        ]
        sem = [
            x
            for x in sem
            if x[0] > lineNumber
            and x[1] > lineNumber
            and lines[x[0] - 1]
            .replace(" ", "")
            .replace("{", "")
            .replace("}", "")
            .replace("\t", "")
            .replace("\n", "")
            != ""
            and lines[x[1] - 1]
            .replace(" ", "")
            .replace("{", "")
            .replace("}", "")
            .replace("\t", "")
            .replace("\n", "")
            != ""
        ]
        for i in range(len(syn)):
            syn[i] = (
                lines[syn[i] - 1]
                .replace(" ", "")
                .replace("{", "")
                .replace("}", "")
                .replace("\t", "")
                .replace("\n", "")
            )
            if syn[i] != "":
                m = hashlib.md5()
                m.update(syn[i].encode("utf8"))
                hash_syn.append(m.hexdigest()[:6])
        for i in range(len(sem)):
            tuple1 = sem[i]
            tuple1[0] = (
                lines[tuple1[0] - 1]
                .replace(" ", "")
                .replace("{", "")
                .replace("}", "")
                .replace("\t", "")
                .replace("\n", "")
            )
            tuple1[1] = (
                lines[tuple1[1] - 1]
                .replace(" ", "")
                .replace("{", "")
                .replace("}", "")
                .replace("\t", "")
                .replace("\n", "")
            )
            if tuple1[0] != "" and tuple1[1] != "":
                tuple2 = []
                m = hashlib.md5()
                m.update(tuple1[0].encode("utf8"))
                tuple2.append(m.hexdigest()[:6])
                m = hashlib.md5()
                m.update(tuple1[1].encode("utf8"))
                tuple2.append(m.hexdigest()[:6])
                tuple2.append(tuple1[2])
                hash_sem.append(tuple2)
    signature_dict = {}
    signature_dict["syn"] = hash_syn
    signature_dict["sem"] = hash_sem

    return signature_dict


def gen_fingerprint(CVE_ID, commit_file_location, git_repo_location, work_dir, sess):
    worker_id = sess.worker_id.replace("/","_")
    astJar = "./config/AstGen1-0.0.1-SNAPSHOT.jar"
    if not os.path.exists(work_dir + "temp_"+worker_id + "/"):
        os.mkdir(work_dir + "temp_"+worker_id + "/")
    os.chdir(git_repo_location)
    readCommit(CVE_ID, commit_file_location, git_repo_location, work_dir, sess)
    print("commit文件解读完成！")
    if not os.path.exists(work_dir + "normalized_"+worker_id + "/"):
        os.mkdir(work_dir + "normalized_"+worker_id + "/")
    with open(f"method_info_{worker_id}.json", "r") as f:
        json_list = json.load(f)
        for ele in json_list:
            delete_lines = ele["delete"]
            add_lines = ele["add"]
            os.system(
                "cp "
                + work_dir
                + "temp_"+worker_id + "/"
                + ele["oldFile"]
                + " "
                + work_dir
                + "normalized_"+worker_id + "/"
                + ele["oldFile"]
            )
            os.system(
                "cp "
                + work_dir
                + "temp_"+worker_id + "/"
                + ele["newFile"]
                + " "
                + work_dir
                + "normalized_"+worker_id + "/"
                + ele["newFile"]
            )
            for method in ele["deleteMethodFull"]:
                if (
                    method in ele["addMethodBegin"].keys()
                    and ele["addMethodBegin"][method] in add_lines
                ):
                    continue
                i = method.find("(")
                methodName = method[:i].split(".")[-1]
                className = method[:i].split(".")[-2]
                parentClassName = " "
                if "$" in className:
                    parentClassName = className.split("$")[0]
                    className = className.split("$")[1]
                if ele["deleteMethodFull"][method]["lineNumber"] == []:
                    old_new_map,new_old_map = get_old_new_map(delete_lines,add_lines)
                    lineNumber = new_old_map[ele["addMethodBegin"][method]]
                else:
                    lineNumber = ele["deleteMethodBegin"][method]
                if methodName == "<init>":
                    methodName = className
                if parentClassName == " ":
                    os.system(
                        "java -jar "
                        + astJar
                        + " "
                        + work_dir
                        + "temp_"+worker_id + "/"
                        + ele["oldFile"]
                        + " "
                        + work_dir
                        + "normalized_"+worker_id + "/"
                        + ele["oldFile"]
                        + " "
                        + methodName
                        + " "
                        + str(lineNumber)
                        + " "
                        + className
                        + " "
                        + parentClassName
                        + " false"
                    )
                else:
                    os.system(
                        "java -jar "
                        + astJar
                        + " "
                        + work_dir
                        + "temp_"+worker_id + "/"
                        + ele["oldFile"]
                        + " "
                        + work_dir
                        + "normalized_"+worker_id + "/"
                        + ele["oldFile"]
                        + " "
                        + methodName
                        + " "
                        + str(lineNumber)
                        + " "
                        + className
                        + " "
                        + parentClassName
                        + " true"
                    )

            for method in ele["addMethodFull"]:
                i = method.find("(")
                methodName = method[:i].split(".")[-1]
                className = method[:i].split(".")[-2]
                parentClassName = " "
                if (
                    method in ele["deleteMethodBegin"].keys()
                    and ele["deleteMethodBegin"][method] in delete_lines
                ):
                    continue
                if "$" in className:
                    parentClassName = className.split("$")[0]
                    className = className.split("$")[1]
                if ele["addMethodFull"][method]["lineNumber"] == []:
                    delete = 1
                    add = 1
                    old_new_map,new_old_map = get_old_new_map(delete_lines,add_lines)
                    lineNumber = old_new_map[ele["deleteMethodBegin"][method]]
                else:
                    lineNumber = ele["addMethodBegin"][method]
                if methodName == "<init>":
                    methodName = className

                if parentClassName == " ":
                    os.system(
                        "java -jar "
                        + astJar
                        + " "
                        + work_dir
                        + "temp_"+worker_id + "/"
                        + ele["newFile"]
                        + " "
                        + work_dir
                        + "normalized_"+worker_id + "/"
                        + ele["newFile"]
                        + " "
                        + methodName
                        + " "
                        + str(lineNumber)
                        + " "
                        + className
                        + " "
                        + parentClassName
                        + " false"
                    )
                else:
                    os.system(
                        "java -jar "
                        + astJar
                        + " "
                        + work_dir
                        + "temp_"+worker_id + "/"
                        + ele["newFile"]
                        + " "
                        + work_dir
                        + "normalized_"+worker_id + "/"
                        + ele["newFile"]
                        + " "
                        + methodName
                        + " "
                        + str(lineNumber)
                        + " "
                        + className
                        + " "
                        + parentClassName
                        + " true"
                    )
                    
    if not os.path.exists(work_dir + "signature_multi_MVP4Version/"):
        os.mkdir(work_dir + "signature_multi_MVP4Version/")
    add_methodNum = []
    deleteMethodNum = []
    changeNum = []
    signatures = {}
    with open(f"method_info_{worker_id}.json", "r") as f:
        json_list = json.load(f)
        for ele in json_list:
            for method in ele["addMethodFull"].keys():
                if method in ele["new2oldChange"].keys():
                    print("新增方法：" + str(method))
                    continue
                if method not in ele["deleteMethodBegin"].keys():
                    i = method.find("(")
                    methodName = method[:i].split(".")[-1]
                    signature = getMethodPrint(
                        work_dir + "temp_"+worker_id + "/" + ele["newFile"],
                        ele["addMethodBegin"][method],
                        ele["addMethodEnd"][method],
                        methodName,sess
                    )
                    if not (signature["syn"] == [] and signature["sem"] == []):
                        method_key = "add__fdse__" + method
                        signatures[method_key] = signature
                    add_methodNum.append(method)
                    continue
                if ele["deleteMethodFull"][method]["lineNumber"] == []:
                    signature = signature_generate_vul_patch(
                        work_dir + "temp_"+worker_id + "/" + ele["oldFile"],
                        work_dir + "temp_"+worker_id + "/" + ele["newFile"],
                        method, sess
                    )
                    if not (
                        signature["vul_syn"] == []
                        and signature["vul_sem"] == []
                        and signature["pat_syn"] == []
                        and signature["pat_sem"] == []
                    ):
                        signatures[method] = signature

            for method in ele["deleteMethodFull"].keys():
                if ele["deleteMethodFull"][method]["lineNumber"] == []:
                    continue
                if (
                    method not in ele["addMethodBegin"].keys()
                    and method not in ele["old2newChange"].keys()
                ):
                    i = method.find("(")
                    methodName = method[:i].split(".")[-1]
                    signature = getMethodPrint(
                        work_dir + "temp_"+worker_id + "/" + ele["oldFile"],
                        ele["deleteMethodBegin"][method],
                        ele["deleteMethodEnd"][method],
                        methodName,sess
                    )
                    if not (signature["syn"] == [] and signature["sem"] == []):
                        method_key = "del__fdse__" + method
                        signatures[method_key] = signature
                    deleteMethodNum.append(method)
                    continue
                method_key = ""
                if method in ele["old2newChange"].keys():
                    method_key = method + "__fdse__" + ele["old2newChange"][method]
                    changeNum.append(method)
                else:
                    method_key = method
                signature = signature_generate_vul_patch(
                    work_dir + "temp_" + worker_id + "/" + ele["oldFile"],
                    work_dir + "temp_" + worker_id + "/" + ele["newFile"],
                    method,sess
                )
                if not (
                    signature["vul_syn"] == []
                    and signature["vul_sem"] == []
                    and signature["pat_syn"] == []
                    and signature["pat_sem"] == []
                ):
                    signatures[method_key] = signature
    with open(work_dir + "signature_multi_MVP4Version/" + CVE_ID + ".json", "w", encoding="utf8") as f:
        json.dump(signatures, f)
    with open(f"methodInfo_{worker_id}.json", "a") as f:
        f.write(
            CVE_ID
            + " "
            + str(add_methodNum)
            + " "
            + str(len(add_methodNum))
            + " "
            + str(deleteMethodNum)
            + " "
            + str(len(deleteMethodNum))
            + " "
            + str(changeNum)
            + str(len(changeNum))
            + "\n"
        )

    print("多方法签名提取成功！")
    if not os.path.exists(work_dir + "temp_"+worker_id + "/"):
        os.system("rm -r " + work_dir + "temp_"+worker_id + "/")
    if not os.path.exists(work_dir + "normalized_"+worker_id + "/"):
        os.system("rm -r " + work_dir + "normalized_"+worker_id + "/")


def dfmp(df, function, columns=None, ordr=True, workers=1, cs=10, desc="Run: ", generator=False, total=None):
    items = df
    it = _dfmp(function, items, ordr, workers, cs, desc, total)
    if generator:
        return it
    else:
        processed = []
        processed.extend(it)
        return processed

def _dfmp(function, items, ordr, workers, cs, desc, total):
    if desc is not None:
        desc = f"({workers} Workers) {desc}"
    with Pool(processes=workers) as p:
        map_func = getattr(p, "imap" if ordr else "imap_unordered")
        it = map_func(function, items, cs)
        if desc is not None:
            try:
                items_len = len(items)
            except:
                if total is not None:
                    items_len = total
                else:
                    items_len = None
            it = tqdm(it, total=items_len, desc=desc)
        yield from it

def preprocess(row, fn, sess):
    CVE_ID, commit_file_location, git_repo_location, work_dir = row["CVE"], row["commit_file_location"], row["git_repo_location"], row["work_dir"]
    fn(CVE_ID, commit_file_location, git_repo_location, work_dir, sess)

def preprocess_whole_df_split(t):
    """
    preprocess one split of the dataframe
    """
    i, split = t
    with open(f"hpc/logs/getgraphs_output_{i}.joernlog", "wb") as lf:
        sess = joern_session.JoernSession(f"fingerprint/{i}", logfile=lf, clean=True, work_dir=config.work_dir)
        try:
            fn = functools.partial(
                gen_fingerprint,
            )
            items = split.to_dict("records")
            position = 0 if not isinstance(i, int) else int(i)
            for row in tqdm(items, desc=f"(worker {i})", position=position):
                preprocess(row, fn, sess)
        finally:
            sess.close()


if __name__ == "__main__":
    df = pd.read_csv("CVEdataset.csv")
    workers = 1
    if workers == 1:
        preprocess_whole_df_split(("all", df))
    else:
        splits = np.array_split(df, workers)
        dfmp(enumerate(splits), preprocess_whole_df_split, ordr=False, workers=workers, cs=1)

    
