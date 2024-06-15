import json
import os
import sys
import copy
import hashlib
import subprocess
from slicing_multi import detect_slicing1
from getFileInfo import detect_get_method_list,detect_generate_signature
import functools
from multiprocessing import Pool, Lock
import os
import traceback
import pandas as pd
import numpy as np
from tqdm import tqdm
import joern_session
import logging
import time
import config

lock = Lock()
detecteds = []
CVE_dict={}
with open("./infoFile/sagaMulti.json","r") as f:
    cves = json.load(f)
    for cve in cves:
        CVE_dict[cve] = cves[cve]
CVE_sigs = {}
for CVE in os.listdir("./signature"):
    with open("./signature/"+CVE,"r") as f:
        CVE_sigs[CVE.replace(".json","")] = json.load(f)
originalDir = os.path.dirname(os.path.abspath(__file__))


def generate_signature_in_file(detect_dir, file,cnt, work_dir, sess, logger):
    astJar = "./config/AstGen1-0.0.1-SNAPSHOT.jar"
    file_name = file.split("/")[-1]
    extension = ["java"]
    if file_name.split(".")[-1] not in extension:
        return
    test = "test"
    if test.lower() in file.lower():
        return
    method_list = []
    method_list, fullName = detect_get_method_list(detect_dir, file, method_list,work_dir, sess)
    if method_list is None:
        return
    worker_id = sess.worker_id.replace("/","_")
    if fullName:
        sess.run_script("slice_per", params={"i": str(worker_id), "filePath": f"./methodInfo/method_filtered_{worker_id}.json", "fileName": file})
    else:
        sess.run_script("slice_per", params={"i": str(worker_id), "filePath": f"./methodInfo/method_filtered_{worker_id}.json", "fileName": file.replace(detect_dir + "/", "")})
    os.system("cp " + work_dir + "temp_" + worker_id + "/" +
                  file_name + " " + work_dir + "normalized_" + worker_id + "/" + file_name)
    i=0
    index_to_file_dict={}
    for method_info in method_list:
        try:
            cnt += 1
            method = method_info[0]
            j = method.find("(")
            methodName = method[:j].split(".")[-1]
            className = method[:j].split(".")[-2]
            parentClassName = " "

            if '$' in className:
                parentClassName = className.split("$")[0]
                className = className.split("$")[1]

            lineNumber = method_info[1]
            endLineNumber = method_info[2]
            if endLineNumber - lineNumber < 2:
                cnt += 1
                continue
            if methodName == "<init>":
                methodName = className
            if parentClassName == "Iterator<PropertyPath>" or parentClassName == "Function<String,MailboxAnnotation>":
                continue
            if parentClassName == " ":
                cmd = "java -jar " + astJar + " " + work_dir + "temp_" + worker_id + "/" + file_name + " " + work_dir + "normalized_" + worker_id + "/" + file_name + " " + methodName + " " + str(lineNumber) + " " + className + " " + parentClassName + " false"
                out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True).decode("utf-8",errors='replace')
                logger.info(out)
            else:
                cmd = "java -jar " + astJar + " " + work_dir + "temp_" + worker_id + "/" + file_name + " " + work_dir + "normalized_" + worker_id + "/" + file_name + " " + methodName + " " + str(lineNumber) + " " + className + " " + parentClassName + " true"
                out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True).decode("utf-8",errors='replace')
                logger.info(out)

            cdg_map, ddg_map = detect_slicing1(i, worker_id)
            func_syn, func_sem = detect_generate_signature(file_name, method_info, cdg_map, ddg_map, work_dir, worker_id)
            with open("./tempSignature_" + worker_id.__str__() + "/"+cnt.__str__()+".json","w") as f:
                json.dump({"func_syn":func_syn,"func_sem":func_sem, "method_name":method_info[0], "file_name":file},f)
            index_to_file_dict[cnt]={"file_name":file,"method_name":method_info[0],"line_number":method_info[1].__str__()}
            i+=1
        except Exception as e:
            logger.debug(str(e))
            logger.debug("Error when detecting file:" + file + " ,the method is " + method_info[0] + " at line " + method_info[1].__str__())
    return index_to_file_dict




def getSimiliarFiles(repoDir,strict,work_dir, sess):
    time0 = time.time()
    repoName = repoDir.split("/")[-1]

    logger = logging.getLogger(repoName)
    logger.setLevel(logging.DEBUG)
    
    os.chdir(originalDir)
    open("./detectLog/{0}.log".format(repoName), 'w').close()
    file_handler = logging.FileHandler("./detectLog/{0}.log".format(repoName))
    file_handler.setLevel(logging.DEBUG)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    worker_id = sess.worker_id.replace("/","_")    
    if not os.path.exists(f"{work_dir}/temp_" + worker_id):
        os.system(f"mkdir {work_dir}/temp_" + worker_id)
    if not os.path.exists(f"{work_dir}/normalized_" + worker_id):
        os.system(f"mkdir {work_dir}/normalized_" + worker_id)
    CVE_dict_line_number={}
    file_hash_line_number_to_index_dict={}
    lock.acquire()    
    os.system("cp -r " + "./vulFileVersion " + repoDir)
    os.chdir("./saga")
    os.system("rm -r ./logs")
    os.system("rm -r ./result")
    os.system("rm -r ./tokenData")
    if os.path.exists(f'{repoDir}/sig_origin'):
        os.system(f'rm -r {repoDir}/sig_origin')
    cmd = "java -jar ./SAGACloneDetector-small.jar " + repoDir
    out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True).decode("utf-8",errors='replace')
    logger.info(out)
    fileIndex = {}
    with open("./result/MeasureIndex.csv","r") as f:
        lines = f.readlines()
        for line in lines:
            id = line.split(",")[0]
            fileName = line.split(",")[1]
            endLine = line.split(",")[-1]
            fileIndex[id] = fileName
            if "vulFileVersion" in fileName:
                file_hash = fileName.split("/")[-1]
                file_hash_line_number_to_index_dict[file_hash+"__fdse__"+endLine.strip()]=id

    for CVE in CVE_dict.keys():
        CVE_dict_line_number[CVE]=[]
        for ele in CVE_dict[CVE].keys():
            for name in CVE_dict[CVE][ele].keys():
                if CVE_dict[CVE][ele][name]["lineEnd"] - CVE_dict[CVE][ele][name]["lineStart"] <= 2:
                    continue
                if ele+"__fdse__"+str(CVE_dict[CVE][ele][name]["lineEnd"]) in file_hash_line_number_to_index_dict.keys():
                    CVE_dict_line_number[CVE].append(file_hash_line_number_to_index_dict[ele+"__fdse__"+str(CVE_dict[CVE][ele][name]["lineEnd"])])
    zero_CVE_set=set()
    for CVE in CVE_dict_line_number.keys():
        if len(CVE_dict_line_number[CVE])==0:
            zero_CVE_set.add(CVE)
    for CVE in zero_CVE_set:
        del CVE_dict_line_number[CVE]
    clone_dict={}
    logger.info(os.getcwd())
    with open("./result/type12_snippet_result.csv","r",encoding="utf8") as f:
        lines = f.readlines()
        i = 0
        while i < len(lines):
            temp = i
            while temp < len(lines) and lines[temp]!="\n":
                temp += 1
            repo_set = set()
            clone_set = set()
            for cur in range(i,temp):
                file_name = fileIndex[lines[cur].split(",")[1]]
                if "vulFileVersion" in file_name:
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
    with open("./result/type3_snippet_result.csv","r",encoding="utf8") as f:
        lines = f.readlines()
        i = 0
        while i < len(lines):
            temp = i
            while temp < len(lines) and lines[temp]!="\n":
                temp += 1
            repo_set = set()
            clone_set = set()
            for cur in range(i,temp):
                file_name = fileIndex[lines[cur].split(",")[1]]
                if "vulFileVersion" in file_name:
                    clone_set.add(lines[cur].split(",")[1])
                else:
                    repo_set.add(lines[cur].split(",")[1])
            for id in clone_set:
                if id not in clone_dict.keys():
                    clone_dict[id] = set()
                for repo_id in repo_set:
                    clone_dict[id].add(repo_id)
            i = temp + 1
    filtered_dict=dict()
    filtered_file_set=set()
    for cve in CVE_dict_line_number.keys():
        file_set = set()
        for id in CVE_dict_line_number[cve]:
            if id in clone_dict.keys():
                for clone_id in clone_dict[id]:
                    file_name = fileIndex[clone_id]
                    if "vulFileVersion" not in file_name:
                        file_set.add(file_name)
                        filtered_file_set.add(file_name)
        if len(file_set)!=0:
            filtered_dict[cve] = file_set
    lock.release()

    # os.chdir(work_dir)
    total_index_to_method_dict={}
    logger.info(len(filtered_file_set))
    cnt = 0
    for file in filtered_file_set:
        logger.info(file)
        index_to_method_dict=generate_signature_in_file(repoDir, file, cnt, work_dir, sess, logger)
        if index_to_method_dict is None:
            continue
        cnt += len(index_to_method_dict)
        for index in index_to_method_dict:
            total_index_to_method_dict[index]=index_to_method_dict[index]


    sus_method_dict={}
    for index in total_index_to_method_dict.keys():
        with open("./tempSignature_" + worker_id.__str__() + "/"+index.__str__()+".json","r") as f:
            sus_method_dict[index]=json.load(f)
            
    for CVE in filtered_dict:
        sig=CVE_sigs[CVE]
        match_dict={}
        for key in sig.keys():
            if key.count("__fdse__")<=1 and not (key.startswith("del__fdse__") or key.startswith("add__fdse__")):
                logger.info(CVE + " " + key)
                delete_lines=sig[key]["deleteLines"]
                vul_syn=sig[key]["vul_syn"]
                vul_sem=sig[key]["vul_sem"]
                pat_syn=sig[key]["pat_syn"]
                pat_sem=sig[key]["pat_sem"]
                split_list=key.split("__fdse__")
                
                match_dict[CVE+"__fdse__"+split_list[0]]=[]
                for index in sus_method_dict:
                    sus_method_syn=copy.deepcopy(sus_method_dict[index]["func_syn"])
                    sus_method_sem=copy.deepcopy(sus_method_dict[index]["func_sem"])
                    method = total_index_to_method_dict[index]["method_name"]
                    logger.info(str(index) + method)
                    is_match=True
                    
                    for line in delete_lines:
                        if line not in sus_method_syn:
                            is_match=False
                        else:
                            sus_method_syn.remove(line)                    
                    sus_method_syn=copy.deepcopy(sus_method_dict[index]["func_syn"])
                    sus_method_sem=copy.deepcopy(sus_method_dict[index]["func_sem"])
                    cnt_vul_syn = 0
                    for syn in vul_syn:
                        if syn in sus_method_syn:
                            sus_method_syn.remove(syn)
                            cnt_vul_syn += 1
                    if len(set(vul_syn)) > 0:
                        logger.info(cnt_vul_syn / len(vul_syn))
                        logger.info(is_match)
                    if len(set(vul_syn)) > 0 and cnt_vul_syn / len(vul_syn) <= 0.7:
                        is_match=False
                        
                    cnt_match_vul_sem = 0
                    for three_tuple_vul_sem in vul_sem:
                        if three_tuple_vul_sem in sus_method_sem:
                            sus_method_sem.remove(three_tuple_vul_sem)
                            cnt_match_vul_sem += 1
                    if len(vul_sem) > 0:
                        logger.info(cnt_match_vul_sem/len(vul_sem))
                        logger.info(is_match)
                    if len(vul_sem)!=0 and cnt_match_vul_sem/len(vul_sem)<=0.7:
                        is_match=False

                    if strict:
                        
                        sus_method_syn=copy.deepcopy(sus_method_dict[index]["func_syn"])
                        sus_method_sem=copy.deepcopy(sus_method_dict[index]["func_sem"])
                        cnt_pat_syn = 0
                        for syn in pat_syn:
                            if syn in sus_method_syn:
                                sus_method_syn.remove(syn)
                                cnt_pat_syn += 1
                        if len(set(pat_syn)) > 0:
                            logger.info(cnt_pat_syn / len(pat_syn))
                            logger.info(is_match)                    
                        if len(set(pat_syn)) > 0 and cnt_pat_syn / len(pat_syn) > 0.3:
                            is_match=False
                            
                        cnt_match_pat_sem = 0
                        for three_tuple_pat_sem in pat_sem:
                            if three_tuple_pat_sem in sus_method_sem:
                                sus_method_sem.remove(three_tuple_pat_sem)
                                cnt_match_pat_sem += 1
                        if len(pat_sem) > 0:
                            logger.info(cnt_match_pat_sem / len(pat_sem))
                            logger.info(is_match)
                        if len(pat_sem) > 0 and cnt_match_pat_sem / len(pat_sem) > 0.3:
                            is_match=False
                    if is_match:                      
                        match_dict[CVE+"__fdse__"+split_list[0]].append(index)
            elif key.startswith("del__fdse__"):
                
                syn_sig=sig[key]["syn"]
                sem_sig=sig[key]["sem"]
                if len(sem_sig) == 0:
                    continue
                split_list=key.split("__fdse__")
                
                match_dict[CVE+"__fdse__"+split_list[1]]=[]
                for index in sus_method_dict:
                    sus_method_syn=copy.deepcopy(sus_method_dict[index]["func_syn"])
                    sus_method_sem=copy.deepcopy(sus_method_dict[index]["func_sem"])
                    is_match=True

                    cnt_vul_syn = 0
                    for syn in syn_sig:
                        if syn in sus_method_syn:
                            sus_method_syn.remove(syn)
                            cnt_vul_syn += 1
                    if len(set(syn_sig)) > 0:
                        logger.info(cnt_vul_syn / len(syn_sig))
                
                    if len(set(syn_sig)) > 0 and cnt_vul_syn / len(syn_sig) <= 0.7:
                        is_match=False

                    cnt_match_vul_sem = 0
                    for three_tuple_pat_sem in sem_sig:
                        if three_tuple_pat_sem in sus_method_sem:
                            sus_method_sem.remove(three_tuple_pat_sem)
                            cnt_match_vul_sem += 1
                    if len(sem_sig)!=0 and cnt_match_vul_sem/len(sem_sig)<=0.7:
                        logger.info("not match sem")
                        is_match=False
                    if is_match:
                        match_dict[CVE+"__fdse__"+split_list[1]].append(index)
        CVE_is_match=False
        for key in match_dict.keys():
            if(len(match_dict[key])!=0):
                CVE_is_match=True
                break
        if CVE_is_match:
            with open("resultMultiSnippetVersion.txt","a",encoding="utf8") as f:
                f.write("Found "+CVE+" in "+repoDir+"!\n")
                logger.info("Found "+CVE+" in "+repoDir+"!\n")
                for key in match_dict.keys():
                    f.write("Method "+key+" matches the following methods:\n")
                    logger.info("Method "+key+" matches the following methods:\n")
                    for id in match_dict[key]:
                        method_info=total_index_to_method_dict[id]
                        f.write("Method "+method_info["method_name"]+" in file "+method_info["file_name"]+" at line "+method_info["line_number"]+".\n")
                        logger.info("Method "+method_info["method_name"]+" in file "+method_info["file_name"]+" at line "+method_info["line_number"]+".\n")
                f.write("\n")
    
    os.system(f'rm -r {repoDir}/vulFileVersion/')
    time1 = time.time()
    logger.info("Elapsed time:{0} to detect {1}".format(str(time1 - time0), repoDir))
    os.system(f"rm {work_dir}/temp_{worker_id}/*")
    os.system(f"rm {work_dir}/normalized_{worker_id}/*")
    os.system(f"rm ./tempSignature_{worker_id}/*")


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
    detect_dir, work_dir = row["detect_dir"], row["work_dir"]
    with open("run.txt","a") as f:
        f.write(sess.worker_id + " " + detect_dir + "\n")
    fn(detect_dir, True, work_dir, sess)

def preprocess_whole_df_split(t):
    """
    preprocess one split of the dataframe
    """
    i, split = t
    with open(f"hpc/logs/detect_output_{i}.joernlog", "wb") as lf:
        sess = joern_session.JoernSession(f"fingerprint/{i}", logfile=lf, clean=True, work_dir=config.work_dir)
        worker_id = sess.worker_id.replace("/","_")
        if not os.path.exists(f"./slicingJson_" + worker_id):
            os.system(f"mkdir ./slicingJson_" + worker_id)
        if not os.path.exists(f"./tempSignature_" + worker_id):
            os.system(f"mkdir ./tempSignature_" + worker_id)
        try:
            fn = functools.partial(
                getSimiliarFiles,
            )
            items = split.to_dict("records")
            position = 0 if not isinstance(i, int) else int(i)
            for row in tqdm(items, desc=f"(worker {i})", position=position):
                preprocess(row, fn, sess)
        finally:
            sess.close()
    

if __name__=="__main__":
    detecteds = []
    needRerun = []
    cnt = 0
    for detected in os.listdir("./detectLog"):
        if detected.replace(".log","") in detecteds:
            continue
        f = open("./detectLog/" + detected)
        lines = f.readlines()
        j = len(lines) - 1
        cnt += 1
        while j>=0 and lines[j] == "\n":
            j -= 1 
        if j>=0 and "Elapsed time:" in lines[j]:
            detecteds.append(detected.replace(".log",""))
    with open("done_1.json","w") as f:
        json.dump(detecteds,f)
    df = pd.read_csv("targetList.csv")
    notRun = []
    already_run = []
    no_cpg = []
    for i, row in df.iterrows():
        if row["detect_dir"].split("/")[-1] not in detecteds:
            notRun.append(row.to_dict())
    print(f"there is {len(notRun)} need to run")
    df_need_run = pd.DataFrame(notRun)
    workers = 1
    if workers == 1:
        preprocess_whole_df_split(("all", df_need_run))
    else:
        splits = np.array_split(df_need_run, workers)
        dfmp(enumerate(splits), preprocess_whole_df_split, ordr=False, workers=workers, cs=1)
    time1 = time.time()
    print("Elapsed time:{0}".format(str(time1 - time0)))