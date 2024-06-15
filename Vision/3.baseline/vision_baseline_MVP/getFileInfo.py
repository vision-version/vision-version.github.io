import os
import json
from formatCode import del_comment,del_lineBreak,addBracket
import hashlib
import copy

def detect_get_method_list(detect_dir, detect_file, method_list,work_dir, sess):
    worker_id = sess.worker_id.replace("/","_")
    file_name = detect_file.split("/")[-1]
    os.system("cp " + detect_file + " " + work_dir + "temp_" + worker_id + "/" + file_name)
    
    sess.import_code(work_dir + "temp_" + worker_id + "/" + file_name)
    sess.run_script("metadata", params={"i": str(worker_id)})
    
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    with open(f"./methodInfo/method_{worker_id}.json") as f:
        json_obj = json.load(f)
        for obj in json_obj:
            if "lineNumber" in obj.keys() and obj["fullName"] != ":<global>" and "signature" in obj.keys() and obj["signature"] != "":
                ss = obj["fullName"].split(":")
                i = obj["code"].find("(")
                j = obj["code"].rfind(")")
                if "<unresolvedSignature>" in ss[-1]:
                    method_list.append(
                        [ss[0] + obj["code"][i:j+1], obj["lineNumber"], obj["lineNumberEnd"], ""])
                else:
                    k = ss[-1].find("(")
                    method_list.append(
                        [ss[0] + obj["code"][i:j+1], obj["lineNumber"], obj["lineNumberEnd"], ss[-1][k:]])
    os.system("cp " + work_dir + "temp_" + worker_id + "/" + file_name + " " + work_dir + "normalized_" + worker_id + "/" + file_name)
    method_list_json = []
    flag = True
    for method_info in method_list:
        method = method_info[0]
        i = method.find("(")
        methodName = method[:i].split(".")[-1]
        method_list_json.append({"signature": methodName, "lineNumber": method_info[1], "lineNumberEnd": method_info[2]})
    if method_list_json == []:
        flag = False
        sess.run_script("metadata", params={"i": str(worker_id)})
        
        os.chdir(os.path.dirname(os.path.abspath(__file__)))
        with open(f"./methodInfo/method_{worker_id}.json") as f:
            json_obj = json.load(f)
            for obj in json_obj:
                if "lineNumber" in obj.keys() and obj["fullName"] != ":<global>" and "signature" in obj.keys() and obj["signature"] != "":
                    ss = obj["fullName"].split(":")
                    i = obj["code"].find("(")
                    j = obj["code"].rfind(")")
                    if "<unresolvedSignature>" in ss[-1]:
                        method_list.append(
                            [ss[0] + obj["code"][i:j+1], obj["lineNumber"], obj["lineNumberEnd"], ""])
                    else:
                        k = ss[-1].find("(")
                        method_list.append(
                            [ss[0] + obj["code"][i:j+1], obj["lineNumber"], obj["lineNumberEnd"], ss[-1][k:]])
        os.system("cp " + work_dir + "temp_" + worker_id + "/" + file_name + " " + work_dir + "normalized_" + worker_id + "/" + file_name)
        method_list_json = []
        
        for method_info in method_list:
            method = method_info[0]
            i = method.find("(")
            methodName = method[:i].split(".")[-1]
            method_list_json.append({"signature": methodName, "lineNumber": method_info[1], "lineNumberEnd": method_info[2]})
    with open(f"./methodInfo/method_filtered_{worker_id}.json", "w", encoding="utf8") as f:
        json.dump(method_list_json, f)
    return method_list, flag


def detect_generate_signature(file_name, method_info, cdg_map, ddg_map, work_dir,worker_id):
    func_syn = []
    func_sem = []
    try:
        with open(work_dir + "normalized_" + worker_id + "/" + file_name, "r") as f:
            lines = f.readlines()
            for i in range(method_info[1] + 1, method_info[2] + 1):
                temp_str = lines[i - 1].replace(" ", "").replace("{", "").replace("}", "").replace("\t", "").replace("\n", "")
                if temp_str != "":
                    m = hashlib.md5()
                    m.update(temp_str.encode("utf8"))
                    func_syn.append(m.hexdigest()[:6])
                    
            for key in cdg_map.keys():
                if not method_info[1] + 1 <= key <= method_info[2]:
                    continue
                for line in cdg_map[key]:
                    if method_info[1] + 1 <= line <= method_info[2]:
                        temp_str1 = lines[key - 1].replace(" ", "").replace("{", "").replace("}", "").replace("\t", "").replace("\n", "")
                        temp_str2 = lines[line - 1].replace(" ", "").replace("{", "").replace("}", "").replace("\t", "").replace("\n", "")
                        if temp_str1 != "" and temp_str2 != "":
                            tuple1 = []
                            m = hashlib.md5()
                            m.update(temp_str1.encode("utf8"))
                            tuple1.append(m.hexdigest()[:6])
                            m = hashlib.md5()
                            m.update(temp_str2.encode("utf8"))
                            tuple1.append(m.hexdigest()[:6])
                            tuple1.append("control")
                            func_sem.append(tuple1)
            for key in ddg_map.keys():
                if not method_info[1] + 1 <= key <= method_info[2]:
                    continue
                for line in ddg_map[key]:
                    if method_info[1] + 1 <= line <= method_info[2]:
                        temp_str1 = lines[key - 1].replace(" ", "").replace("{", "").replace("}", "").replace("\t", "").replace("\n", "")
                        temp_str2 = lines[line - 1].replace(" ", "").replace("{", "").replace("}", "").replace("\t", "").replace("\n", "")
                        if temp_str1 != "" and temp_str2 != "":
                            tuple1 = []
                            m = hashlib.md5()
                            m.update(temp_str1.encode("utf8"))
                            tuple1.append(m.hexdigest()[:6])
                            m = hashlib.md5()
                            m.update(temp_str2.encode("utf8"))
                            tuple1.append(m.hexdigest()[:6])
                            tuple1.append("data")
                            func_sem.append(tuple1)
        return func_syn, func_sem
    except Exception as e:
        print(str(e))
        print("Error when detecting file:" + file_name + " ,the method is " + method_info[0] + " at line " + method_info[1].__str__())
        return func_syn, func_sem

def detect_generate_signature_merge(file_name, method_info, cdg_map, ddg_map, work_dir):
    func_syn = {}
    func_sem = {}
    func_merge = {}
    try:
        with open(work_dir + "normalized/" + file_name, "r") as f:
            lines = f.readlines()
            for i in range(method_info[1] + 1, method_info[2] + 1):
                temp_str = lines[i - 1].replace(" ", "").replace("{", "").replace("}", "").replace("\t", "").replace("\n", "")
                if temp_str != "":
                    m = hashlib.md5()
                    m.update(temp_str.encode("utf8"))
                    func_syn[str(i)] = m.hexdigest()[:6]
            for key in cdg_map.keys():
                if not method_info[1] + 1 <= key <= method_info[2]:
                    continue
                for line in cdg_map[key]:
                    if method_info[1] + 1 <= line <= method_info[2]:
                        temp_str1 = lines[key - 1].replace(" ", "").replace("{", "").replace("}", "").replace("\t", "").replace("\n", "")
                        temp_str2 = lines[line - 1].replace(" ", "").replace("{", "").replace("}", "").replace("\t", "").replace("\n", "")
                        if temp_str1 != "" and temp_str2 != "":
                            tuple1 = []
                            m = hashlib.md5()
                            m.update(temp_str1.encode("utf8"))
                            tuple1.append(m.hexdigest()[:6])
                            m = hashlib.md5()
                            m.update(temp_str2.encode("utf8"))
                            tuple1.append(m.hexdigest()[:6])
                            tuple1.append("control")
                            line_tuple_str = str(key) + "__fdse__" + str(line) + "__fdse__control"
                            func_sem[line_tuple_str] = tuple1
                            if str(key) not in func_merge.keys():
                                func_merge[str(key)] = []
                            if str(line) not in func_merge.keys():
                                func_merge[str(line)] = []
                            func_merge[str(key)].append(tuple1)
                            func_merge[str(line)].append(tuple1)
                            
            for key in ddg_map.keys():
                if not method_info[1] + 1 <= key <= method_info[2]:
                    continue
                for line in ddg_map[key]:
                    if method_info[1] + 1 <= line <= method_info[2]:
                        temp_str1 = lines[key - 1].replace(" ", "").replace("{", "").replace("}", "").replace("\t", "").replace("\n", "")
                        temp_str2 = lines[line - 1].replace(" ", "").replace("{", "").replace("}", "").replace("\t", "").replace("\n", "")
                        if temp_str1 != "" and temp_str2 != "":
                            tuple1 = []
                            m = hashlib.md5()
                            m.update(temp_str1.encode("utf8"))
                            tuple1.append(m.hexdigest()[:6])
                            m = hashlib.md5()
                            m.update(temp_str2.encode("utf8"))
                            tuple1.append(m.hexdigest()[:6])
                            tuple1.append("data")
                            line_tuple_str = str(key) + "__fdse__" + str(line) + "__fdse__data"
                            func_sem[line_tuple_str] = tuple1
                            if str(key) not in func_merge.keys():
                                func_merge[str(key)] = []
                            if str(line) not in func_merge.keys():
                                func_merge[str(line)] = []
                            func_merge[str(key)].append(tuple1)
                            func_merge[str(line)].append(tuple1)
                            
        return func_syn, func_sem,func_merge
    except Exception as e:
        print(str(e))
        print("Error when detecting file:" + file_name + " ,the method is " + method_info[0] + " at line " + method_info[1].__str__())