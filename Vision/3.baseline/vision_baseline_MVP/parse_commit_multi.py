import os
import json
from formatCode import del_comment,del_lineBreak,addBracket
import config


originalDir = os.path.dirname(os.path.abspath(__file__))
def readCommit(CVE_ID, location, git_repo_location, work_dir, sess):
    method_info = []
    with open(location, "r", encoding="utf8") as f:
        lines = f.readlines()
        files = []
        file_seperator = []
        for i in range(len(lines)):
            if lines[i].startswith("diff --git"):
                file_seperator.append(i)
        for i in range(len(file_seperator) - 1):
            files.append(lines[file_seperator[i] : file_seperator[i + 1] - 1])
        files.append(lines[file_seperator[len(file_seperator) - 1] : len(lines)])
    worker_id = sess.worker_id.replace("/","_")
    for file in files:
        parseFile(CVE_ID, file, method_info, git_repo_location, work_dir, sess)
    with open(f"method_info_{worker_id}.json", "w") as f:
        json.dump(method_info, f)

    with open(f"method_multi_{worker_id}.json", "a") as f:
        json.dump(method_info, f)


def parseFile(CVE_ID, file, method_info, git_repo_location, work_dir, sess):
    worker_id = sess.worker_id.replace("/","_")
    extension = ["java"]
    info = {}
    info["oldFileName"] = file[0].split(" ")[2]
    info["newFileName"] = file[0].split(" ")[3][:-1]
    if (
        info["oldFileName"].split(".")[-1] not in extension
        or info["newFileName"].split(".")[-1] not in extension
    ):
        return
    test = "test"
    infos = info["oldFileName"].lower().split("/")
    infos_new = info["newFileName"].lower().split("/")
    flag_old = True 
    flag_new = True  
    if (
        test.lower() in infos
        or test.lower() in infos_new
        or test.lower() in infos[-1]
        or test.lower() in infos_new[-1]
    ):
        return
    if file[1].startswith("old mode"):
        info["oldCommit"] = file[3].split(" ")[1].split("..")[0].replace("\n", "")
        info["newCommit"] = file[3].split(" ")[1].split("..")[1].replace("\n", "")
    elif file[1].startswith("new file mode"): 
        info["oldCommit"] = file[2].split(" ")[1].split("..")[0].replace("\n", "")
        info["newCommit"] = file[2].split(" ")[1].split("..")[1].replace("\n", "")
        flag_old = False
    elif file[1].startswith("similarity index"):
        return
    elif file[1].startswith("deleted file mode"):
        info["oldCommit"] = file[2].split(" ")[1].split("..")[0].replace("\n", "")
        info["newCommit"] = file[2].split(" ")[1].split("..")[1].replace("\n", "")
        flag_new = False
    else:
        info["oldCommit"] = file[1].split(" ")[1].split("..")[0]
        info["newCommit"] = file[1].split(" ")[1].split("..")[1]

    if "00000000" in info["oldCommit"]:
        flag_old = False
    elif "00000000" in info["newCommit"]:
        flag_new = False
    old_name = info["oldCommit"] + "-" + info["oldFileName"].split("/")[-1]
    new_name = info["newCommit"] + "-" + info["newFileName"].split("/")[-1]
    info["oldCommit"] += " -- " + info["oldFileName"].split("/")[-1]
    info["newCommit"] += " -- " + info["newFileName"].split("/")[-1]
    info["add"] = []
    info["delete"] = []
    os.chdir(git_repo_location)
    try:
        if not flag_old:
            os.system(
                "git show " + info["newCommit"] + " > " + work_dir + "temp_"+worker_id + "/" + new_name
            )
            del_comment(work_dir + "temp_"+worker_id + "/" + new_name)
            del_lineBreak(work_dir + "temp_"+worker_id + "/" + new_name)
            empty_line = addBracket(work_dir + "temp_"+worker_id + "/" + new_name)
            empty_line_old = []
        elif not flag_new:
            if not os.path.exists(work_dir + "vulFileVersion/" + CVE_ID):
                os.system("mkdir -pv " +work_dir + "vulFileVersion/" + CVE_ID)
            os.system(
                "git show "
                + info["oldCommit"]
                + " > "
                + work_dir
                + "vulFileVersion/"
                + CVE_ID
                + "/"
                + old_name
            )
            os.system(
                "git show " + info["oldCommit"] + " > " + work_dir + "temp_"+worker_id + "/" + old_name
            )
            os.system("mv " + new_name + " " + work_dir + "temp_"+worker_id + "/" + new_name)
            del_comment(work_dir + "temp_"+worker_id + "/" + old_name)
            del_lineBreak(work_dir + "temp_"+worker_id + "/" + old_name)
            empty_line_old = addBracket(
                work_dir + "temp_"+worker_id + "/" + old_name
            )
            del_comment(work_dir + "vulFileVersion/" + CVE_ID + "/" + old_name)
            del_lineBreak(work_dir + "vulFileVersion/" + CVE_ID + "/" + old_name)
            empty_line_old = addBracket(
                work_dir + "vulFileVersion/" + CVE_ID + "/" + old_name
            )
            empty_line = []
        else:
            if not os.path.exists(work_dir + "vulFileVersion/" + CVE_ID):
                os.system("mkdir -pv " +work_dir + "vulFileVersion/" + CVE_ID)
            os.system(
                "git show " + info["oldCommit"] + " > " + work_dir + "temp_"+worker_id + "/" + old_name
            )
            os.system(
                "git show "
                + info["oldCommit"]
                + " > "
                + work_dir
                + "vulFileVersion/"
                + CVE_ID
                + "/"
                + old_name
            )
            os.system(
                "git show " + info["newCommit"] + " > " + work_dir + "temp_"+worker_id + "/" + new_name
            )
            del_comment(work_dir + "temp_"+worker_id + "/" + new_name)
            del_comment(work_dir + "temp_"+worker_id + "/" + old_name)
            del_lineBreak(work_dir + "temp_"+worker_id + "/" + new_name)
            del_lineBreak(work_dir + "temp_"+worker_id + "/" + old_name)
            empty_line = addBracket(work_dir + "temp_"+worker_id + "/" + new_name)
            empty_line_old = addBracket(
                work_dir + "temp_"+worker_id + "/" + old_name
            )
            del_comment(work_dir + "vulFileVersion/" + CVE_ID + "/" + old_name)
            del_lineBreak(work_dir + "vulFileVersion/" + CVE_ID + "/" + old_name)
            empty_line_old = addBracket(
                work_dir + "vulFileVersion/" + CVE_ID + "/" + old_name
            )
    except Exception as e:
        print("format Error!!")
        print(e)

    os.system(
        "git diff -w "
        + work_dir
        + "temp_"+worker_id + "/"
        + old_name
        + " "
        + work_dir
        + "temp_"+worker_id + "/"
        + new_name
        + " > "
        + work_dir
        + "temp_commit/"
        + old_name
        + "__fdse__"
        + new_name
        + ".txt"
    )
    add_line = 0
    delete_line = 0
    commits = open(
        work_dir + "temp_commit/" + old_name + "__fdse__" + new_name + ".txt", "r"
    )
    lines = commits.readlines()

    for line in lines:
        if line.startswith("@@"):
            delete_line = int(line.split("-")[1].split(",")[0]) - 1
            add_line = int(line.split("+")[1].split(",")[0]) - 1
        elif line.startswith("+") and not line.startswith("+++"):
            add_line += 1
            info["add"].append(add_line)
        elif line.startswith("-") and not line.startswith("---"):
            delete_line += 1
            info["delete"].append(delete_line)
        else:
            add_line += 1
            delete_line += 1
    sess.import_code(work_dir + "temp_"+worker_id + "/" + old_name)
    os.chdir(originalDir)
    sess.run_script("metadata", params={"i": str(worker_id)})
    method_list = []
    old_method_begin = {}
    old_method_end = {}
    os.chdir(originalDir)
    with open(f"./methodInfo/method_{worker_id}.json") as f:
        json_obj = json.load(f)
        for obj in json_obj:
            if "lineNumber" in obj.keys() and obj["fullName"] != ":<global>":
                method_dict = {}
                ss = obj["fullName"].split(":")
                i = obj["code"].find("(")
                j = obj["code"].rfind(")")
                method_dict["fullName"] = ss[0] + obj["code"][i : j + 1]
                old_method_begin[method_dict["fullName"]] = obj["lineNumber"]
                old_method_end[method_dict["fullName"]] = obj["lineNumberEnd"]
                method_dict["paramType"] = obj["code"][i : j + 1]
                if obj["lineNumber"] == obj["lineNumberEnd"]:
                    continue
                method_dict["lineStart"] = obj["lineNumber"]
                method_dict["lineEnd"] = obj["lineNumberEnd"]
                method_list.append(method_dict)
    delete_dictFull = {}
    delete_begin = {}
    delete_end = {}
    for line in info["delete"]:
        for method in method_list:
            if method["lineStart"] <= line <= method["lineEnd"]:
                if method["fullName"] not in delete_begin.keys():
                    delete_begin[method["fullName"]] = method["lineStart"]
                if method["fullName"] not in delete_end.keys():
                    delete_end[method["fullName"]] = method["lineEnd"]
                if method["fullName"] not in delete_dictFull.keys():
                    delete_dictFull[method["fullName"]] = {}
                    delete_dictFull[method["fullName"]]["lineNumber"] = []
                    delete_dictFull[method["fullName"]]["paramType"] = method[
                        "paramType"
                    ]
                delete_dictFull[method["fullName"]]["lineNumber"].append(line)

    this_method_info_dict = {}
    this_method_info_dict["oldFile"] = old_name
    this_method_info_dict["deleteMethodBegin"] = delete_begin
    this_method_info_dict["deleteMethodEnd"] = delete_end
    this_method_info_dict["deleteMethodFull"] = delete_dictFull
    sess.import_code(work_dir + "temp_"+worker_id + "/" + new_name)
    sess.run_script("metadata", params={"i": str(worker_id)})
    method_list_new = []
    new_method_begin = {}
    new_method_end = {}
    os.chdir(originalDir)
    with open(f"./methodInfo/method_{worker_id}.json") as f:
        json_obj = json.load(f)
        for obj in json_obj:
            if "lineNumber" in obj.keys() and obj["fullName"] != ":<global>":
                method_dict = {}
                ss = obj["fullName"].split(":")
                i = obj["code"].find("(")
                j = obj["code"].rfind(")")
                method_dict["fullName"] = ss[0] + obj["code"][i : j + 1]
                method_dict["paramType"] = obj["code"][i : j + 1]
                if obj["lineNumber"] == obj["lineNumberEnd"]:
                    continue
                new_method_begin[method_dict["fullName"]] = obj["lineNumber"]
                new_method_end[method_dict["fullName"]] = obj["lineNumberEnd"]
                method_dict["lineStart"] = obj["lineNumber"]
                method_dict["lineEnd"] = obj["lineNumberEnd"]
                method_list_new.append(method_dict)
    add_dict_full = {}
    add_begin = {}
    add_end = {}
    for line in info["add"]:
        for method in method_list_new:
            if method["lineStart"] <= line <= method["lineEnd"]:
                if method["fullName"] not in add_begin.keys():
                    add_begin[method["fullName"]] = method["lineStart"]
                if method["fullName"] not in add_end.keys():
                    add_end[method["fullName"]] = method["lineEnd"]
                if method["fullName"] not in add_dict_full.keys():
                    add_dict_full[method["fullName"]] = {}
                    add_dict_full[method["fullName"]]["lineNumber"] = []
                    add_dict_full[method["fullName"]]["paramType"] = method["paramType"]
                add_dict_full[method["fullName"]]["lineNumber"].append(line)

    this_method_info_dict["newFile"] = new_name
    this_method_info_dict["addMethodBegin"] = add_begin
    this_method_info_dict["addMethodEnd"] = add_end
    this_method_info_dict["addMethodFull"] = add_dict_full
    this_method_info_dict["delete"] = info["delete"]
    this_method_info_dict["add"] = info["add"]
    changeMethods = {}
    for method in this_method_info_dict["addMethodFull"].keys():
        if method not in this_method_info_dict["deleteMethodFull"].keys():
            if (
                len(this_method_info_dict["addMethodFull"][method]["lineNumber"])
                != add_end[method] - add_begin[method] + 1
            ):
                cnt = add_end[method] - add_begin[method] + 1
                for i in empty_line:
                    if (
                        add_begin[method] <= i <= add_end[method]
                        and i
                        not in this_method_info_dict["addMethodFull"][method][
                            "lineNumber"
                        ]
                    ):
                        cnt -= 1
                if (
                    len(this_method_info_dict["addMethodFull"][method]["lineNumber"])
                    != cnt
                ):
                    method_raw_lineNumber = set(
                        range(add_begin[method], add_end[method] + 1)
                    )
                    method_change_lineNumber = set(
                        this_method_info_dict["addMethodFull"][method]["lineNumber"]
                    )
                    changeMethods[method] = method_raw_lineNumber.difference(
                        method_change_lineNumber
                    )
                else:
                    this_method_info_dict["deleteMethodFull"][method] = {}
                    this_method_info_dict["deleteMethodFull"][method][
                        "paramType"
                    ] = this_method_info_dict["addMethodFull"][method]["paramType"]
                    this_method_info_dict["deleteMethodFull"][method]["lineNumber"] = []
            else:
                this_method_info_dict["deleteMethodFull"][method] = {}
                this_method_info_dict["deleteMethodFull"][method][
                    "paramType"
                ] = this_method_info_dict["addMethodFull"][method]["paramType"]
                this_method_info_dict["deleteMethodFull"][method]["lineNumber"] = []
    changeMethods_old = {}
    for method in this_method_info_dict["deleteMethodFull"].keys():
        if method not in this_method_info_dict["addMethodFull"].keys():
            if (
                len(this_method_info_dict["deleteMethodFull"][method]["lineNumber"])
                != delete_end[method] - delete_begin[method] + 1
            ):
                cnt = delete_end[method] - delete_begin[method] + 1
                for i in empty_line_old:
                    if (
                        delete_begin[method] <= i <= delete_end[method]
                        and i
                        not in this_method_info_dict["deleteMethodFull"][method][
                            "lineNumber"
                        ]
                    ):
                        cnt -= 1
                if (
                    len(this_method_info_dict["deleteMethodFull"][method]["lineNumber"])
                    != cnt
                ):
                    method_raw_lineNumber = set(
                        range(delete_begin[method], delete_end[method] + 1)
                    )
                    method_change_lineNumber = set(
                        this_method_info_dict["deleteMethodFull"][method]["lineNumber"]
                    )
                    changeMethods_old[method] = method_raw_lineNumber.difference(
                        method_change_lineNumber
                    )
                else:
                    this_method_info_dict["addMethodFull"][method] = {}
                    this_method_info_dict["addMethodFull"][method]["lineNumber"] = []
                    this_method_info_dict["addMethodFull"][method][
                        "paramType"
                    ] = this_method_info_dict["deleteMethodFull"][method]["paramType"]
            else:
                this_method_info_dict["addMethodFull"][method] = {}
                this_method_info_dict["addMethodFull"][method]["lineNumber"] = []
                this_method_info_dict["addMethodFull"][method][
                    "paramType"
                ] = this_method_info_dict["deleteMethodFull"][method]["paramType"]
    old2newChange, new2oldChange, new_old_map, old_new_map = getChangeMethod(
        changeMethods, changeMethods_old, this_method_info_dict
    )
    this_method_info_dict["old2newChange"] = old2newChange
    this_method_info_dict["new2oldChange"] = new2oldChange
    for changeMethod in changeMethods.keys():
        if changeMethod not in this_method_info_dict["new2oldChange"].keys():
            this_method_info_dict["deleteMethodFull"][changeMethod] = {}
            this_method_info_dict["deleteMethodFull"][changeMethod][
                "paramType"
            ] = this_method_info_dict["addMethodFull"][changeMethod]["paramType"]
            this_method_info_dict["deleteMethodFull"][changeMethod]["lineNumber"] = []
            if new_method_begin[changeMethod] in new_old_map.keys():
                this_method_info_dict["deleteMethodBegin"][changeMethod] = new_old_map[
                    new_method_begin[changeMethod]
                ]
                if new_method_end[changeMethod] in new_old_map.keys():
                    this_method_info_dict["deleteMethodEnd"][
                        changeMethod
                    ] = new_old_map[new_method_end[changeMethod]]
    for changeMethod_old in changeMethods_old.keys():
        if changeMethod_old not in this_method_info_dict["old2newChange"].keys():
            this_method_info_dict["addMethodFull"][changeMethod_old] = {}
            this_method_info_dict["addMethodFull"][changeMethod_old]["lineNumber"] = []
            this_method_info_dict["addMethodFull"][changeMethod_old][
                "paramType"
            ] = this_method_info_dict["deleteMethodFull"][changeMethod_old]["paramType"]
            if old_method_begin[changeMethod_old] in old_new_map.keys():
                this_method_info_dict["addMethodBegin"][changeMethod_old] = old_new_map[
                    old_method_begin[changeMethod_old]
                ]
                if old_method_end[changeMethod_old] in old_new_map.keys():
                    this_method_info_dict["addMethodEnd"][
                        changeMethod_old
                    ] = old_new_map[old_method_end[changeMethod_old]]
    method_info.append(this_method_info_dict)


def get_old_new_map(delete_lines,add_lines):
    old_new_map = {}
    new_old_map = {}
    delete = 1
    add = 1
    for i in range(1, 10000):
        while delete in delete_lines:
            delete += 1
        while add in add_lines:
            add += 1
        old_new_map[delete] = add
        new_old_map[add] = delete
        delete += 1
        add += 1
    return old_new_map, new_old_map

def getChangeMethod(changeMethods, changeMethods_old, this_method_info_dict):
    old2newChange = {}
    new2oldChange = {}
    delete_lines = this_method_info_dict["delete"]
    add_lines = this_method_info_dict["add"]
    old_new_map,new_old_map = get_old_new_map(delete_lines,add_lines)

    vis = []
    for changeMethod in changeMethods.keys():
        for changeMethod_old in changeMethods_old.keys():
            if changeMethod_old in vis:
                continue
            for i in changeMethods[changeMethod]:
                if new_old_map[i] in changeMethods_old[changeMethod_old]:
                    vis.append(changeMethod_old)
                    old2newChange[changeMethod_old] = changeMethod
                    new2oldChange[changeMethod] = changeMethod_old
                    break
            if changeMethod_old in vis:
                break

    return old2newChange, new2oldChange, new_old_map, old_new_map
