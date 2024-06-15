import os
from icecream import ic
import json

from joern_utils.CPGWorkspace import CPGWorkspace

joern_dir = "../joern-cli"


def joern_method_parse(joern_methods):
    method_list = []
    for obj in joern_methods:
        if "lineNumber" in obj.keys() and obj["fullName"] != ":<global>":
            method_dict = {}
            ss = obj["fullName"].split(":")
            i = obj["code"].find("(")
            j = obj["code"].rfind(")")
            method_dict["filename"] = obj["filename"]
            method_dict["originalFullName"] = obj["fullName"]
            method_dict["fullName"] = ss[0] + obj["code"][i : j + 1]
            method_dict["paramType"] = obj["code"][i : j + 1]
            if obj["lineNumber"] == obj["lineNumberEnd"]:
                continue
            method_dict["lineStart"] = obj["lineNumber"]
            method_dict["lineEnd"] = obj["lineNumberEnd"]
            method_list.append(method_dict)  
    return method_list


def method_line_parse(change_info, method_list, file_path: str = ""):
    dictFull = {}
    method_begin = {}
    method_end = {}
    outmethod_line = []

    for lineNo, codeContent in change_info.items():
        method_contained = False
        for method in method_list:

            # lineNo = list(line.keys())[0]

            if file_path in method["filename"] and method["lineStart"] <= lineNo <= method["lineEnd"]:
                method_contained = True
                if method["fullName"] not in method_begin.keys():
                    method_begin[method["fullName"]] = method["lineStart"]
                if method["fullName"] not in method_end.keys():
                    method_end[method["fullName"]] = method["lineEnd"]
                if method["fullName"] not in dictFull.keys():
                    dictFull[method["fullName"]] = {}
                    dictFull[method["fullName"]]["lineNumber"] = []
                    dictFull[method["fullName"]]["paramType"] = method["paramType"]
                    dictFull[method["fullName"]]["originalFullName"] =  method["originalFullName"]
                dictFull[method["fullName"]]["lineNumber"].append({lineNo: codeContent})
        if not method_contained: 
            outmethod_line.append({lineNo: codeContent})
    return method_begin, method_end, dictFull, outmethod_line



def methods_extract(cve, local_repo_path, work_dir, diff_files, commit_hash, cpgWorkspace: CPGWorkspace):
    '''

    '''
    old_methods = []
    new_methods = []


    with open("github_path_whitelist.json", "r") as fr:
        githubWhiteList = json.load(fr)
    if cve in githubWhiteList:
        githubCPGPath = githubWhiteList[cve]
    else:
        githubCPGPath = local_repo_path
    

    old_file_lst = []
    for diff_file_pair in diff_files:
        old_file_lst.append(os.path.join(local_repo_path,diff_file_pair[0]))
    old_save_path = cpgWorkspace.generateCPG(cve = cve, filepath=githubCPGPath, status='old', commit_hash=commit_hash, modified_files = old_file_lst, overwrite=True)
    cpgWorkspace.joernScript(script_path="metadata.sc", params=f"cpgFile={old_save_path},Status=old")

    with open("./old_method.json") as f:
        json_obj = json.load(f)
    old_method_list = joern_method_parse(json_obj)

    new_file_lst = []
    for diff_file_pair in diff_files:
        new_file_lst.append(os.path.join(local_repo_path,diff_file_pair[1]))
    new_save_path = cpgWorkspace.generateCPG(cve = cve, filepath=githubCPGPath, status='new', commit_hash=commit_hash, modified_files = new_file_lst, overwrite=True)
    cpgWorkspace.joernScript(script_path="metadata.sc", params=f"cpgFile={new_save_path},Status=new")

    with open("./new_method.json") as f:
        json_obj = json.load(f)
    new_method_list = joern_method_parse(json_obj)


    for diff_file_pair in diff_files:
        old_file_path = diff_file_pair[0]
        new_file_path = diff_file_pair[1]
        os.chdir(local_repo_path)
        info = {
            "add": {},
            "delete": {}
        }
        os.makedirs(os.path.join(work_dir, "temp_diff"), exist_ok=True)

        normalizedOldFileName = old_file_path.split("/")[-1]
        normalizedNewFileName = new_file_path.split("/")[-1]
        
        # os.system(
        #     ic(
        #     "git diff -w" 
        #     +f"{commit_hash}^:"
        #     + old_file_path
        #     + " "
        #     + f"{commit_hash}:"
        #     + new_file_path
        #     + " > "
        #     + os.path.join(f"{work_dir}", "temp_diff/")
        #     + old_file_path.split("/")[-1]
        #     + "__split__"
        #     + new_file_path.split("/")[-1]
        #     + ".txt")
        # )
        os.chdir(work_dir)
        ic(os.getcwd())
        os.system(
            ic(
            "git diff --no-index -w " 
            + f"./github_diff/{cve}/oldfiles/" + normalizedOldFileName + " "
            + f"./github_diff/{cve}/newfiles/" + normalizedNewFileName
            + " > " + "temp_diff/"
            + cve + "__split__" + normalizedOldFileName + "__split__" + normalizedNewFileName + ".txt")
        )
        add_line = 0
        delete_line = 0
        

        commits = open(
            "temp_diff/" + cve + "__split__" + normalizedOldFileName + "__split__" + normalizedNewFileName + ".txt", "r"
        )
        lines = commits.readlines()

        # deleted_code_lines = {}
        for line in lines:
            if line.startswith("@@"):
                delete_line = int(line.split("-")[1].split(",")[0]) - 1
                add_line = int(line.split("+")[1].split(",")[0]) - 1
            elif line.startswith("+") and not line.startswith("+++"):
                add_line += 1
                info["add"][add_line] = line.strip()[1:].strip()
            elif line.startswith("-") and not line.startswith("---"):
                delete_line += 1
                info["delete"][delete_line] = line.strip()[1:].strip()
            else:
                add_line += 1
                delete_line += 1
        print(info)
        delete_begin, delete_end, delete_dictFull, delet_outmethod_line = method_line_parse(info["delete"], old_method_list, old_file_path)
        add_begin, add_end, add_dictFull, add_outmethod_line = method_line_parse(info["add"], new_method_list, new_file_path)
        # os.system("rm cpg.bin")
        # os.system("rm old_method.json")

        # os.system("rm cpg.bin")
        # os.system("rm new_method.json")

        old_methods.append({
            "oldFilePath": old_file_path,
            "deleteMethodBegin": delete_begin,
            "deleteMethodEnd": delete_end,
            "deleteMethodFull": delete_dictFull
        })

        new_methods.append({
            "newFilePath": new_file_path,
            "addMethodBegin": add_begin,
            "addMethodEnd": add_end,
            "addMethodFull": add_dictFull
        })

    return old_methods, new_methods



if __name__ == "__main__":
    local_repo_path = 'GithubCache/apache__split__maven-shared-utils'
    work_dir = '2.methodology/patch_callchain_generate'
    commit = 'f751e614c09df8de1a080dc1153931f3f68991c9'
    diff_files = [('src/main/java/org/apache/maven/shared/utils/cli/shell/BourneShell.java',
                  'src/main/java/org/apache/maven/shared/utils/cli/shell/BourneShell.java'),
                 ('src/main/java/org/apache/maven/shared/utils/cli/shell/Shell.java',
                  'src/main/java/org/apache/maven/shared/utils/cli/shell/Shell.java')]
    methods_extract(local_repo_path, work_dir, diff_files, commit)