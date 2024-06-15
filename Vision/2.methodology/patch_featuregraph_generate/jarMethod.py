import json
import os, sys
import subprocess
from joern_utils.CPGWorkspace import CPGWorkspace
from icecream import ic
'''

'''

def methods_extract(cve, status, joernBinPath, githubJarMapMethods, cpgWorkspace: CPGWorkspace, joernPath):
    '''

    '''

    os.chdir(joernPath)
    
    methods = []

    print(f"{joernPath}:::{os.getcwd()}")
    os.system(f"rm -f ./{status}_method.json")

    # cpgWorkspace.joernScript(script_path="metadata.sc", params=f"cpgFile={joernBinPath},Status={status}", JoernDistributedPath = joernPath)
    command = f"./joern --script metadata.sc --params cpgFile={joernBinPath},Status={status}"
    ic(subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True))

    try:
        with open(f"./{status}_method.json") as f:
            json_obj = json.load(f)
    except Exception as e:
        return {}
    method_list = joern_method_parse(json_obj)
    
    for method, methodContent in githubJarMapMethods.items():
        info = {}

        if not any(methodContent): continue

        for mappedLineContent in methodContent:
            if mappedLineContent["similarity"] < 0.5 : continue
            jarLine = mappedLineContent["linemap"][1]
            jarcontent = mappedLineContent["contentmap"][1]
            info.update({jarLine: jarcontent})
        # file_path = methodContent[0]["jarAbsPath"].split("/")[-1]
        file_path = methodContent[0]["jarAbsPath"]

        method_begin,method_end, method_dictFull, outmethod_line = method_line_parse(info, method_list, file_path.split("/")[-1])
        if status == "old":
            methods.append({
                "oldFilePath": file_path,
                "deleteMethodBegin": method_begin,
                "deleteMethodEnd": method_end,
                "deleteMethodFull": method_dictFull
            })
        if status == "new":
            methods.append({
                "newFilePath": file_path,
                "addMethodBegin": method_begin,
                "addMethodEnd": method_end,
                "addMethodFull": method_dictFull
            })

    return methods

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