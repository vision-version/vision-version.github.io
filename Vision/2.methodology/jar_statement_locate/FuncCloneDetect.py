import os
import json
from icecream import ic
import git
import xml.etree.ElementTree as ET

def gitHubMethodLineMap(GitHubMethodsMeta, unmatchedMethods, cveid, githubStatus):
    unmatchedMethodsDic = {_ : None for _ in unmatchedMethods}
    
    for unmatchedMethod in unmatchedMethods:
        unmatchedPath, unmatchedMethodFullName = unmatchedMethod.split("__split__")
        FileStatus = "old_methods_info" if githubStatus == "old" else "new_methods_info"
        MethodStatus = "oldFilePath" if githubStatus == "old" else "newFilePath"
        MethodStatusBegin = "deleteMethodBegin" if githubStatus == "old" else "addMethodBegin"
        MethodStatusEnd = "deleteMethodEnd" if githubStatus == "old" else "addMethodEnd"

        unmatchedFiles = GitHubMethodsMeta[cveid][FileStatus]
        for unmatchedFile in unmatchedFiles:
            if unmatchedFile[MethodStatus].replace(".", "/") != unmatchedPath.replace(".", "/"):  
                continue
            methodsBeginLines = unmatchedFile[MethodStatusBegin]
            methodsEndLines = unmatchedFile[MethodStatusEnd]
            for method in methodsBeginLines:
                if not method.startswith(f"{unmatchedMethodFullName}("): 
                    continue
                BeginLine = methodsBeginLines[method]
                EndLine = methodsEndLines[method]
                unmatchedMethodsDic[unmatchedMethod] = (BeginLine, EndLine)
    return unmatchedMethodsDic

def funcCloneDetection(xml_file, GitHubFilePath, startline, endline, githubStatus, v):
    threshold = 50
    try:
        tree = ET.parse(xml_file)
    except Exception:
        return {}
    root = tree.getroot()
    fileSimEachV = {
        v:{}
    }

    for clone_elem in root.findall('.//clone'):
        simNicad = int(clone_elem.get("similarity"))
        nicadMethod1 = clone_elem.find('.//source[1]')
        nicadMethod2 = clone_elem.find('.//source[2]')
        fileName1 = nicadMethod1.get('file')
        fileName2 = nicadMethod2.get('file')

        # fileName1 = nicadMethod1.get('file').replace("/", ".")
        # fileName2 = nicadMethod2.get('file').replace("/", ".")

        nicadStart1 = nicadMethod1.get('startline')
        nicadEndline1 = nicadMethod1.get('endline')
        nicadStart2 = nicadMethod2.get('startline')
        nicadEndline2 = nicadMethod2.get('endline')  
        
        file1 = {
            "fileName": fileName1,
            "nicadStart": nicadStart1,
            "nicadEnd": nicadEndline1
        }
        file2 = {
            "fileName": fileName2,
            "nicadStart": nicadStart2,
            "nicadEnd": nicadEndline2            
        }

        ifMatch, githubFile, mvnFile = matchGitHubMvnFile(file1, file2, githubStatus)
        if not ifMatch: continue
        githubFile["fileName"] = githubFile["fileName"].replace(f"{githubStatus}_", "")

        if compare_last_n_path_elements(githubFile["fileName"],GitHubFilePath,1) and \
            int(githubFile["nicadStart"]) == int(startline) and int(githubFile["nicadEnd"]) == int(endline):
            if simNicad < threshold: continue

            if not any(fileSimEachV[v]) or simNicad > fileSimEachV[v]["simNicad"]: 
                fileSimEachV[v] = {
                    "jarPath": mvnFile["fileName"],
                    "startline": mvnFile["nicadStart"],
                    "endline": mvnFile["nicadEnd"],
                    "simNicad": simNicad
                }
    return fileSimEachV

def matchGitHubMvnFile(file1, file2, githubStatus):
    if "systems/tmp/JAR" in file1["fileName"] and "systems/tmp/GitHub" in file2["fileName"]:
        githubFile = file2
        mvnFile = file1
    elif "systems/tmp/JAR" in file2["fileName"] and "systems/tmp/GitHub" in file1["fileName"]:
        githubFile = file1
        mvnFile = file2
    else:
        return False, None, None
    if not githubStatus + "_" in githubFile["fileName"]:
        return False, None, None
    else:
        # githubFile["fileName"] = githubFile["fileName"].replace("/", ".")
        # mvnFile["fileName"] = mvnFile["fileName"].replace("/", ".")
        githubFile["fileName"] = githubFile["fileName"]
        mvnFile["fileName"] = mvnFile["fileName"]
        return True, githubFile, mvnFile
    
def compare_last_n_path_elements(path1, path2, n):
    path_elements1 = path1.split('/')
    path_elements2 = path2.split('/')
    
    last_n_elements1 = path_elements1[-n:]
    last_n_elements2 = path_elements2[-n:]

    return last_n_elements1 == last_n_elements2

if __name__ == "__main__":
    pass