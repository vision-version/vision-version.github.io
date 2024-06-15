import json
import os
import sys
from github import Github
import git

def linesMap(cve, jarV, methodMapTable, cve_methods):
    '''
    '''
    jarPath = methodMapTable["absPath"]
    old_jarMethodsMap = {}
    new_jarMethodsMap = {}

    if "old" in methodMapTable:
        for methodSig, jarInfo in methodMapTable["old"].items():
            if not any(jarInfo): continue

            fileAbsPath = jarPathProcess(jarPath, jarInfo["jarPath"])
            jarMethodLineContentMap = extractLine(fileAbsPath, jarInfo["startline"], jarInfo["endline"])
            old_jarMethodsMap.update({methodSig: {
                "lineMap": jarMethodLineContentMap,
                "jarAbsPath": fileAbsPath}})


    if "new" in methodMapTable:
        for methodSig, jarInfo in methodMapTable["new"].items():
            if not any(jarInfo): continue

            fileAbsPath = jarPathProcess(jarPath, jarInfo["jarPath"])
            jarMethodLineContentMap = extractLine(fileAbsPath, jarInfo["startline"], jarInfo["endline"])
            new_jarMethodsMap.update({methodSig: {
                "lineMap": jarMethodLineContentMap,
                "jarAbsPath": fileAbsPath}})
    

    old_githubMethodsMap = {}
    new_githubMethodsMap = {}

    if "old_methods_info" in cve_methods:
        for modifiedfile in cve_methods["old_methods_info"]:
            for deletemethod, githubmethodMeta in modifiedfile["deleteMethodFull"].items():
                old_githubMethodsMap[deletemethod] = {}
                for linecontent in githubmethodMeta["lineNumber"]:
                    old_githubMethodsMap[deletemethod].update(linecontent) 

    if "new_methods_info" in cve_methods:
        for modifiedfile in cve_methods["new_methods_info"]:
            for addmethod, githubmethodMeta in modifiedfile["addMethodFull"].items():
                new_githubMethodsMap[addmethod] = {}
                for linecontent in githubmethodMeta["lineNumber"]:
                    new_githubMethodsMap[addmethod].update(linecontent)


    old_githubjarMap = editDistanceMatch(old_jarMethodsMap, old_githubMethodsMap)
    new_githubjarMap = editDistanceMatch(new_jarMethodsMap, new_githubMethodsMap)
    return (cve, jarV, old_githubjarMap, new_githubjarMap)
def jarPathProcess(jarAbsPath: str, relPath: str) -> str:

    relPath = relPath.split(jarAbsPath.split("/")[-1])[-1].strip("/")
    fileAbsPath = os.path.join(jarAbsPath, relPath)
    return fileAbsPath

def extractLine(jarPath: str, startline: int, endline: int) -> dict:
    '''
    {
        "line1":line_content1,
        "line2":line_content2,
        "line3":line_content3
    }
    '''
    result = {}
    with open(jarPath, 'r') as file:
        lines = file.readlines()
        for i in range(int(startline), int(endline) + 1):
            result[i] = lines[i - 1].strip()
    return result
    
def editDistanceMatch(jarMethodsMap: dict, githubMethodsMap: dict) -> dict:
    '''
    '''
    githubMethodDic = {}

    for methodNamePara, methodContent in githubMethodsMap.items():

        githubMethodDic[methodNamePara] = []
        for githubLine, githubLineContent in methodContent.items():

            maxSim = 0.0
            linecontentMap = {
                "linemap": (int(githubLine), None),
                "contentmap": (githubLineContent, None),
                "similarity": maxSim
            }

            if githubLineContent in ["", "(", ")", "{", "}"]: continue

            matched_github_method = None
            for each in jarMethodsMap.keys():
                if methodNamePara in each:
                    matched_github_method = each 
            if not matched_github_method:
                continue
            for jarLine, jarLineContent in jarMethodsMap[matched_github_method]["lineMap"].items():
                sim = levenshtein_distance(githubLineContent, jarLineContent)
                if sim > maxSim:
                    maxSim = sim
                    linecontentMap = {
                        "linemap": (int(githubLine), jarLine),
                        "contentmap": (githubLineContent, jarLineContent),
                        "similarity": maxSim,
                        "jarAbsPath": jarMethodsMap[matched_github_method]["jarAbsPath"]
                    }

            githubMethodDic[methodNamePara].append(linecontentMap)       
    return githubMethodDic

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

if __name__ == "__main__":
    

    pass