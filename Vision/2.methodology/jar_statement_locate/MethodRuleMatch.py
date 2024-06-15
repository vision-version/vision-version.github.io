import os, sys
from JarProject import JarProject
import Levenshtein

def methodRuleMatch(cve, jarV, jarV_dic: dict, patchFilePath: str) -> dict:
    jarAbsPath = jarV_dic["absPath"]
    
    jarproject = JarProject(jarAbsPath)
    classMethodsLines = jarproject.class_methods_lines

    if "new" in jarV_dic:
        githubNew = jarV_dic["new"]
        githubNew = githubClassMethodExtract(githubNew, jarAbsPath, classMethodsLines, patchFilePath, status = "new")
        jarV_dic["new"] = githubNew
    # ------- new old divider--------------
    if "old" in jarV_dic:
        githubOld = jarV_dic["old"]
        githubOld = githubClassMethodExtract(githubOld, jarAbsPath, classMethodsLines, patchFilePath, status = "old")
        jarV_dic["old"] = githubOld
    
    return (cve, jarV, jarV_dic)


def githubClassMethodExtract(githubMethods:dict, jarAbsPath: str, jarMethods:dict, patchFilePath:str, status: str) -> str:
    jarMethodNames = list(jarMethods.keys())
    # for _ in jarMethodNames:
    #     if "RegexRequestMatcher" in _:
    #         print(_)

    matchedJarMethod = {}
    
    for githubMethodSignature in githubMethods:

        classString, methodString, githubStartLine, githubEndLine = githubMethodSignature.split("__split__")
        githubMethodContent = githubMethodContentExtract(patchFilePath, status, classString.split("/")[-1], githubStartLine, githubEndLine)
        filedName = classString.split("/")[-1].strip(".java")
        methodName = methodString.split("(")[0].split(".")[-1]
        className = methodString.replace("$", ".").split(".")[-2]


        methodCoordinate1 =  "__split__" + filedName + "__split__" + methodName + "__split__"
        methodCoordinate2 =  "__split__" + className + "__split__" + methodName + "__split__"

        maxSim = 0
        mostMatchMethodConent = {}
        mostMatchJarName = ""

        for jarMethodName in jarMethodNames:

            if jarMethodName in matchedJarMethod: continue
            
            if methodName != "<init>":
                if methodCoordinate1 not in jarMethodName and methodCoordinate2 not in jarMethodName:
                    continue
            else:
                if "__split__" + className + "__split__" + className + "__split__" not in jarMethodName:
                    continue
            jarFilePath = os.path.join(jarAbsPath, jarMethodName.split("__fdse")[0])
            if classMethodArgumentMatch(githubMethodSignature, jarMethodName):
                mostMatchMethodConent = {
                    "jarPath": jarFilePath,
                    "startline": jarMethods[jarMethodName][0],
                    "endline": jarMethods[jarMethodName][1],
                    "simRule": 100
                }
                mostMatchJarName = jarMethodName
                break
            jarMethodContent = jarMethodContentExtract(jarFilePath, jarMethods[jarMethodName][0], jarMethods[jarMethodName][1])
            # FIXME
            sim = 1 - Levenshtein.distance(githubMethodContent, jarMethodContent) / max(len(githubMethodContent), len(jarMethodContent))
            if sim > maxSim and jarMethodName not in matchedJarMethod:
                maxSim = sim
                mostMatchMethodConent = {
                    "jarPath": jarFilePath,
                    "startline": jarMethods[jarMethodName][0],
                    "endline": jarMethods[jarMethodName][1],
                    "simRule": maxSim
                }
                mostMatchJarName = jarMethodName
        if mostMatchJarName != "":
            matchedJarMethod[mostMatchJarName] = githubMethodSignature
            githubMethods[githubMethodSignature] = mostMatchMethodConent
    return githubMethods

def githubMethodContentExtract(patchFilePath:str, status:str, fileName: str, githubStartLine:str, githubEndLine:str):
    '''
    args:
        patchFilePath:
        status:
        fileName:
        githubStartLine/githubEndLine:
    '''

    filePath = os.path.join(patchFilePath + f"/{status}files/" + fileName)

    with open(filePath, 'r') as file:
        lines = file.readlines()

    start_line = int(githubStartLine)
    end_line = int(githubEndLine)
    method_content = ''.join(lines[start_line-1:end_line])
    method_content = method_content.replace("\t", "").replace("\n", "")
    return method_content

def jarMethodContentExtract(jarFilePath: str, jarFileStartLine: str, jarFileEndLine: str):
    '''
    args:
        jarFilePath: jar
        jarFileStartLine/jarFileEndLine:
    '''

    with open(jarFilePath, 'r') as file:
        lines = file.readlines()

    start_line = int(jarFileStartLine)
    end_line = int(jarFileEndLine)
    method_content = ''.join(lines[start_line-1:end_line])
    method_content = method_content.replace("\t", "").replace("\n", "")
    return method_content
   
def classMethodArgumentMatch(githubMethods, jarMethods):
    githubFilePath, githubMethodName, githubStartLine, githubEndLine = githubMethods.split("__split__")
    jarFilePath, jarClass, _, jarMethodName = jarMethods.split("__split__")
    githubArgument = "(" + githubMethodName.split("(")[-1] 
    jarArgument =  "(" + jarMethodName.split("(")[-1] 
    normedGithubArguments = []
    for argument in githubArgument.split(","):
        normedGithubArguments.append(argument.strip(" ").split(" ")[0])
    normedGithubArguments = ",".join(normedGithubArguments)
    if not normedGithubArguments.endswith(")"): normedGithubArguments += ")"
    if jarArgument == normedGithubArguments: 
        return True
    else: 
        return False