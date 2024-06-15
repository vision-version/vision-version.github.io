import json
import os, sys
from joern_utils.CPGWorkspace import CPGWorkspace

'''
'''
import os
import json
from DataLoader import DataLoader
from github import Github
from icecream import ic
import git
from copy import deepcopy
from IntraSlicing import slicing
from cleanGraph import cleanCycle, cleanHead
from GraphGenerate import generateGraph, callsiteAdd, connectgraph, extractLineContent



def jarSlice(cve: str, jarV:str, cve_methods, RUNPATH: str, joernBinPath: str, joernPath: str):
    '''
    '''
    oldMethods = {}
    newMethods = {}
    for modifiedFile in cve_methods["old_methods_info"]:
        modifiedFilePath = modifiedFile["oldFilePath"]
        if modifiedFilePath not in oldMethods:
            oldMethods[modifiedFilePath] = {}
        for methodName, methodContent in modifiedFile["deleteMethodFull"].items():
            if not methodContent["lineNumber"]: continue
            methodFullName = methodContent["originalFullName"]
            oldMethods[modifiedFilePath][methodFullName] = {
                "startLine": int(modifiedFile["deleteMethodBegin"][methodName]),
                "endLine": int(modifiedFile["deleteMethodEnd"][methodName]),
                "modifiedLines": methodContent["lineNumber"]
            }
            
    for modifiedFile in cve_methods["new_methods_info"]:
        modifiedFilePath = modifiedFile["newFilePath"]
        if modifiedFilePath not in newMethods:
            newMethods[modifiedFilePath] = {}
        for methodName, methodContent in modifiedFile["addMethodFull"].items():
            if not methodContent["lineNumber"]: continue
            methodFullName = methodContent["originalFullName"]
            newMethods[modifiedFilePath][methodFullName] = {
                "startLine": int(modifiedFile["addMethodBegin"][methodName]),
                "endLine": int(modifiedFile["addMethodEnd"][methodName]),
                "modifiedLines": methodContent["lineNumber"]
            }
    cveGraphGenerator(cve = cve, jarV = jarV, Methods= oldMethods, joernBinPath = joernBinPath, RUNPATH = RUNPATH, status ="old", joernPath = joernPath)
    cveGraphGenerator(cve = cve, jarV = jarV, Methods= newMethods, joernBinPath = joernBinPath, RUNPATH = RUNPATH, status ="new", joernPath = joernPath)

def cveGraphGenerator(cve:str, jarV:str, Methods:dict, joernBinPath:str, RUNPATH: str, status:str, joernPath: str):
    '''
    '''
    methodCallPath = RUNPATH + f"/jar_file/CGs/{cve}"
    subgraphs = []

    for filePath, modifiedMethods in Methods.items():
        for methodFullName, modifiedContent in modifiedMethods.items():
            cdgMap, ddgMap, slicingSet = slicing(joernPath, filePath, methodFullName, "", modifiedContent["modifiedLines"], methodFullName, joernBinPath)
            ddgMap_cp = deepcopy(ddgMap)
            if not any(ddgMap_cp):
                ddgMap_cp = {each: {} for each in list(slicingSet)}
            for key, value in cdgMap.items():
                ddgMap_cp[key] = ddgMap_cp.get(key, set()) | value
            pdgMapNocycle = cleanCycle(ddgMap_cp)
            
            depline_list = list(pdgMapNocycle.keys())
            depedline_list = []
            for depline in depline_list:
                if any(pdgMapNocycle[depline]):
                    depedline_list += list(pdgMapNocycle[depline])

            pdgMapNocycleNohead = cleanHead(pdgMapNocycle, modifiedContent["startLine"], modifiedContent["modifiedLines"], filePath)
            ic(pdgMapNocycleNohead)

            subGraph = generateGraph(methodFullName, modifiedContent, pdgMapNocycleNohead, filePath)
            subgraphs.append(subGraph)

    subgraphsWithCallSites, callSiteEdges = callsiteAdd(cve, jarV, status, methodCallPath, subgraphs)

    mergedGraph = connectgraph(subgraphsWithCallSites, callSiteEdges)

    weighted_graph = extractLineContent(mergedGraph)
    os.chdir(RUNPATH)
    os.makedirs(f"jar_graph/{cve}", exist_ok=True)
    with open(f"./jar_graph/{cve}/{cve}_{jarV}_{status}.json", "w") as fw:
        json.dump(weighted_graph, fw, indent = 4)
if __name__ == "__main__":
    pass