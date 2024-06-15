import os
import json
from DataLoader import DataLoader
from github import Github
from icecream import ic
from pathlib import Path
import git
from copy import deepcopy
from IntraSlicing import slicing
from cleanGraph import cleanCycle, cleanHead
from GraphGenerate import generateGraph, callsiteAdd, connectgraph, extractLineContent

RootPath = os.getcwd()
cveMetainfoPath = RootPath + "/../patch_callchain_generate/cves_metainfo.json"
cveMethodsPath=  RootPath + "/../patch_callchain_generate/cves_methods.json"
joern_path = RootPath + "/../joern-cli"
githubFilePath = RootPath + "/../patch_callchain_generate/github_diff"
methodCallPath = RootPath + "/../patch_callchain_generate/CGs"
githubGraphPath = RootPath + "/weighted_graph"

class PatchCFGGenerate(DataLoader):
    def __init__(self, cveMethodsPath, cveMetainfoPath):
        self.cveMethodsPath = cveMethodsPath
        self.cveMetainfoPath = cveMetainfoPath
        super().__init__(cveMethodsPath, cveMetainfoPath)
        self.access_token = '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'

    def cveSliceLoop(self):
        '''

        '''

        generatedGithubGraphs = [str(file.name) for file in Path(githubGraphPath).iterdir() if file.is_dir()]

        with open(RootPath + "/../patch_callchain_generate/cves_methods_40.json", "r") as fr:
            generated_40 = json.load(fr)
        # ic(generatedGithubGraphs)
        for cve in self.cveMethods:
            # if cve != "CVE-2020-11002": continue
            if cve in generated_40: 
                   continue
            # if cve in generatedGithubGraphs:
            #     continue
            ic(cve)
            cve_meta = self.cveMetaPath[cve]
            cve_methods = self.cveMethods[cve]

            oldMethods = {}
            newMethods = {}
            for modifiedFile in cve_methods["old_methods_info"]:
                modifiedFilePath = modifiedFile["oldFilePath"]
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
                newMethods[modifiedFilePath] = {}
                for methodName, methodContent in modifiedFile["addMethodFull"].items():
                    if not methodContent["lineNumber"]: continue
                    methodFullName = methodContent["originalFullName"]
                    newMethods[modifiedFilePath][methodFullName] = {
                        "startLine": int(modifiedFile["addMethodBegin"][methodName]),
                        "endLine": int(modifiedFile["addMethodEnd"][methodName]),
                        "modifiedLines": methodContent["lineNumber"]
                    }
            self.cveGraphGenerator(cve = cve, Methods= oldMethods, status ="old")
            self.cveGraphGenerator(cve = cve, Methods= newMethods, status ="new")

    def cveGraphGenerator(self, cve:str, Methods:dict, status:str):
        '''
        '''

        binFile = ""
        for root, dirs, files in os.walk(joern_path+ "/cache"):
            for file in files:
                if file.endswith('.bin') and file.startswith(f'{cve}_{status}'):
                    binFile = os.path.join(root, file)
        subgraphs = []


        for filePath, modifiedMethods in Methods.items():
            for methodFullName, modifiedContent in modifiedMethods.items():

                localFilePath = os.path.join(githubFilePath, cve, f"{status}files", filePath.split("/")[-1])
                cdgMap, ddgMap, slicingSet = slicing(joern_path, localFilePath, methodFullName, "", modifiedContent["modifiedLines"], methodFullName, binFile)
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

                pdgMapNocycleNohead = cleanHead(pdgMapNocycle, modifiedContent["startLine"], modifiedContent["modifiedLines"], localFilePath)
                ic(pdgMapNocycleNohead)

                subGraph = generateGraph(methodFullName, modifiedContent, pdgMapNocycleNohead, localFilePath)
                subgraphs.append(subGraph)

        subgraphsWithCallSites, callSiteEdges = callsiteAdd(cve, "", status, methodCallPath, subgraphs)

        mergedGraph = connectgraph(subgraphsWithCallSites, callSiteEdges)

        weighted_graph = extractLineContent(mergedGraph)
        os.chdir(RootPath)
        
        os.makedirs(f"./weighted_graph/{cve}", exist_ok=True)
        with open(f"./weighted_graph/{cve}/{cve}_{status}.json", "w") as fw:
            json.dump(weighted_graph, fw, indent = 4)
if __name__ == '__main__':
    pathCFGGenerate = PatchCFGGenerate(cveMethodsPath, cveMetainfoPath)
    pathCFGGenerate.cveSliceLoop()