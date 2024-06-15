import os, sys, json
from icecream import ic
from missingJarPathExtract import methodReInit

RUNPATH = os.getcwd()
jarMappingPath = RUNPATH + "/../jar_statement_locate"
sys.path.append(jarMappingPath)
from ModifiedLinesMap import linesMap

def missingPatchExtract():
    '''
    '''

    githubFeatureGraphPath = os.path.join(RUNPATH, "./weighted_graph")
    folders = set() 
    for root, dirs, files in os.walk(githubFeatureGraphPath):
        for dir_name in dirs:
            dir_path = os.path.join(root, dir_name)
            folders.add(dir_path)
    folders = list(folders)
    
    missingCVEs = {}
    
    for folder in folders:

        cve = folder.split("/")[-1]
        files = []  
        for file_name in os.listdir(folder):
            file_path = os.path.join(folder, file_name)
            if os.path.isfile(file_path):
                files.append(file_path)
        for file in files:
            with open(file, "r") as fr:
                githubFeatureGraph = json.load(fr)

                if not any(githubFeatureGraph["node_dicts"]):

                    missingCVEs[cve] = "new" if "old" in file else "old"
    return missingCVEs

def GitHubModifiedLineExtract(status, cveMethodMeta):
    '''

    '''
    modifiedFileLine = []
    for file in cveMethodMeta:
        fileName = file[f"{status}FilePath"].split("/")[-1]
        methodFull = file["deleteMethodFull"] if status == "old" else file["addMethodFull"]
        methodBegin = file["deleteMethodBegin"] if status == "old" else file["addMethodBegin"]
        methodEnd = file["deleteMethodEnd"] if status == "old" else file["addMethodEnd"]
        
        for methodFakeFullName in methodFull:
            modifiedLines = []
            for methodLineNumber in methodFull[methodFakeFullName]["lineNumber"]:
                modifiedLines += list(methodLineNumber.keys())
            if any(modifiedLines):
                for eachModifiedLines in modifiedLines:
                    modifiedFileLine.append((fileName, methodFakeFullName, methodFull[methodFakeFullName]["originalFullName"], f"__split__{methodBegin[methodFakeFullName]}__split__{methodEnd[methodFakeFullName]}__split__{eachModifiedLines}")) 
    return modifiedFileLine

def JarModifiedLineExtract(status, jarVLineMap, githubModifiedLines):
    '''

    '''
    modifiedFileLine = []
    for githubModifiedLine in githubModifiedLines:

        for mappedLine in jarVLineMap[githubModifiedLine[1]]:

            githubLine = mappedLine["linemap"][0]
            jarLine = mappedLine["linemap"][1]
            jarFileName = mappedLine["jarAbsPath"].split("/")[-1]
 
            if githubModifiedLine[3].endswith("__split__" + str(githubLine)):
                modifiedFileLine.append((jarFileName, "", "", f"__split__{jarLine}"))
    return modifiedFileLine

    
def GitHubSubgraphExtract(GitHubGraph: dict, githubModifiedLines: list):

    directModifiedNodes = []
    methodNodes = []

    
    methodHeadNodes = []
    for githubModifiedLine in githubModifiedLines:
        startLine, endLine, modifiedLine = githubModifiedLine[3].strip("__split__").split("__split__")
        # startLine, endLine, modifiedLine = 
        if startLine == modifiedLine:

            methodHeadNodes.append((githubModifiedLine[0], startLine, endLine))

    for node in GitHubGraph["node_dicts"]:
        for methodHeadNode in methodHeadNodes:
            if methodHeadNode[0] in node and "__split__" + methodHeadNode[1] + "__split__" + methodHeadNode[2] + "__split__" in node:
                methodNodes.append(node)
    for githubModifiedLine in githubModifiedLines:
        for node in GitHubGraph["node_dicts"]:
            if githubModifiedLine[0] in node and githubModifiedLine[3] in node:
                directModifiedNodes.append(node)
    

    deletedNodes = delNodes(GitHubGraph["nodes"], directModifiedNodes)
    deletedEdges = delEdges(GitHubGraph["edges"], directModifiedNodes)
    deletedNodedicts = delnodeDict(GitHubGraph["node_dicts"], directModifiedNodes)


    deletedNodes = delNodes(deletedNodes, methodNodes)
    deletedEdges = delEdges(deletedEdges, methodNodes)
    deletedNodedicts = delnodeDict(deletedNodedicts, methodNodes)

 
    noSingleNodes, noSingleEdges, noSingleNodedicts = delSingleNodes(deletedNodes, deletedEdges,deletedNodedicts)
    return {
        "nodes": noSingleNodes,
        "edges": noSingleEdges,
        "node_dicts": noSingleNodedicts
    }

def JarSubgraphExtract(JarGraph: dict, jarModifiedLines: list):

    directModifiedNodes = []
    for jarModifiedLine in jarModifiedLines:
        for node in JarGraph["node_dicts"]:
            if jarModifiedLine[0] in node and jarModifiedLine[3] in node:
                directModifiedNodes.append(node)

    deletedNodes = delNodes(JarGraph["nodes"], directModifiedNodes)
    deletedEdges = delEdges(JarGraph["edges"], directModifiedNodes)
    deletedNodedicts = delnodeDict(JarGraph["node_dicts"], directModifiedNodes)
    

    noSingleNodes, noSingleEdges, noSingleNodedicts = delSingleNodes(deletedNodes, deletedEdges,deletedNodedicts)
    
    return {
        "nodes": noSingleNodes,
        "edges": noSingleEdges,
        "node_dicts": noSingleNodedicts
    }

def delNodes(nodes, delNodes):
    tmp_nodes = []
    tmp_nodes = list(set(nodes) - set(delNodes))
    return tmp_nodes

def delEdges(edges, delNodes):
    tmp_edges = []
    for edge in edges:
        if edge[0] not in delNodes and edge[1] not in delNodes:
            tmp_edges.append(edge)
    return tmp_edges

def delnodeDict(node_dicts, delNodes):
    tmp_dicts = {}
    for key, value in node_dicts.items():
        if key in delNodes: continue
        tmp_dicts[key] = value
    return tmp_dicts

def delSingleNodes(Nodes, Edges, Nodedicts):
    existSingleNode = False
    singleNodes = []

    if len(Nodes) == 1:
        return Nodes, Edges, Nodedicts

    for node in Nodedicts:
        ifDeleteEdges = delEdges(Edges, node)
        if len(ifDeleteEdges) == len(Edges):
            existSingleNode =True
            singleNodes.append(node)

    if existSingleNode:
        deletedNodes = delNodes(Nodes, singleNodes)
        deletedEdges = delEdges(Edges, singleNodes)
        deletedNodedicts = delnodeDict(Nodedicts, singleNodes)
        return delSingleNodes(deletedNodes, deletedEdges, deletedNodedicts)

    else:
        return Nodes, Edges, Nodedicts

if __name__ == "__main__":
    existCVEsStatus = missingPatchExtract()

    cveMetaPath = os.path.join("../patch_callchain_generate/cves_methods.json")
    with open(cveMetaPath, "r") as fr:
        cveMeta = json.load(fr)
    

    lineMapPath = os.path.join("../jar_statement_locate/lineMatchResult.json")
    with open(lineMapPath, "r") as fr:
        jarLineMap = json.load(fr)


    with open("../jar_statement_locate/rulebasedMethodMatechResult.json", "r") as fr:
        functionWiseSim = json.load(fr)

    with open("../jar_statement_locate/lineMatchResult.json", "r") as fr:
        cves_githubjarLineMap = json.load(fr)


    fillingGithubFeatureGraphPath = os.path.join(RUNPATH, "./weighted_graph")
    fillingJarFeatureGraphPath = os.path.join(RUNPATH, "./jar_graph")
    

    with open("missingCVE.json", "r") as fr:
        missing_cves = json.load(fr)

    for cve, status in existCVEsStatus.items():

        if cve not in missing_cves:
            missing_cves[cve] = status


    with open("missingCVE.json", "w") as fw:
        json.dump(missing_cves, fw, indent = 4)

    missing_cvemethods = {}
    for cve, status in missing_cves.items():
        if cve != "CVE-2020-7238": 
            continue

        missing_cvemethods[cve] = {}

        if status == "old":
            missingStatus = "new"
        else:
            missingStatus = "old"


        githubModifiedLines = GitHubModifiedLineExtract(status, cveMeta[cve][f"{status}_methods_info"])
        
        jarModifiedLines = {}
        for jarV, jarVLineMap in jarLineMap[cve].items():

            jarVModifiedLines = JarModifiedLineExtract(status, jarVLineMap[status], githubModifiedLines)
            jarModifiedLines[jarV] = jarVModifiedLines

        with open(os.path.join(fillingGithubFeatureGraphPath, cve, cve + "_" + status + ".json"), "r") as fr:
            GitHubGraph = json.load(fr)
        GitHubSubGraph = GitHubSubgraphExtract(GitHubGraph, githubModifiedLines)
        with open(os.path.join(fillingGithubFeatureGraphPath, cve, cve + "_" + missingStatus + ".json"), "w") as fw:
            json.dump(GitHubSubGraph, fw, indent = 4)

        missingStatusContent = methodReInit(GitHubSubGraph, cve, status, missingStatus)
        missing_cvemethods[cve][f"{status}_methods_info"] = missingStatusContent

        jarVs_dic = functionWiseSim[cve]

        for jarV, jarV_dic in jarVs_dic.items():

            jarV_dic[missingStatus] = jarV_dic[status]
            cve, jarV, old_githubjarLineMap, new_githubjarLineMap= linesMap(cve, jarV, jarV_dic, missing_cvemethods[cve])
            missingjarLineMap = old_githubjarLineMap if status == "old" else new_githubjarLineMap
            cves_githubjarLineMap[cve][jarV].update({missingStatus: missingjarLineMap})


    with open("MissingCVEMethods.json", "w") as fw:
        json.dump(missing_cvemethods,  fw, indent = 4)

    with open("../jar_statement_locate/lineMatchResult.json", "w") as fw:
        json.dump(cves_githubjarLineMap, fw, indent = 4)