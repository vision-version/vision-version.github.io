import os, sys,json
import math
RUNPATH = os.getcwd()

def githubNonCriticalMethodExtract(GitHubCriticalMethods: dict):

    HitsThreshold = 0.9
    EditdistanceThreshold = 0.8

    NoncriticalOldMethods = set()
    NoncriticalNewMethods = set()

    criticalOldMethods = set()
    criticalNewMethods = set()
    
    statusLst = ["old_info", "new_info"]
    simLst = ["hits", "similarity"]


    for status in statusLst:

        if GitHubCriticalMethods[status]["hits"] == None:
            continue

        max_value = max(GitHubCriticalMethods[status]["hits"].values())
        min_value = min(GitHubCriticalMethods[status]["hits"].values())
        for simType in simLst:

            sorted_methods = sorted(GitHubCriticalMethods[status][simType].items(), key=lambda x: x[1])

            if len(sorted_methods) * HitsThreshold < 1:
  
                num_methods_to_keep = math.ceil(len(sorted_methods) * HitsThreshold)
                num_methods_to_extract = len(sorted_methods) - num_methods_to_keep
            else:

                num_methods_to_extract = math.floor(len(sorted_methods) * (1 - HitsThreshold))

            bottom_methods = sorted_methods[:num_methods_to_extract]

            for method, value in bottom_methods:
                if status == "old_info":
                    NoncriticalOldMethods.add(method)
                elif status == "new_info":
                    NoncriticalNewMethods.add(method)

    # if any(NoncriticalOldMethods) and any(NoncriticalOldMethods):
    #     return list(NoncriticalOldMethods - criticalOldMethods), list(NoncriticalNewMethods - criticalNewMethods)
    # else:
    #     return list(NoncriticalOldMethods - criticalOldMethods - criticalNewMethods), list(NoncriticalNewMethods - criticalOldMethods - criticalNewMethods)
    if criticalOldMethods == set(): return list(), list(NoncriticalNewMethods - criticalNewMethods)
    return list(NoncriticalOldMethods - criticalOldMethods), list(NoncriticalNewMethods - criticalNewMethods)

def jarCriticalMethodMap(cve: str, GitHubJarMap: dict, GitHubNoncriticalMethods: dict, status: str, cveMethodMeta: dict):
    JarNoncriticalMethods = {}
    for version, GitHubMethod in GitHubJarMap.items():

        JarNoncriticalMethods[version] = {
            status: []
        }
        for GitHubMethodName, MatchedJarMethod in GitHubMethod[status].items():

            GitHubMethodFakeFullName = GitHubMethodName.split("__split__")[1]

            GitHubMethodFullName = ""
            for eachFile in cveMethodMeta:
                methodFullKeyword = "deleteMethodFull" if status == "old" else "addMethodFull"
                if GitHubMethodFakeFullName in eachFile[methodFullKeyword].keys():
                    GitHubMethodFullName = eachFile[methodFullKeyword][GitHubMethodFakeFullName]["originalFullName"]

            if GitHubMethodFullName in GitHubNoncriticalMethods and any(MatchedJarMethod):
                JarNoncriticalMethods[version][status].append(MatchedJarMethod)
    return JarNoncriticalMethods

def GitHubGraphDel(FeatureGraph, NoncriticalMethods):
    '''
    '''
    NoncriticalNodes = []
    for NoncriticalMethod in NoncriticalMethods:
        for featureNodes in list(FeatureGraph["node_dicts"].keys()):
            if NoncriticalMethod in featureNodes:
                NoncriticalNodes.append(featureNodes)
    criticalFeatureGraph = delGraph(FeatureGraph, NoncriticalNodes)
    return criticalFeatureGraph

def JarGraphDel(FeatureGraph, NoncriticalMethods):
    '''
    '''
    NoncriticalNodes = []
    for NoncriticalMethod in NoncriticalMethods:
        for featureNode in list(FeatureGraph["node_dicts"].keys()):

            if NoncriticalMethod["jarPath"] in featureNode and "__split__" + str(NoncriticalMethod["startline"]) + "__split__" + str(NoncriticalMethod["endline"]) + "__split__" in featureNode:      
                NoncriticalNodes.append(featureNode)
    criticalFeatureGraph = delGraph(FeatureGraph, NoncriticalNodes)
    return criticalFeatureGraph

def delGraph(FeatureGraph: dict, NoncriticalNodes: list) -> dict:
    '''
    '''
    deletedNodes = delNodes(FeatureGraph["nodes"], NoncriticalNodes)
    deletedEdges = delEdges(FeatureGraph["edges"], NoncriticalNodes)
    deletedNodedicts = delnodeDict(FeatureGraph["node_dicts"], NoncriticalNodes)
    
    return {
        "nodes": deletedNodes,
        "edges": deletedEdges,
        "node_dicts": deletedNodedicts
    }

def delNodes(nodes, NoncriticalNodes):
    tmp_nodes = []
    tmp_nodes = list(set(nodes) - set(NoncriticalNodes))
    return tmp_nodes

def delEdges(edges, NoncriticalNodes):
    tmp_edges = []
    for edge in edges:
        if edge[0] not in NoncriticalNodes and edge[1] not in NoncriticalNodes:
            tmp_edges.append(edge)
    return tmp_edges

def delnodeDict(node_dicts, NoncriticalNodes):
    tmp_dicts = {}
    for key, value in node_dicts.items():
        if key in NoncriticalNodes: continue
        tmp_dicts[key] = value
    return tmp_dicts

if __name__ == "__main__":
    '''
    '''
    subdirs = [name for name in os.listdir("weighted_graph_perfect")
               if os.path.isdir(os.path.join("weighted_graph_perfect", name))]
    print(subdirs)
    CVEIDs  = subdirs
    # CVEIDs  = ["CVE-2020-5421"]
    

    githubFeatureGraphPath = os.path.join(RUNPATH, "./weighted_graph_perfect")
    jarFeatureGraphPath = os.path.join(RUNPATH, "./jar_graph")
    

    # criticalGithubFeatureGraphPath = os.path.join(RUNPATH, "./critical_github_graph")
    # criticalJarFeatureGraphPath = os.path.join(RUNPATH, "./critical_jar_graph")
    criticalGithubFeatureGraphPath = os.path.join(RUNPATH, "./critical_github_graph_0.1")
    criticalJarFeatureGraphPath = os.path.join(RUNPATH, "./critical_jar_graph_0.1")


    criticalMethodRootPath = os.path.join(RUNPATH, "../patch_callchain_generate/CGs prefect/")
    # criticalMethodRootPath = os.path.join(RUNPATH, "../patch_callchain_generate/CGs_withoutRef/")


    GitHubJarMapPath = os.path.join(RUNPATH, "../jar_statement_locate/MethodMatechResult.json")


    cveMethodMetaPath = os.path.join(RUNPATH, "../patch_callchain_generate/cves_methods.json")

    with open(GitHubJarMapPath, "r") as fr:
        GitHubJarMap = json.load(fr)
     
    with open(cveMethodMetaPath, "r") as fr:
        cveMethodMeta = json.load(fr)

    for cve in CVEIDs:

        criticalMethodPath = os.path.join(criticalMethodRootPath, "critical_" + cve + ".json")


        if not os.path.exists(criticalMethodPath): continue
        
        with open(criticalMethodPath, "r") as fr:
            GitHubCriticalMethods = json.load(fr)

        GitHubNoncriticalOldMethods, GitHubNoncriticalNewMethods = githubNonCriticalMethodExtract(GitHubCriticalMethods)

        if GitHubCriticalMethods["old_info"]["hits"] == None:
            GitHubNoncriticalOldMethods = GitHubNoncriticalNewMethods
        if GitHubCriticalMethods["new_info"]["hits"] == None:
            GitHubNoncriticalNewMethods = GitHubNoncriticalOldMethods
        
        JarNoncriticalNewMethods = jarCriticalMethodMap(cve, GitHubJarMap[cve], GitHubNoncriticalNewMethods, "new", cveMethodMeta[cve]["new_methods_info"])
        JarNoncriticalOldMethods = jarCriticalMethodMap(cve, GitHubJarMap[cve], GitHubNoncriticalOldMethods, "old", cveMethodMeta[cve]["old_methods_info"])

        with open(os.path.join(githubFeatureGraphPath, cve, cve + "_old.json"), "r") as fr:
            githubOldFeatureGraph = json.load(fr)
        GitHubcriticalOldMethods = GitHubGraphDel(githubOldFeatureGraph, GitHubNoncriticalOldMethods)

        os.makedirs(os.path.join(criticalGithubFeatureGraphPath, cve), exist_ok=True)

        with open(os.path.join(criticalGithubFeatureGraphPath, cve, cve + "_old.json"), "w") as fw:
            json.dump(GitHubcriticalOldMethods, fw, indent = 4)
        
        with open(os.path.join(githubFeatureGraphPath, cve, cve + "_new.json"), "r") as fr:
            githubNewFeatureGraph = json.load(fr)        
        GitHubcriticalNewMethods = GitHubGraphDel(githubNewFeatureGraph, GitHubNoncriticalNewMethods)

        os.makedirs(os.path.join(criticalGithubFeatureGraphPath, cve), exist_ok=True)

        with open(os.path.join(criticalGithubFeatureGraphPath, cve, cve + "_new.json"), "w") as fw:
            json.dump(GitHubcriticalNewMethods, fw, indent = 4)

        for JarVersion in JarNoncriticalOldMethods:

            os.makedirs(os.path.join(criticalJarFeatureGraphPath, cve), exist_ok=True)

            if not os.path.exists(os.path.join(jarFeatureGraphPath, cve, cve + "_" + JarVersion + "_" + "old.json")): continue

            with open(os.path.join(jarFeatureGraphPath, cve, cve + "_" + JarVersion + "_" + "old.json"), "r") as fr:
                jarOldFeatureGraph = json.load(fr)
            jarCriticalOldMethods = JarGraphDel(jarOldFeatureGraph, JarNoncriticalOldMethods[JarVersion]["old"])
            with open(os.path.join(criticalJarFeatureGraphPath, cve, cve + "_" + JarVersion + "_old.json"), "w") as fw:
                json.dump(jarCriticalOldMethods, fw, indent = 4)  

            if not os.path.exists(os.path.join(jarFeatureGraphPath, cve, cve + "_" + JarVersion + "_" + "new.json")): continue                     
            with open(os.path.join(jarFeatureGraphPath, cve, cve + "_" + JarVersion + "_" + "new.json"), "r") as fr:
                jarNewFeatureGraph = json.load(fr)
            jarCriticalNewMethods = JarGraphDel(jarNewFeatureGraph, JarNoncriticalNewMethods[JarVersion]["new"])
            with open(os.path.join(criticalJarFeatureGraphPath, cve, cve + "_" + JarVersion + "_new.json"), "w") as fw:
                json.dump(jarCriticalNewMethods, fw, indent = 4)