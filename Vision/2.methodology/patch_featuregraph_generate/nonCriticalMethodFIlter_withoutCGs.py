import os, sys,json
import math
RUNPATH = os.getcwd()

def githubNonCriticalMethodExtract(GitHubCriticalMethods: dict):
    '''
    '''

    HitsThreshold = 0.4
    EditdistanceThreshold = 0.8

    NoncriticalOldMethods = set()
    NoncriticalNewMethods = set()

    criticalOldMethods = set()
    criticalNewMethods = set()
    
    OldMethods = set()
    NewMethods = set()

    statusLst = ["old_info", "new_info"]

    for status in statusLst:

        if GitHubCriticalMethods[status]["hits"] == None:
            continue
        refedMethods = []
        for method_name in GitHubCriticalMethods[status]["hits"]:
            if method_name.startswith("Virtual"): refedMethods.append(method_name)
        if refedMethods != []:
            for method in refedMethods:
                methodName = method.split("__split__")[-1]
                for methods_name in GitHubCriticalMethods[status]["hits"]:
                    if methods_name.startswith("Virtual"): continue
                    if status == "old_info":
                        OldMethods.add(methods_name)
                        if "." + methodName in methods_name:
                            criticalOldMethods.add(methods_name)
                    if status == "new_info": 
                        NewMethods.add(methods_name)
                        if "." + methodName in methods_name and status == "new_info": 
                            criticalNewMethods.add(methods_name)
            if status == "old_info":
                NoncriticalOldMethods = OldMethods - criticalOldMethods
            elif status == "new_info":
                NoncriticalNewMethods = NewMethods - criticalNewMethods

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
    subdirs = [name for name in os.listdir("weighted_graph")
               if os.path.isdir(os.path.join("weighted_graph", name))]
    print(subdirs)
    CVEIDs  = subdirs
    # CVEIDs  = ["CVE-2020-5421"]
    

    githubFeatureGraphPath = os.path.join(RUNPATH, "./weighted_graph")
    jarFeatureGraphPath = os.path.join(RUNPATH, "./jar_graph")
    

    # criticalGithubFeatureGraphPath = os.path.join(RUNPATH, "./critical_github_graph")
    # criticalJarFeatureGraphPath = os.path.join(RUNPATH, "./critical_jar_graph")
    criticalGithubFeatureGraphPath = os.path.join(RUNPATH, "./critical_github_graph_withoutcg")
    criticalJarFeatureGraphPath = os.path.join(RUNPATH, "./critical_jar_graph_withoutcg")


    # criticalMethodRootPath = os.path.join(RUNPATH, "../patch_callchain_generate/CGs/")
    criticalMethodRootPath = os.path.join(RUNPATH, "../patch_callchain_generate/CGs")


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