import os,sys,json

def generateGraph(methodName, modifiedContent, linesDependency, localFilePath):
    nodes = []
    edges = []
    node_dicts = {}

    for key, values in linesDependency.items():

        methodFingerPrint = localFilePath + "__split__" +  \
        methodName + "__split__" + \
        str(modifiedContent["startLine"]) + "__split__" + \
        str(modifiedContent["endLine"]) + "__split__"
        node1 = methodFingerPrint + str(key)
        nodes.append(node1)
        for value in values:
            node2 = methodFingerPrint + str(value)
            nodes.append(node2)
            edge = [node1, node2]
            if edge not in edges:
                edges.append(edge)
    

    for node in nodes:

        node_dict = {
            "weight": 1,
            "node_string": "" 
        }
        node_dicts[node] = node_dict
    nodes = list(set(nodes))

    result = {
        "nodes": nodes,
        "edges": edges,
        "node_dicts": node_dicts
    }
    return result

def callsiteAdd(cve:str, jarV :str = "", status:str= "", methodCallPath :str= "", subgraphs:dict= ""):
    '''
    status: str, old/new
    methodCallPath: str
    subgraphs: dict
    subgraphsWithCallsite: dict
    '''
    if jarV != "": callGraphAbsPath = os.path.join(methodCallPath, f"{cve}_{jarV}_{status}.json")
    else:callGraphAbsPath = os.path.join(methodCallPath, f"{cve}_{status}.json")
    callsites = []

    if not os.path.exists(callGraphAbsPath):
        return subgraphs, []
    with open(callGraphAbsPath, "r") as f:
        callGraph = json.load(f)

    if not any(callGraph["edges"]):
        return subgraphs, []

    # if not any(callGraph["nodes"]):
    #     return subgraphs, []
    
    for edge in callGraph["edges"]:
        if "callsite" not in edge:
            continue
        if not any(edge["callsite"]):
            continue
        callsites.append(edge)
    
    callsiteEdges = []
    for callsite in callsites:
        source = callsite["source"]
        target = callsite["target"]
        sourceCallSites = callsite["callsite"]
        
        callSiteNodes = []

        for methodindex, sourceSubGraph in enumerate(subgraphs):

            firstnode = sourceSubGraph["nodes"][0]
            methodFullName = firstnode.split("__split__")[-4]
            

            if methodFullName == source:

                for callSite in sourceCallSites:
                    callSiteLine = callSite.split("__split__")[-1]

                    sourceNode = ""
                    prefix = subgraphs[methodindex]["nodes"][0].rsplit("__split__", 1)[0]
                    addFlag = True
                    for node in sourceSubGraph["nodes"]:
                        if node.split("__split__")[-1] == callSiteLine:
                            addFlag = False
                            sourceNode = node

                            subgraphs[methodindex]["node_dicts"].update({sourceNode:{"weight": 3,"node_string": ""}})
                    if addFlag:
                        sourceNode = prefix + "__split__" + callSiteLine
                        subgraphs[methodindex]["nodes"].append(sourceNode)
                        subgraphs[methodindex]["node_dicts"].update({sourceNode:{"weight": 3,"node_string": ""}})
                        
                    callSiteNodes.append(sourceNode)
        

        targetNode =""
        for methodindex, sourceSubGraph in enumerate(subgraphs):

            firstnode = sourceSubGraph["nodes"][0]
            methodFullName = firstnode.split("__split__")[-4]

            if methodFullName == target:
 
                headline = 10000
                for node in sourceSubGraph["nodes"]:
                    if int(node.split("__split__")[-1]) < headline:

                        headline = int(node.split("__split__")[-1])
        
                        targetNode = node

        if targetNode != "":
            for callSiteNode in callSiteNodes:
                callsiteEdges.append(
                    [callSiteNode, targetNode]
                    )
    return subgraphs, callsiteEdges

def connectgraph(subgraphs:dict, methodCallsite:list):
    mergedGraphs = {
        "nodes":[],
        "edges":[],
        "node_dicts":{}
    }
    for subgraph in subgraphs:
        mergedGraphs["nodes"] += subgraph["nodes"]
        mergedGraphs["edges"] += subgraph["edges"]
        mergedGraphs["node_dicts"].update(subgraph["node_dicts"])
    for callsite in methodCallsite:
        mergedGraphs["edges"].append(callsite)

    return mergedGraphs

def extractLineContent(mergedGraph):
    for node in mergedGraph["node_dicts"]:
        fileAbsPath = node.split("__split__")[0]
        lineNumber = node.split("__split__")[-1]
   
        with open(fileAbsPath, 'r') as file:
            lines = file.readlines()
            line_content = lines[int(lineNumber) - 1].strip() 
            mergedGraph["node_dicts"][node]["node_string"] = line_content
    return mergedGraph