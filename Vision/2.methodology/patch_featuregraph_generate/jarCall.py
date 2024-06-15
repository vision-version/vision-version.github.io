import json
import os, sys
from joern_utils.CPGWorkspace import CPGWorkspace
from graph import plot_cg
'''
'''
def calls_axonomy(cve: str, jarVersion: str, RUNPATH: str, joernBinPath:str, cve_methods, cpgWorkspace: CPGWorkspace, joernPath: str):

    cpg_paths = methods_show(cve_id = cve, jarVersion = jarVersion, RUNPATH = RUNPATH, joernBinPath = joernBinPath, cve_methods=cve_methods, cpgWorkspace=cpgWorkspace, joernPath = joernPath)
        
    for index, cpg_path in enumerate(cpg_paths):
        status = ""
        if index == 0:
            status = "old"
        elif index == 1:
            status = "new"

        if cpg_path == "": continue
        if not status: continue
        
        cve_cg_path = os.path.join(RUNPATH, f"jar_file/CGs/{cve}/{cve}_{jarVersion}_{status}.json")
        
        with open(cve_cg_path, "r") as fr:
            cve_cg = json.load(fr)

        for edge in cve_cg["edges"]:
            # source_function, target_function, callCode = process_function(source=edge['source'], target=edge['target'])
            callsite = []
            callsite = cpgWorkspace.callSiteQuery(cpg_path=cpg_path, source_function_sign=edge['source'], target_function_sign=edge['target'], JoernDistributedPath = joernPath)
            edge['callsite'] = callsite
        with open(cve_cg_path, "w") as fw:
            json.dump(cve_cg,fw, indent = 4)
def methods_show(cve_id: str, jarVersion: str, RUNPATH: str, joernBinPath: str, cve_methods: dict, cpgWorkspace: CPGWorkspace, joernPath: str):
    '''
    @params: cve_id
    @params: cve_methods: methods information of a CVE
    @params: cpgWorkspace: CPGWorkspace (singlten)

    @return: list of path of cpg of a proj
    '''
    old_methods, new_methods = change_methods_extract(cve_methods)

    old_cpg_file = ""
    new_cpg_file = ""

    if len(old_methods) > 1:
        old_layer, old_cpg_file, name_mapping = joern_callgraph_generate(cve = cve_id, jarVersion = jarVersion, joernBinPath = joernBinPath, methods=old_methods, cpgWorkspace=cpgWorkspace, status="old", joernPath = joernPath)
        with open("old_name_mapping.json", "w") as fw:
            json.dump(name_mapping, fw, indent=4)
        with open("old_layer.json", 'w') as lf:
            json.dump(old_layer, lf, indent=4)
        layer2graph(layer=old_layer, cve_id=cve_id, jarVersion = jarVersion, RUNPATH = RUNPATH, status="old", methodNameMapping=name_mapping)
    

    if len(new_methods) > 1:
        new_layer, new_cpg_file, name_mapping = joern_callgraph_generate(cve = cve_id, jarVersion = jarVersion, joernBinPath = joernBinPath, methods=new_methods, cpgWorkspace=cpgWorkspace, status="new", joernPath = joernPath)
        with open("new_name_mapping.json", "w") as fw:
            json.dump(name_mapping, fw, indent=4)
        layer2graph(layer=new_layer, cve_id=cve_id, jarVersion = jarVersion, RUNPATH = RUNPATH, status="new", methodNameMapping=name_mapping)

    return [old_cpg_file, new_cpg_file]

def change_methods_extract(methods):
    '''
    @param: methods
    return old & new methods of a CVE
    '''
    old_methods = {}
    new_methods = {}
    for file in methods["old_methods_info"]:
        file_name = file["oldFilePath"].split("/")[-1]
        for method in file["deleteMethodFull"]:
            if not file["deleteMethodFull"][method]["lineNumber"]: 
                continue
            original_name = file["deleteMethodFull"][method]["originalFullName"]
            # old_methods.append({file_name + "__split__" + method: original_name})
            old_methods[file_name + "__split__" + method] = original_name

    for file in methods["new_methods_info"]:
        file_name = file["newFilePath"].split("/")[-1]
        for method in file["addMethodFull"]:
            original_name = file["addMethodFull"][method]["originalFullName"]
            # new_methods.append({file_name + "__split__" + method: original_name})
            new_methods[file_name + "__split__" + method] = original_name
    return old_methods, new_methods

def joern_callgraph_generate(cve: str, jarVersion: str, joernBinPath:str, methods: dict, cpgWorkspace: CPGWorkspace, status="", joernPath = ""):
    '''
    @param: cve: cve id
    @param: local_repo: local repo path
    @param: methods: part of method list of a CVE
    @param: cpgWorkspace: CPGWorkspace
    @param: status: new / old
    @return: call_layers: call layers of methods
    @return: save_path: path of cpg of a proj

    '''

    os.chdir(joernPath)

    call_layers = {_.split("__split__")[-1] :{} for _ in methods}
    name_mapping = {}

    for name, original_name in methods.items():
        name_mapping[name.split("__split__")[-1]] = original_name
    
    for method, original_name in methods.items():

        java_path, method_fullname = method.split("__split__")
        _caller_methods = joern_callgraph_operator(cpg_path=joernBinPath, method_fullname=method, cpgWorkspace=cpgWorkspace, joernPath = joernPath)
        for key, value in _caller_methods.items():
            name_mapping[key.split("__split__")[-1]] = value
        caller_methods = list(set(each.split("__split__")[-1] for each in _caller_methods.keys()))
        call_layers[method_fullname] = {_: {} for _ in caller_methods}
        
        for caller_method in caller_methods:
            _caller_caller_methods = joern_callgraph_operator(cpg_path=joernBinPath, method_fullname=caller_method, cpgWorkspace=cpgWorkspace, joernPath = joernPath)
            for key, value in _caller_caller_methods.items():
                name_mapping[key.split("__split__")[-1]] = value
            caller_caller_methods = list(set(each.split("__split__")[-1] for each in _caller_caller_methods.keys()))

            call_layers[method_fullname][caller_method] = caller_caller_methods
    

    with open("old_layer.json", "w") as fw:
        json.dump(call_layers, fw, indent = 4)
    
    return call_layers, joernBinPath, name_mapping
def joern_callgraph_operator(cpg_path: str, method_fullname: str, cpgWorkspace: CPGWorkspace, joernPath: str):
    '''
    @param: cpg_path: path of cpg of a proj
    @method_fullname: sign of a method
    @cpgWorkspace: CPGWorkspace

    get certain calls from CPG
    '''
    # method_fullname_noparm = method_fullname.split("(")[0]
    # method_code = method_code.replace(",","__split__")

    method_fullname_noparm, method_fullname_para = method_fullname.split("(", maxsplit=1)
    method_fullname_noparm = method_fullname_noparm.split("__split__")[-1]
    method_fullname_para_escape = method_fullname_para.replace(",","__split__")

    # os.system(ic(f"./joern --script methodcall.sc --params cpgFile=cpg.bin,methodFullName=\"{method_fullname_noparm}:\",methodCode=\"({method_fullname_para_escape}\""))
    scriptPath = "methodcall.sc"
    params = f"cpgFile={cpg_path},methodFullName=\"{method_fullname_noparm}:\",methodCode=\"({method_fullname_para_escape}\""
    cpgWorkspace.joernScript(script_path=scriptPath, params=params, JoernDistributedPath = joernPath)
    with open("./methodcaller.json", "r") as fr:
        json_obj = json.load(fr)
    method_list = method_caller_extract(json_obj)
    # method_list = []
    # for obj in json_obj:
    #     method_list.append(f"{obj['filename']}__split__{obj['fullName']}")
    # os.system("rm methodcaller.json")
    return method_list

def method_caller_extract(joern_methods):
    method_list = {}
    for obj in joern_methods:
        if "lineNumber" in obj.keys() and obj["fullName"] != ":<global>":
            ss = obj["fullName"].split(":")
            i = obj["code"].find("(")
            j = obj["code"].rfind(")")
            java_path = obj["filename"]
            # method_list.append(java_path + "__split__" + ss[0] + obj["code"][i : j + 1])
            method_list[java_path + "__split__" + ss[0] + obj["code"][i : j + 1]] = obj["fullName"]
    return method_list

def layer2graph(layer: dict, cve_id: str, jarVersion: str, RUNPATH : str, status: str, methodNameMapping: dict):
    _direct_affected_methods = list(layer.keys())
    nodes = []
    edges = []
    color = "red" if status == "old" else "green"
    for direct_affected_method, callers in layer.items():
        nodes.append({
            "id": methodNameMapping[direct_affected_method],
            "name": direct_affected_method.split("(")[0].split(".")[-2],
            "color": color
        })
        
        for caller, caller_callers in callers.items():
            caller_name = caller.split("__split__")[-1]
            if caller_name not in _direct_affected_methods:
                nodes.append({
                    "id": methodNameMapping[caller_name],
                    "name": caller.split("(")[0].split(".")[-2],
                    "color": "grey"
                })
            edges.append({"source": methodNameMapping[caller_name], 
                          "target": methodNameMapping[direct_affected_method], 
                          "weight": 3})
            for caller_caller in caller_callers:
                caller_caller_name = caller_caller.split("__split__")[-1]

                if caller_caller_name not in _direct_affected_methods or caller not in _direct_affected_methods:
                    continue
                if caller_caller_name not in _direct_affected_methods:
                    nodes.append({
                        "id": methodNameMapping[caller_caller_name],
                        "name": caller_caller.split("(")[0].split(".")[-2], 
                        "color": "grey"
                    })
                target_func = methodNameMapping[caller_name]
                target_func_param = target_func.split(":")[-1]
                target_func_name = target_func.split(":")[0].split(".")[-1]
                target_func = f"{target_func_name}:{target_func_param}"

                edges.append({
                    "source": methodNameMapping[caller_caller_name], 
                    "target": methodNameMapping[caller_name], 
                    "weight": 3
                })
    os.makedirs(os.path.join(RUNPATH, f"jar_file/CGs/{cve_id}"), exist_ok=True)
    cg_path = f"jar_file/CGs/{cve_id}/{cve_id}_{jarVersion}_{status}.json"
    direct_affected_methods = []
    for method in _direct_affected_methods:
        direct_affected_methods.append(methodNameMapping[method])

    nodes, edges = graph_post_deal(nodes, edges, direct_affected_methods)
    with open(os.path.join(RUNPATH, cg_path), "w") as fw:
        json.dump({"nodes":nodes, "edges":edges}, fw, indent = 4)
    print(f"CG with only nodes and edge wrote finished: {cg_path}")
    plot_cg({"nodes": nodes, "edges": edges}, cve_id, status, RUNPATH, jarVersion) 
    return cg_path

def graph_post_deal(nodes: dict, edges: dict, direct_affected_methods: list):

    nodes = deduplicate(nodes)
    edges = deduplicate(edges)
    

    while True:
        noise_nodes = []
        for node in nodes:
            node_indegree = False
            nodeid = node["id"]
            if nodeid in direct_affected_methods: 
                # print(f"{nodeid} in direct affected methods")
                continue
            for edge in edges:

                if nodeid == edge["target"]:
                    print(f"{nodeid} no indegree")
                    node_indegree = True
                    break
            if node_indegree == False:
                noise_nodes.append(node["id"])
        
        if not noise_nodes:
            break
        else:
            nodes = [node for node in nodes if node["id"] not in noise_nodes]
            edges = [edge for edge in edges if edge["source"] not in noise_nodes]

    index = 0
    for node_index, _ in enumerate(nodes):
        nodes[node_index]["index"] = index
        index += 1
    return nodes, edges

def deduplicate(d_set):
    seen = []
    deduplicated_set = []
    for element in d_set:
        # sorted_edge = tuple(sorted(element.items()))
        if element not in seen:
            seen.append(element)
            deduplicated_set.append(element)
    return deduplicated_set
if __name__ == "__main__":
    pass