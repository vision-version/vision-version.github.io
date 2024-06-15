import json
from icecream import ic
from set_operate import analyze_sets
from github import Github
import os
import git
import re
from graph import plot_cg
from GitHubUtils import RepoDataLoader, get_commit_message
from DescNodeReg.reportFaksNode import text2sourceevidence

from joern_utils.CPGWorkspace import CPGWorkspace

METHOD_PATH = os.getcwd()
JOERN_PATH = "../joern-cli"

def deduplicate(d_set):
    seen = []
    deduplicated_set = []
    for element in d_set:
        # sorted_edge = tuple(sorted(element.items()))
        if element not in seen:
            seen.append(element)
            deduplicated_set.append(element)
    return deduplicated_set


def methods_number(cve_methods: dict):

    single_method_cnt = 0
    mullti_method_cnt = 0
    none_method_cnt = 0
    

    mullti_method_number = 0
    for cve, methods in cve_methods.items():
        # ic(cve)
        old_m, new_m = change_methods_extract(methods)
        old_methods = old_m.keys()
        new_methods = new_m.keys()
        fullset = set(new_methods) | set(old_methods)
        if len(fullset) == 1:
            single_method_cnt += 1
        elif len(fullset) > 1:
            mullti_method_cnt += 1
            mullti_method_number += len(fullset)
        else:
            none_method_cnt += 1
        analyze_sets(set(new_methods), set(old_methods))


def change_methods_extract(methods):
    '''
    @param: methods
    return old & new methods of a CVE
    '''
    old_methods = {}
    new_methods = {}
    for file in methods["old_methods_info"]:
        file_name = file["oldFilePath"]
        for method in file["deleteMethodFull"]:
            if not file["deleteMethodFull"][method]["lineNumber"]: 
                continue
            original_name = file["deleteMethodFull"][method]["originalFullName"]
            # old_methods.append({file_name + "__split__" + method: original_name})
            old_methods[file_name + "__split__" + method] = original_name

    for file in methods["new_methods_info"]:
        file_name = file["newFilePath"]
        for method in file["addMethodFull"]:
            if not file["addMethodFull"][method]["lineNumber"]:
                ic(method)
            original_name = file["addMethodFull"][method]["originalFullName"]
            # new_methods.append({file_name + "__split__" + method: original_name})
            new_methods[file_name + "__split__" + method] = original_name
    return old_methods, new_methods


def joern_callgraph_generate(cve: str, local_repo: str, methods: dict, commitHash: str, cpgWorkspace: CPGWorkspace, status=""):
    '''
    @param: cve: cve id
    @param: local_repo: local repo path
    @param: methods: part of method list of a CVE
    @param: cpgWorkspace: CPGWorkspace
    @param: status: new / old
    @return: call_layers: call layers of methods
    @return: save_path: path of cpg of a proj

    '''
    
    os.chdir(JOERN_PATH)

    save_path = f"./cache/{cve}_{status}_{commitHash}.bin"
    call_layers = {_.split("__split__")[-1] :{} for _ in methods}
    name_mapping = {}
    # name_mapping.update(methods)
    for name, original_name in methods.items():
        name_mapping[name.split("__split__")[-1]] = original_name
    
    for method, original_name in methods.items():

        java_path, method_fullname = method.split("__split__")
        _caller_methods = joern_callgraph_operator(cpg_path=save_path, method_fullname=method, cpgWorkspace=cpgWorkspace)
        for key, value in _caller_methods.items():
            key = key.replace(local_repo, '').strip('/')
            name_mapping[key.split("__split__")[-1]] = value
        caller_methods = _caller_methods.keys()
        

        caller_methods = list(set([each.replace(local_repo, "").strip("/") for each in caller_methods]))
        call_layers[method_fullname] = {_: {} for _ in caller_methods}
        
        for caller_method in caller_methods:
            caller_java_path, caller_fullname = caller_method.split("__split__")
            _caller_caller_methods = joern_callgraph_operator(cpg_path=save_path, method_fullname=caller_fullname, cpgWorkspace=cpgWorkspace)
            for key, value in _caller_caller_methods.items():
                key = key.replace(local_repo, '').strip('/')
                name_mapping[key.split("__split__")[-1]] = value
            caller_caller_methods = _caller_caller_methods.keys()

            caller_caller_methods = [each.replace(local_repo, "").strip("/") for each in caller_caller_methods]
            call_layers[method_fullname][caller_method] = list(set(caller_caller_methods))
    
    # os.system("rm cpg.bin")
    os.chdir(METHOD_PATH)
    with open("old_layer.json", "w") as fw:
        json.dump(call_layers, fw, indent = 4)
    
    return call_layers, save_path, name_mapping


def joern_callgraph_operator(cpg_path: str, method_fullname: str, cpgWorkspace: CPGWorkspace):
    '''
    @param: cpg_path: path of cpg of a proj
    @method_fullname: sign of a method
    @cpgWorkspace: CPGWorkspace

    get certain calls from CPG
    '''
    os.chdir(JOERN_PATH)
    # method_fullname_noparm = method_fullname.split("(")[0]
    # method_code = method_code.replace(",","__split__")
    method_fullname_noparm, method_fullname_para = method_fullname.split("(", maxsplit=1)
    method_fullname_noparm = method_fullname_noparm.split("__split__")[-1]
    method_fullname_para_escape = method_fullname_para.replace(",","__split__")

    # os.system(ic(f"./joern --script methodcall.sc --params cpgFile=cpg.bin,methodFullName=\"{method_fullname_noparm}:\",methodCode=\"({method_fullname_para_escape}\""))
    scriptPath = "methodcall.sc"
    params = f"cpgFile={cpg_path},methodFullName=\"{method_fullname_noparm}:\",methodCode=\"({method_fullname_para_escape}\""
    cpgWorkspace.joernScript(script_path=scriptPath, params=params)
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


def layer2graph(layer: dict, cve_id: str, status: str, methodNameMapping: dict):
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

                if caller_caller_name not in _direct_affected_methods and caller not in _direct_affected_methods:
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

    cg_path = f"CGs/{cve_id}_{status}.json"
    direct_affected_methods = []
    for method in _direct_affected_methods:
        direct_affected_methods.append(methodNameMapping[method])

    nodes, edges = graph_post_deal(nodes, edges, direct_affected_methods)
    with open(os.path.join(METHOD_PATH, cg_path), "w") as fw:
        json.dump({"nodes":nodes, "edges":edges}, fw, indent = 4)
    print(f"CG with only nodes and edge wrote finished: {cg_path}")
    plot_cg({"nodes": nodes, "edges": edges}, cve_id, status) 
    return cg_path
    



def methods_show(cve_id: str, meta_data: dict, cve_methods: dict, cpgWorkspace: CPGWorkspace):
    '''
    @params: cve_id
    @params: meta_data: meta data (local repo address) of a CVE
    @params: cve_methods: methods information of a CVE
    @params: cpgWorkspace: CPGWorkspace (singlten)

    @return: list of path of cpg of a proj
    '''

    access_token = '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'
    g = Github(access_token)
    
    ic(cve_id)
    # if cve_id != "CVE-2022-22976": continue
    patch_url = meta_data["patch"]
    local_repo = meta_data["local_repo"]
    commit_hash = patch_url.split("/")[-1]
    repo = git.Repo(local_repo)

    commit = repo.commit(commit_hash)
    commit_parent = commit.parents[0]
    # methods = cve_methods[cve_id]
    # repoLoder = RepoDataLoader()
    old_methods, new_methods = change_methods_extract(cve_methods)
    # with open("methods_test.json", 'w') as f:
    #     json.dump({"old_methods": old_methods, "new_methods": new_methods}, f, indent=4)


    # repo.git.reset('--hard', commit_parent)

    # method_name_mapping = {}
    # for method_info in cve_methods["old_methods_info"]:
    #     delete_method_full = method_info.get("deleteMethodFull", {})
    #     for method_name, method_details in delete_method_full.items():
    #         method_name_mapping[method_name] = method_details["originalFullName"]
    # # print(json.dumps(method_name_mapping, indent=4))
    old_cpg_file = ""
    new_cpg_file = ""

    if len(old_methods) > 1:
        old_layer, old_cpg_file, name_mapping = joern_callgraph_generate(cve = cve_id, local_repo=local_repo, methods=old_methods, cpgWorkspace=cpgWorkspace, status="old", commitHash=commit_parent)
        with open("old_name_mapping.json", "w") as fw:
            json.dump(name_mapping, fw, indent=4)
        with open("old_layer.json", 'w') as lf:
            json.dump(old_layer, lf, indent=4)
        layer2graph(layer=old_layer, cve_id=cve_id, status="old", methodNameMapping=name_mapping)


    # repo.git.reset('--hard', commit)
    # method_name_mapping = {}
    # for method_info in cve_methods["new_methods_info"]:
    #     delete_method_full = method_info.get("addMethodFull", {})
    #     for method_name, method_details in delete_method_full.items():
    #         method_name_mapping[method_name] = method_details["originalFullName"]
    # # print(json.dumps(method_name_mapping, indent=4))
    

    if len(new_methods) > 1:
        new_layer, new_cpg_file, name_mapping = joern_callgraph_generate(cve = cve_id, local_repo=local_repo, methods=new_methods, cpgWorkspace=cpgWorkspace, status="new", commitHash=commit)
        with open("new_name_mapping.json", "w") as fw:
            json.dump(name_mapping, fw, indent=4)
        layer2graph(layer=new_layer, cve_id=cve_id, status="new", methodNameMapping=name_mapping)

    return [old_cpg_file, new_cpg_file]



if __name__ == "__main__":
    pass

        