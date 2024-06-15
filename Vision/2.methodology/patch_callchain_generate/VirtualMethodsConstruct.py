import json
import os
import re
from joern_utils.CPGWorkspace import CPGWorkspace
from DescNodeReg.reportFaksNode import text2sourceevidence
from method_analysis import joern_callgraph_operator, joern_callgraph_generate

current_path = os.getcwd()
joern_path = os.path.join(current_path[:current_path.rfind("methodology") + len("methodology")], "joern-cli")
cve_path = os.path.join(current_path[:current_path.rfind("methodology") + len("methodology")], "patch_callchain_generate/CGs/")
cache_path = os.path.join(joern_path, "cache")
repo_path = "GithubCache"


def commit_msg_methods_construct(cve: str, commit_info: dict, cg_info: dict):
    commit_methods = commit_info['method_names']
    commit_class = commit_info['classnamelst']
    commit_files = commit_info['pathlst']
    
    commit_file_methods = []
    commit_class_methods = []

    nodes_index = cg_info['nodes'][-1]['index']
    nodes_class = []
    nodes_method = []
    

    for node in cg_info['nodes']:
        nodes_class.append(node['name'])
        nodes_func = node['id'].split("__split__")[-1]
        pattern = r'\b\w+[\w<>\[\]]*\(\)'
        match = re.search(pattern, nodes_func)
        if match:
            nodes_method.append(match.group())

    # if commit_files:
        # for cf in commit_files:
        #     commit_file_methods[cf] = []
        #     cpgWorkspace.joernScript(script_path="search_method_in_file.sc", params=f"cpgFile={cpgPath},fileName={cf}")
        #     os.chdir(current_path)
        #     with open("search_method_in_file.json", "r") as fr:
        #         json_obj = json.load(fr)
        #         commit_file_methods[cf] = json_obj
        # os.system(f"rm {os.path.join(joern_path, 'search_method_in_file.json')}")
    
        # print(json.dumps(commit_file_methods, indent=4))
        # for method, called_method in commit_file_methods.items():
        #     if method not in nodes_method:
        #         nodes_index += 1
        #         nodes_class.append("VirtualMethod")
        #         nodes_method.append(method)
        #         cg_info['nodes'].append({
        #             "id": method, 
        #             "name": "PENDING",
        #             "index": nodes_index
        #         })
        #         for cm in called_method:
        #             if cm not in nodes_method:
        #                 nodes_index += 1
        #                 nodes_class.append("VirtualMethod")
        #                 nodes_method.append(cm)
        #                 methods['nodes'].append({
        #                     "id": cm, 
        #                     "name": "PENDING",
        #                     "index": nodes_index
        #                 })
        #             methods['edges'].append({
        #                 'source': method, 
        #                 'target': cm
        #             })


    if commit_methods:
        for m in commit_methods:
            nodes_index += 1
            fake_node = {
                "index": nodes_index,
                "name": "Virtual",
                "id": f"Virtual_CommitMessage_Method__split__{m}"
            }
            cg_info['nodes'].append(fake_node)
            if m not in nodes_method:
                print(f"[COMMIT MESSAGE] No such method in CG ({cve}): {m}")
            else:
                for node_m in cg_info['nodes']:
                    if m in node_m['id']:
                        cg_info['edges'].append({
                            "source": fake_node['id'], 
                            "target": node_m['id'], 
                            "weight": 1, 
                            "callsite": []
                        })
    

    if commit_class:
        for c in commit_class:
            if c not in nodes_class:
                nodes_index += 1 
                cg_info['nodes'].append({
                    "index": nodes_index, 
                    "name": "Virtual", 
                    "id": f"Virtual_CommitMessage_Class__split__{c}"
                })
                print(f"[COMMIT MESSAGE] No such class in CG ({cve}): {c}")
            else:
                fake_nodes = []
                for n in cg_info['nodes']:
                    if n['name'] == c:
                        nodes_index += 1
                        fake_node = {
                            "index": nodes_index,
                            "name": "Virtual",
                            "id": f"Virtual_CommitMessage_Class__split__{c}"
                        }
                        fake_nodes.append(fake_node)
                        cg_info['edges'].append({
                            "source": fake_node['id'], 
                            "target": n['id'], 
                            "weight": 1, 
                            "callsite": []
                        })
                cg_info['nodes'].extend(fake_nodes)
    return cg_info


def entry_construct(cg_info: dict):
    nodes_index = cg_info['nodes'][-1]['index']
    nodes_index += 1
    entry = {
        "index": nodes_index, 
        "name": "Virtual", 
        "id": "Virtual__split__Entry",
        "color": "yellow",
    }

    if_matched = False
    for node in cg_info["nodes"]:

        if node['name'] == "Virtual": continue

        if_indgree = False
        if_outdegree = False
        for edge in cg_info['edges']:
            if edge["source"] == node['id']: if_outdegree = True
            if edge["target"] == node['id']: if_indgree = True

        if not if_indgree and if_outdegree:
            if_matched = True
            cg_info['edges'].append({
                "source": entry['id'],
                "target": node['id'],
                "weight": 1,
                "callsite": []
            })

    if if_matched:
        cg_info['nodes'].append(entry)
    return cg_info


def exit_construct(cg_info: dict):
    nodes_index = cg_info['nodes'][-1]['index']
    nodes_index += 1
    exit = {
        "index": nodes_index, 
        "name": "Virtual", 
        "id": "Virtual__split__Exit",
        "color": "yellow",
    }

    if_matched = False
    for node in cg_info["nodes"]:

        if node['name'] == "Virtual": continue

        if_indgree = False
        if_outdegree = False
        for edge in cg_info['edges']:
            if edge["source"] == node['id']: if_outdegree = True
            if edge["target"] == node['id']: if_indgree = True

        if if_indgree and not if_outdegree:
            if_matched = True
            cg_info['edges'].append({
                "source": exit['id'],
                "target": node['id'],
                "weight": 1,
                "callsite": []
            })

    if if_matched:
        cg_info['nodes'].append(exit)
    return cg_info



def construct_virtual_nodes(cg_info: dict, commit_info: str, cve: str):
    new_info = commit_msg_methods_construct(cg_info=cg_info, commit_info=commit_info, cve=cve)
    new_info = entry_construct(cg_info=new_info)
    new_info = exit_construct(cg_info=new_info)
    return new_info




if __name__ == "__main__":
    with open("2.methodology/patch_callchain_generate/CGs/CVE-2022-29599_new.json", 'r') as methods_f:
        cg_info = json.load(methods_f)

    commit_info_dict = {
            "method_names": [],
            "classnamelst": [
                "BourneShell"
            ],
            "pathlst": [],
            "langrelatedfiles": []
        }
    new_methods = construct_virtual_nodes(cg_info=cg_info, commit_info=commit_info_dict, cve="CVE-2022-29599")
    with open("fake_nodes_test.json", 'w') as f:
        json.dump(new_methods, f, indent=4)