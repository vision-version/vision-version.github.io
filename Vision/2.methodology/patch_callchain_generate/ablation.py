import json
import os
import shutil


source_dir = 'CGs'
target_dir = 'CGs_withoutRef'


os.makedirs(target_dir, exist_ok=True)


for file_name in os.listdir(source_dir):

    if file_name.startswith('CVE') and file_name.endswith('.json'):
        source_file_path = os.path.join(source_dir, file_name)
        target_file_path = os.path.join(target_dir, file_name)

        with open(source_file_path, "r") as fr:
            cg_graph = json.load(fr)
        
        cp_cg_graph = {}
        cp_cg_graph["nodes"] = []
        cp_cg_graph["edges"]= []
        
        for node in cg_graph["nodes"]:
            if node.get("name") == "Virtual": pass
            else: cp_cg_graph["nodes"].append(node)
        for edge in cg_graph["edges"]:
            if  edge["source"].startswith("Virtual") or edge["target"].startswith("Virtual"): pass
            else: cp_cg_graph["edges"].append(edge)

        with open(target_file_path, "w") as fw:
            json.dump(cp_cg_graph, fw, indent = 4)
