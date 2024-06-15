import os
import json
import threading
import jpype
from icecream import ic
from joern_utils.CPGWorkspace import CPGWorkspace
from GitHubUtils import RepoDataLoader, get_commit_message
from DiffFileSearch import process_commit_changes
from DiffMethodExtract import methods_extract
from method_analysis import methods_number, methods_show
from DescNodeReg.reportFaksNode import text2sourceevidence
from VirtualMethodsConstruct import construct_virtual_nodes
from FunctionSimilarityCompare import functionSimComparator
from hits import hits_algorithm


work_dir = os.getcwd()
methods_dir = "cves_methods.json"
meta_dir = "cves_metainfo.json"
TAINT_ANALYSIS_PATH = os.path.join(work_dir, 'taint_analysis')
PREPATCH_EXTRACT_PATH = os.path.join(TAINT_ANALYSIS_PATH, 'prePatchExtractResult')

cpgWorkspace = CPGWorkspace()
cve_methods_lock = threading.Lock() 


def process_function(source: str, target: str):
    source_function = source.split("__split__")[-1]
    target_function = target.split("__split__")[-1]
    source_function, callCode = source_function.split('(')
    callCodeList = callCode[: callCode.find(')')].split(' ')
    callCode = ''
    
    if callCodeList:
        for seg in callCodeList:
            if not callCodeList.index(seg) % 2 == 0:
                callCode += seg.replace(",", '__split__') + ' '
        callCode.strip()

    return source_function, target_function, callCode


def github_methods_extract(metainfo_path: str, method_path: str):

    repoDataLoader = RepoDataLoader(os.path.join(work_dir, metainfo_path))
    cve_patchs = repoDataLoader.repo_clone()
    with open(meta_dir, "w") as fw:
        json.dump(cve_patchs, fw, indent = 4)

    with open("cves_methods.json", "r") as fr:
        cves_methods = json.load(fr)

    with open("CVE_DESC.json", "r") as fr:
        cves_desc = json.load(fr)

    for cve, cve_meta in cve_patchs.items():

        if cve in cves_methods: 
            continue
        patch = cve_meta["patch"]
        local_repo_path = cve_meta["local_repo"]
        commit_hash = patch.split("/")[-1]

        ic(local_repo_path)
        ic(commit_hash)
        old_file_lst, new_file_lst = process_commit_changes(cve=cve, repo_path=local_repo_path, commit_hash=patch.split("/")[-1], overwrite=True)
        changed_file_lst = list(set(old_file_lst) & set(new_file_lst))

        diff_files = []
        for changed_file in changed_file_lst:
            diff_files.append((changed_file, changed_file))

        
        old_methods, new_methods = methods_extract(cve=cve, local_repo_path=local_repo_path, work_dir=work_dir, diff_files=diff_files, commit_hash=patch.split("/")[-1], cpgWorkspace=cpgWorkspace)

        commit_msg = get_commit_message(local_repo_path=local_repo_path, commit_hash=commit_hash)
        nodes_in_commit_msg = text2sourceevidence(commit_msg + cves_desc[cve], work_dir)
        os.chdir(work_dir)
        
        cves_methods[cve] = {
            "old_methods_info": old_methods, 
            "new_methods_info": new_methods, 
            "commit_message_info": nodes_in_commit_msg
        }
        
        with cve_methods_lock:
            with open(methods_dir, 'w') as f:
                json.dump(cves_methods, f, indent=4)
        print(f"Wrote {cve} methods finished. ")


def calls_axonomy():
    with open(methods_dir, "r") as fr:
        cve_methods = json.load(fr)
    

    methods_number(cve_methods)
    with cve_methods_lock:
        pass

    # methods_show(metas, cve_methods ,cpgWorkspace=cpgWorkspace)
    
    with open(meta_dir, "r") as fr:
        metas = json.load(fr)
    with open(methods_dir, "r") as fr:
        cve_methods = json.load(fr)
    
    with open("cves_methods_40.json", "r") as fr:
        cve_methods_40 = json.load(fr)
    
    flag = False
    for cve, methods in cve_methods.items():
        meta_info = metas[cve]
        cpg_paths = methods_show(cve_id=cve, meta_data=meta_info, cve_methods=methods ,cpgWorkspace=cpgWorkspace)
        
        for cpg_path in cpg_paths:
            status = ""
            if "new" in cpg_path:
                status = "new"
            elif "old" in cpg_path:
                status = "old"

            if not status: continue
            cve_cg_path = os.path.join(work_dir, f"CGs/{cve}_{status}.json")
            
            with open(cve_cg_path, "r") as fr:
                cve_cg = json.load(fr)

            for edge in cve_cg["edges"]:
                # source_function, target_function, callCode = process_function(source=edge['source'], target=edge['target'])
                callsite = []
                callsite = cpgWorkspace.callSiteQuery(cpg_path=cpg_path, source_function_sign=edge['source'], target_function_sign=edge['target'])
                edge['callsite'] = callsite
        

            cg_with_virtual = construct_virtual_nodes(cg_info=cve_cg, commit_info=methods['commit_message_info'], cve=cve)
            with open(cve_cg_path, "w") as f:
                json.dump(cg_with_virtual, f, indent=4)
            print("updated CGS: ", cve_cg_path)


        old_func_similarity_scores = {}
        new_func_similarity_scores = {}
        

        for old_file in methods["old_methods_info"]:
            if not any(old_file["deleteMethodFull"]): break
            old_func_similarity_scores.update(functionSimComparator(old_file["deleteMethodFull"]))
        for new_file in methods["new_methods_info"]:
            if not any(new_file["addMethodFull"]): break
            new_func_similarity_scores.update(functionSimComparator(new_file["addMethodFull"]))
        

        if os.path.exists(os.path.join(work_dir, f"CGs/{cve}_old.json")):
            with open(os.path.join(work_dir, f"CGs/{cve}_old.json"), "r") as fr:
                old_cg = json.load(fr)
            old_hits_result = hits_algorithm(old_cg["nodes"], old_cg["edges"])[-1]
            old_hits_result = {key: value for key, value in old_hits_result.items() if value > 0}
        else:
            old_hits_result = None

        if os.path.exists(os.path.join(work_dir, f"CGs/{cve}_new.json")):
            with open(os.path.join(work_dir, f"CGs/{cve}_new.json"), "r") as fr:
                new_cg = json.load(fr)
            new_hits_result = hits_algorithm(new_cg["nodes"], new_cg["edges"])[-1]
            new_hits_result = {key: value for key, value in new_hits_result.items() if value > 0}
        else:
            new_hits_result = None

        if new_hits_result == None and old_hits_result == None:continue

        old_critical_nodes = {
            "hits": old_hits_result, 
            "similarity": old_func_similarity_scores
        }
        new_critical_nodes = {
            "hits": new_hits_result, 
            "similarity": new_func_similarity_scores
        }
        critical_nodes = {
            "old_info": old_critical_nodes, 
            "new_info": new_critical_nodes
        }
        with open(os.path.join(work_dir, f"./CGs/critical_{cve}.json"), "w") as fw:
            json.dump(critical_nodes, fw, indent=4)
        print(f"Updated critical methods: {os.path.join(work_dir, f'critical_{cve}.json')}")


if __name__ == "__main__":
    github_methods_extract()
    calls_axonomy()