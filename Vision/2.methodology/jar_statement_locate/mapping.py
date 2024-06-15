import json
import os
from icecream import ic

from statement_match import StatementMatch
from NicadMatch import NicadMatcher
from ModifiedLinesMap import linesMap
from MethodRuleMatch import methodRuleMatch
from multiprocessing import Pool

BASEPATH = os.getcwd()

GT_PATH = os.path.join(BASEPATH,"../../1.empirical/cve_analysis_all.json")
methods_dir = os.path.join(BASEPATH, "../patch_callchain_generate/cves_methods.json")
CVE_GAV_PATH = os.path.join(BASEPATH,"../../1.empirical/cve_gav_all.json")
CVE_MATA_PATH = os.path.join(BASEPATH,"../patch_callchain_generate/cves_metainfo.json")
GITHUB_PATCH_PATH = os.path.join(BASEPATH,"../patch_callchain_generate/github_diff")
METHOD_MATCHED_OUTPUT_PATH = os.path.join(BASEPATH,"../jar_statement_locate/methodMatchResult.json")
RULEBASED_METHOD_MATCHED_OUTPUT_PATH = os.path.join(BASEPATH,"../jar_statement_locate/rulebasedMethodMatechResult.json")
LINE_MATCHED_OUTPUT_PATH = os.path.join(BASEPATH,"../jar_statement_locate/lineMatchResult.json")
JAR_PATH = os.path.join(BASEPATH, "../../4.jar/jarDecompile")

with open(GT_PATH, "r") as fr:
    gt_cve = json.load(fr)
with open(CVE_GAV_PATH, "r") as fr:
    cve_gav = json.load(fr)
with open(methods_dir, "r") as fr:
    cve_methods = json.load(fr)
with open(CVE_MATA_PATH, "r") as fr:
    cve_meta = json.load(fr)
def change_methods_extract(methods):
    old_methods = []
    new_methods = []
    for file in methods["old_methods_info"]:
        file_name = file["oldFilePath"]
        for method in file["deleteMethodFull"]:
            methodBegin = str(file["deleteMethodBegin"][method])
            methodEnd = str(file["deleteMethodEnd"][method])
            if not file["deleteMethodFull"][method]["lineNumber"]: continue
            old_methods.append(file_name + "__split__" + method + "__split__" + methodBegin + "__split__" + methodEnd)

    for file in methods["new_methods_info"]:
        file_name = file["newFilePath"]
        for method in file["addMethodFull"]:
            methodBegin = str(file["addMethodBegin"][method])
            methodEnd = str(file["addMethodEnd"][method])
            if not file["addMethodFull"][method]["lineNumber"]:
                ic(method)
            new_methods.append(file_name + "__split__" + method + "__split__" + methodBegin + "__split__" + methodEnd)
    return old_methods, new_methods

def nicadMatch(initJson):
    '''
    '''
    for cve in gt_cve:
        ic(cve)
        old_methods, new_methods = change_methods_extract(cve_methods[cve])
        cve_ga = cve_gav[cve]
        nicadMatch = NicadMatcher(old_methods, new_methods, cve_ga, None, cve_meta[cve], cve)

        nicadMatch.nicadMethodMatch()

        # nicadMatch.nicadHunkMatch()

def ruledClassMethodLocate():
    '''
    '''


    with open("initMatchResult.json", "r") as fr:
        initMethods = json.load(fr)
    

    with open(RULEBASED_METHOD_MATCHED_OUTPUT_PATH, "r") as fr:
        clonedMethods = json.load(fr)
    

    clonedMethods["CVE-2022-24897"] = initMethods["CVE-2022-24897"]
    with open(RULEBASED_METHOD_MATCHED_OUTPUT_PATH, "w") as fw:
        json.dump(clonedMethods, fw, indent = 4)


    cves = []
    jarVs = []
    jarDicts = []
    githubPathPaths = []
    
    
    for cve, jarVs_dic in clonedMethods.items():
        for jarV, jarV_dic in jarVs_dic.items():
            #     print(jarV)
            #     continue
            cves.append(cve)
            jarVs.append(jarV)
            jarDicts.append(jarV_dic)
            githubPathPaths.append(os.path.join(GITHUB_PATCH_PATH, cve))
            ic(jarV)
            
    cjjg = list(zip(cves, jarVs, jarDicts, githubPathPaths))
 
    with Pool(600) as pool:
        matchedResults = pool.starmap(methodRuleMatch, cjjg)
    for matchedGAV in matchedResults:
        cve = matchedGAV[0]
        jarV = matchedGAV[1]
        matchedGAVMethods = matchedGAV[2]
        clonedMethods[cve][jarV] = matchedGAVMethods
        # cves, jarVs, jarDicts, githubPathPaths
    with open(RULEBASED_METHOD_MATCHED_OUTPUT_PATH, "w") as fw:
        json.dump(clonedMethods, fw, indent = 4)


def modifiedLineLocate():
    '''
    pass
    '''
    with open(RULEBASED_METHOD_MATCHED_OUTPUT_PATH, "r") as fr:
        functionWiseSim = json.load(fr)

    cves = []
    jarVs = []
    jarDicts = []
    cvesMethods = []

    with open(LINE_MATCHED_OUTPUT_PATH, "r") as fr:
        cves_githubjarLineMap = json.load(fr)
    # cves_githubjarLineMap = {}
    
    for cve, jarVs_dic in functionWiseSim.items():
        cves_githubjarLineMap[cve] = {}
        for jarV, jarV_dic in jarVs_dic.items():
            cves.append(cve)
            jarVs.append(jarV)
            jarDicts.append(jarV_dic)
            cvesMethods.append(cve_methods[cve])
    cjjg = list(zip(cves, jarVs, jarDicts, cvesMethods))
    with Pool(1000) as pool:
        matchedResults = pool.starmap(linesMap, cjjg)
    for matchedMethodLine in matchedResults:
        cve = matchedMethodLine[0]
        jarV = matchedMethodLine[1]
        old_githubjarLineMap = matchedMethodLine[2]
        new_githubjarLineMap = matchedMethodLine[3]
        cves_githubjarLineMap[cve][jarV] = {
            "old": old_githubjarLineMap,
            "new": new_githubjarLineMap
        }
    with open(LINE_MATCHED_OUTPUT_PATH, "w") as fw:
        json.dump(cves_githubjarLineMap, fw, indent = 4)

def initMatch():
    with open("initMatchResult.json", "r") as fr:
        initMatchResult = json.load(fr)
    for cve in cve_methods: 
        initMatchResult[cve] = {}
        old_methods, new_methods = change_methods_extract(cve_methods[cve])
        cve_ga = cve_gav[cve]
        v_dic= version_acquire(cve_ga)
        for v in v_dic:
            initMatchResult[cve][v] ={
                "old": {},
                "new": {},
                "absPath": {}
            }
            initMatchResult[cve][v]["old"].update({each:{} for each in old_methods} )
            initMatchResult[cve][v]["new"].update({each:{} for each in new_methods} )
            initMatchResult[cve][v]["absPath"] = v_dic[v]
            print(initMatchResult[cve][v]["absPath"])
    with open("initMatchResult.json", "w") as fw:
        json.dump(initMatchResult, fw, indent = 4)
        
    return initMatchResult

def version_acquire(ga):
    v_lst = {}
    ga_folder = ga.replace(":", "-")
    a_name = ga.split(":")[-1]
    jar_ga_path = os.path.join(JAR_PATH, ga.replace(":", "-"))
    if os.path.exists(jar_ga_path) and os.path.isdir(jar_ga_path):

        file_names = os.listdir(jar_ga_path)

        for file_name in file_names:
            v = file_name.replace(a_name + "-", "")
            if v.startswith("CVE"):continue
            v_lst.update({v:os.path.join(jar_ga_path, file_name)})
    return v_lst
def main():
    initJson = initMatch()
    nicadMatch(initJson)
    ruledClassMethodLocate()
    modifiedLineLocate()

if __name__ == "__main__":
    main()