import json
import os
from icecream import ic
import javalang
import git
import xml.etree.ElementTree as ET

JAR_PATH = "4.jar/jarDecompile"
NiCad_PATH = "2.methodology/graph_sim/nicad/NiCad-6.2"
GitHubMethodPath = "2.methodology/patch_callchain_generate/cves_methods.json"

def method_match(GitHub_Methods, ga, v, cve_meta = None, cveid = None, githubStatus = None):
    '''
    input: methods to be matched, ga
    putput: matched unmatched methods of target jar
    '''

    matchResult ={}
    v_lst = version_acquire(ga, v)

    with open(GitHubMethodPath, "r") as fr:
        GitHubMethodsMeta = json.load(fr)
        
    patch = cve_meta["patch"]
    local_repo = cve_meta["local_repo"]
    commitId = patch.split("/")[-1]
    ic(commitId, local_repo)
    
    targetcommit = get_parent_commit(local_repo, commitId) if githubStatus == "old" else commitId

    commitRollback(targetcommit, local_repo)
    nicadCacheClean()
    repofileCp(GitHub_Methods, local_repo)
    
    for v in v_lst:
        matchResult[v] = {
            "matchedPathMethodsMap":{},
            "matchedCloneMethodsMap":{}
        }
        ic(v)
        ga_folder = ga.replace(":", "-")
        v_foler = ga.split(":")[-1] + '-' + v
        jar_abs_path = os.path.join(JAR_PATH, ga_folder, v_foler)
        os.system(f"cp -r {jar_abs_path} {NiCad_PATH}/systems/tmp/JAR")
        JAR_Methods = extract_methods_from_directory()
        matchedMethods, unmatchedMethods = locate_methods_from_directory(GitHub_Methods, JAR_Methods)
        # ic(matchedMethods)
        # ic(unmatchedMethods)
        if not any(unmatchedMethods): continue
        matchResult[v]["matchedPathMethodsMap"] = matchedMethods
        gitHub_Method_Line_Map = gitHubMethodLineMap(GitHubMethodsMeta, unmatchedMethods, cveid, githubStatus)
        ic(gitHub_Method_Line_Map)
        os.chdir(NiCad_PATH)
        os.system("./nicad6 functions java systems/tmp versionfunction")
        for githubMethod, linetuple in gitHub_Method_Line_Map.items():
            jarSimMethod = funcCloneDetection("./systems/tmp_functions-blind-clones/tmp_functions-blind-clones-0.50.xml", 
                            githubMethod.split("__split__")[0], linetuple[0], linetuple[1])
            matchResult[v]["matchedCloneMethodsMap"][githubMethod] = jarSimMethod
        # if_match = extract_methods_from_nicad(NiCad_PATH)
        # if if_match: continue
        # print(f"not match")
    return matchResult
    
def version_acquire(ga, v):
    v_lst = []
    if v == None:

        ga_folder = ga.replace(":", "-")
        a_name = ga.split(":")[-1]
        jar_ga_path = os.path.join(JAR_PATH, ga.replace(":", "-"))
        if os.path.exists(jar_ga_path) and os.path.isdir(jar_ga_path):

            file_names = os.listdir(jar_ga_path)
            for file_name in file_names:
                v = file_name.strip(a_name)
                if v.startswith("CVE"):continue
                v_lst.append(v)
    else:
        v_lst = [v]
    return v_lst
def get_parent_commit(local_repo_path, commit_sha):
    repo = git.Repo(local_repo_path)
    commit = repo.commit(commit_sha)

    if commit.parents:
        parent_commit_sha = commit.parents[0].hexsha
        return parent_commit_sha
    else:
        print("Commit has no parent.")
        return None

        
def commitRollback(commitid, localRepoPath):
    os.chdir(localRepoPath)
    os.system(f"git checkout -f {commitid}")

def repofileCp(methods, local_repo):
    files = []
    for method in methods:
        files.append(method.split("__split__")[0])
    files = list(set(files))
    for file in files:
        abs_file_path = os.path.join(local_repo, file)
        os.system(f"cp -r {abs_file_path} {NiCad_PATH}/systems/tmp/GitHub")

def extract_methods_from_directory():
    JAR_PATH = os.path.join(NiCad_PATH, "systems/tmp/JAR")
    # ic(JAR_PATH)
    full_method_lst = []
    for root, dirs, files in os.walk(JAR_PATH):
        for file in files:
            if file.endswith(".java"):
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, JAR_PATH)
                relative_path = os.path.splitext(relative_path)[0].replace(os.path.sep, '.')
                with open(file_path, 'r') as file:
                    content = file.read()
                    tree = javalang.parse.parse(content)
                    for path, node in tree:
                        if isinstance(node, javalang.tree.MethodDeclaration):
                            full_method_path =  relative_path + "." + node.name
                            full_method_lst.append(full_method_path)
    # ic(full_method_lst)
    return full_method_lst
    
def locate_methods_from_directory(GitHub_Methods, JAR_Methods):
    GitHub_Methods = [_.replace("/", ".").split("(")[0] for _ in GitHub_Methods]
    # ic(JAR_Methods)
    # ic(GitHub_Methods)
    
    matched_methods = []
    unmatched_methods = []
    for GitHub_Method in GitHub_Methods:
        _, githubMethodFullName = GitHub_Method.split("__split__")
        if_matched = False
        for JAR_Method in JAR_Methods:
            if compare_last_n_path_elements(githubMethodFullName, JAR_Method, 3):
                matched_methods.append((GitHub_Method, JAR_Method))
                if_matched = True
                break
        if not if_matched: unmatched_methods.append(GitHub_Method)
    return matched_methods, unmatched_methods

def compare_last_n_path_elements(path1, path2, n):

    path_elements1 = path1.split('.')
    path_elements2 = path2.split('.')
    
    last_n_elements1 = path_elements1[-n:]
    last_n_elements2 = path_elements2[-n:]

    return last_n_elements1 == last_n_elements2

def extract_methods_from_nicad(NiCad_PATH):
    pass

def gitHubMethodLineMap(GitHubMethodsMeta, unmatchedMethods, cveid, githubStatus):

    unmatchedMethodsDic = {_ : None for _ in unmatchedMethods}
    
    for unmatchedMethod in unmatchedMethods:
        unmatchedPath, unmatchedMethodFullName = unmatchedMethod.split("__split__")
        FileStatus = "old_methods_info" if githubStatus == "old" else "new_methods_info"
        MethodStatus = "oldFilePath" if githubStatus == "old" else "newFilePath"
        MethodStatusBegin = "deleteMethodBegin" if githubStatus == "old" else "addMethodBegin"
        MethodStatusEnd = "deleteMethodEnd" if githubStatus == "old" else "addMethodEnd"

        unmatchedFiles = GitHubMethodsMeta[cveid][FileStatus]
        for unmatchedFile in unmatchedFiles:
            if unmatchedFile[MethodStatus].replace("/", ".") != unmatchedPath:  continue
            methodsBeginLines = unmatchedFile[MethodStatusBegin]
            methodsEndLines = unmatchedFile[MethodStatusEnd]
            for method in methodsBeginLines:
                if not method.startswith(f"{unmatchedMethodFullName}("): 
                    continue
                BeginLine = methodsBeginLines[method]
                EndLine = methodsEndLines[method]
                unmatchedMethodsDic[unmatchedMethod] = (BeginLine, EndLine)
    return unmatchedMethodsDic

def funcCloneDetection(xml_file, GitHubFilePath, startline, endline):
    simMax = 0
    threshold = 10
    tree = ET.parse(xml_file)
    root = tree.getroot()

    jarNicadSimMethod = None
    for clone_elem in root.findall('.//clone'):
        simNicad = int(clone_elem.get("similarity"))
        nicadMethod1 = clone_elem.find('.//source[1]')
        nicadMethod2 = clone_elem.find('.//source[2]')

        fileName1 = nicadMethod1.get('file').replace("/", ".")
        fileName2 = nicadMethod2.get('file').replace("/", ".")

        nicadStart1 = nicadMethod1.get('startline')
        nicadEndline1 = nicadMethod1.get('endline')
        nicadStart2 = nicadMethod2.get('startline')
        nicadEndline2 = nicadMethod2.get('endline')  
        
        if compare_last_n_path_elements(fileName1,GitHubFilePath,2) and \
            int(nicadStart1) == int(startline) and int(nicadEndline1) == int(endline):
            if "systems.tmp.JAR." in fileName2 and simNicad > threshold and simNicad > simMax:
                    #update
                    simMax = simNicad
                    jarNicadSimMethod = {
                        "jarPath": fileName2,
                        "startline": nicadStart2,
                        "endline": nicadEndline2
                    }
                    
                    
        if compare_last_n_path_elements(fileName2,GitHubFilePath,2) and \
            int(nicadStart2) == int(startline) and int(nicadEndline2) == int(endline):
            if "systems.tmp.JAR." in fileName1 and simNicad > threshold and simNicad > simMax:
                    #update
                    simMax = simNicad
                    jarNicadSimMethod = {
                        "jarPath": fileName1,
                        "startline": nicadStart1,
                        "endline": nicadEndline1
                    }
    return jarNicadSimMethod
            

    return None

def nicadCacheClean():
    os.chdir(NiCad_PATH)
    os.system("rm -r ./systems/tmp/GitHub/*")
    os.system("rm -r ./systems/tmp/JAR/*")
    os.system("rm -r tmp_functions-blind-clones")
    os.system("rm -r ./systems/*.log")
    os.system("rm -r ./systems/*.xml")
