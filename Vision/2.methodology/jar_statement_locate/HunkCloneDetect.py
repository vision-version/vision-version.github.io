import os
import json
from icecream import ic
import git
import xml.etree.ElementTree as ET

def locate_methods_from_directory(GitHub_Methods, JAR_Methods):
    GitHub_Methods = [_.replace("/", ".").split("(")[0] for _ in GitHub_Methods]
    # ic(JAR_Methods)
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

def hunkCloneDetection(xml_file, GitHubFilePath, startline, endline, githubStatus):
    threshold = 60
    tree = ET.parse(xml_file)
    root = tree.getroot()
    fileSimEachV = {}

    for clone_elem in root.findall('.//clone'):
        simNicad = int(clone_elem.get("similarity"))
        nicadMethod1 = clone_elem.find('.//source[1]')
        nicadMethod2 = clone_elem.find('.//source[2]')

        fileName1 = nicadMethod1.get('file')
        fileName2 = nicadMethod2.get('file')

        # fileName1 = nicadMethod1.get('file').replace("/", ".")
        # fileName2 = nicadMethod2.get('file').replace("/", ".")

        nicadStart1 = nicadMethod1.get('startline')
        nicadEndline1 = nicadMethod1.get('endline')
        nicadStart2 = nicadMethod2.get('startline')
        nicadEndline2 = nicadMethod2.get('endline')  
        
        file1 = {
            "fileName": fileName1,
            "nicadStart": nicadStart1,
            "nicadEnd": nicadEndline1
        }
        file2 = {
            "fileName": fileName2,
            "nicadStart": nicadStart2,
            "nicadEnd": nicadEndline2            
        }

        ifMatch, githubFile, mvnFile = matchGitHubMvnFile(file1, file2, githubStatus)
        if not ifMatch: continue

        githubFile["fileName"] = githubFile["fileName"].replace(f"{githubStatus}_", "")
        if compare_last_n_path_elements(githubFile["fileName"],GitHubFilePath,1) and \
            int(githubFile["nicadStart"]) >= int(startline) and int(githubFile["nicadEnd"]) <= int(endline):
            # if simNicad < threshold: continue
            simJarMethod = {
                "jar_Path": mvnFile["fileName"],
                "jar_startline": mvnFile["nicadStart"],
                "jar_endline": mvnFile["nicadEnd"],
                "github_startline": githubFile["nicadStart"],
                "github_endline": githubFile["nicadEnd"],
                "simNicad": simNicad
            }
            if mvnFile["v"] not in fileSimEachV: 
                fileSimEachV[mvnFile["v"]] = [simJarMethod]
            else:
                fileSimEachV[mvnFile["v"]].append(simJarMethod)
                
    return fileSimEachV

def matchGitHubMvnFile(file1, file2, githubStatus):
    if "systems/tmp/JAR" in file1["fileName"] and "systems/tmp/GitHub" in file2["fileName"]:
        githubFile = file2
        mvnFile = file1
    elif "systems/tmp/JAR" in file2["fileName"] and "systems/tmp/GitHub" in file1["fileName"]:
        githubFile = file1
        mvnFile = file2
    else:
        return False, None, None
    if not githubStatus + "_" in githubFile["fileName"]:
        return False, None, None
    else:
        mvnFile["v"] = mvnFile["fileName"].split("/")[3].split("-")[-1]
        return True, githubFile, mvnFile
    
def compare_last_n_path_elements(path1, path2, n):
    path_elements1 = path1.split('.')
    path_elements2 = path2.split('.')
    
    last_n_elements1 = path_elements1[-n:]
    last_n_elements2 = path_elements2[-n:]

    return last_n_elements1 == last_n_elements2