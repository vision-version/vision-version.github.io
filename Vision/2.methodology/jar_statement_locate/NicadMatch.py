import os
import json
from icecream import ic
import git
import xml.etree.ElementTree as ET
from FuncCloneDetect import gitHubMethodLineMap, funcCloneDetection
from HunkCloneDetect import hunkCloneDetection

BasePath = os.getcwd()
GitHubMethodPath = os.path.join(BasePath, "../patch_callchain_generate/cves_methods.json")
JAR_PATH = os.path.join(BasePath, "../../4.jar/jarDecompile")
NiCad_PATH = os.path.join(BasePath, "../graph_sim/nicad/NiCad-6.2")
MethodSimSavePath = os.path.join(BasePath, "methodMatchResult.json")
HunkSimSavePath = os.path.join(BasePath, "hunkMatchResult.json")

class NicadMatcher():
    def __init__(self, old_methods, new_methods, ga, v, 
                 cve_meta = None, cveid = None):
        self.old_methods = old_methods
        self.new_methods = new_methods
        self.ga = ga
        self.v = v
        self.cve_meta = cve_meta
        self.cveid = cveid
    
    def nicadMethodMatch(self):
        '''
        '''
        v_lst = NicadMatcher.version_acquire(self.ga, self.v)

        with open(GitHubMethodPath, "r") as fr:
            GitHubMethodsMeta = json.load(fr)
            
        patch = self.cve_meta["patch"]
        local_repo = self.cve_meta["local_repo"]
        commitId = patch.split("/")[-1]
        ic(commitId, local_repo)
        
        oldcommitID = NicadMatcher.get_parent_commit(local_repo, commitId)
        newcommitID = commitId

        NicadMatcher.nicadGitHubCacheClean()
        self.repofileCp("/2.methodology/patch_callchain_generate/github_diff", self.cveid, "old")
        self.repofileCp("/2.methodology/patch_callchain_generate/github_diff", self.cveid, "new")
        
        os.chdir(NiCad_PATH)
        for v in v_lst:
            try:
                with open(MethodSimSavePath, 'r') as fr:
                    saveMethodResults = json.load(fr)
            except FileNotFoundError:
                saveMethodResults = {}
            if self.cveid not in saveMethodResults:
                saveMethodResults[self.cveid] = {}
            if v in saveMethodResults[self.cveid]:
                print(f"{v}")
                continue
            # ic(v)
            NicadMatcher.nicadJarCacheClean()
            ga_folder = self.ga.replace(":", "__split__")
            v_foler = self.ga.split(":")[-1] + '-' + v
            jar_abs_path = os.path.join(JAR_PATH, ga_folder.replace("__split__", "-"), v_foler)

            os.system(f"cp -r {jar_abs_path} {NiCad_PATH}/systems/tmp/JAR")
            os.system("./nicad6 functions java systems/tmp versionfunction")
            
            gav_method_result = self.methodSave(v, jar_abs_path)
            saveMethodResults[self.cveid].update(gav_method_result)

            with open(MethodSimSavePath, "w") as fw:
                json.dump(saveMethodResults, fw, indent = 4)
            
    @staticmethod
    def version_acquire(ga, v):
        v_lst = []
        if v == None:

            ga_folder = ga.replace(":", "-")
            a_name = ga.split(":")[-1]
            jar_ga_path = os.path.join(JAR_PATH, ga.replace(":", "-"))
            if os.path.exists(jar_ga_path) and os.path.isdir(jar_ga_path):

                file_names = os.listdir(jar_ga_path)
                for file_name in file_names:
                    v = file_name.replace(a_name + "-", "")
                    if v.startswith("CVE"):continue
                    v_lst.append(v)
        else:
 
            v_lst = [v]
        return v_lst
    
    @staticmethod
    def get_parent_commit(local_repo_path, commit_sha):
        repo = git.Repo(local_repo_path)
        commit = repo.commit(commit_sha)

        if commit.parents:
            parent_commit_sha = commit.parents[0].hexsha
            return parent_commit_sha
        else:
            print("Commit has no parent.")
            return None
        
    def repofileCp(self, local_repo, cveid, github_status):
        abs_file_path = os.path.join(local_repo, cveid, github_status+ "files")
        if os.path.exists(abs_file_path):
            all_items = os.listdir(abs_file_path)
            files = [item.split("/")[-1] for item in all_items if os.path.isfile(os.path.join(abs_file_path, item))]
            for file in files:
                os.system(f"cp -r {abs_file_path} {NiCad_PATH}/systems/tmp/GitHub/{github_status}_{file}")
        else:
            print("Path does not exist:", abs_file_path)
        
    @staticmethod
    def commitRollback(commitid, localRepoPath):
        os.chdir(localRepoPath)
        os.system(f"git checkout -f {commitid}")

    @staticmethod
    def nicadGitHubCacheClean():
        os.chdir(NiCad_PATH)

        os.system("rm -r ./systems/tmp/GitHub/*")
        os.system("rm -r ./systems/tmp_*")
        os.system("rm -r ./systems/tmp_*")
        os.system("rm -r ./systems/*.log")
        os.system("rm -r ./systems/*.xml")

    @staticmethod
    def nicadJarCacheClean():
        os.chdir(NiCad_PATH)

        os.system("rm -r ./systems/tmp/JAR/*")
        os.system("rm -r ./systems/tmp_*")
        os.system("rm -r ./systems/tmp_*")
        os.system("rm -r ./systems/*.log")
        os.system("rm -r ./systems/*.xml")

    def nicadMethodMatchDeprecated(self):
        os.chdir(NiCad_PATH)
        os.system("./nicad6 functions java systems/tmp versionfunction")
        
        try:

            with open(MethodSimSavePath, 'r') as fr:
   
                saveMethodResults = json.load(fr)

        except FileNotFoundError:

            saveMethodResults = {}
        saveMethodResults[self.cveid] = self.methodSave()

        with open(MethodSimSavePath, "w") as fw:
            json.dump(saveMethodResults, fw, indent = 4)
            
    def nicadHunkMatch(self):

        os.chdir(NiCad_PATH)
        self.nicadJarFileRemove()
        os.system("./nicad6 blocks java systems/tmp versionhunk")
        try:

            with open(HunkSimSavePath, 'r') as fr:

                saveHunkResults = json.load(fr)

        except FileNotFoundError:

            saveHunkResults = {}
        saveHunkResults[self.cveid] = self.hunkSave()

        with open(HunkSimSavePath, "w") as fw:
            json.dump(saveHunkResults, fw, indent = 4)       
        

    def methodSave(self, v, jar_abs_path):
        os.chdir(NiCad_PATH)
        methodMatchEachV = {
            v:{}
        }
        '''
        <clone nlines="33" similarity="28">
            <source file="systems/tmp/JAR/maven-shared-utils-0.6/org/apache/maven/shared/utils/io/FileUtils.java" startline="602" endline="633" pcid="7468"></source>
            <source file="systems/tmp/GitHub/old_Shell.java" startline="132" endline="181" pcid="12845"></source>
        </clone>
        '''
        with open(GitHubMethodPath, "r") as fr:
            GitHubMethodsMeta = json.load(fr)

        old_GitHub_Methods = [_.split("(")[0] for _ in self.old_methods]
        new_GitHub_Methods = [_.split("(")[0] for _ in self.new_methods]
        old_gitHub_Method_Line_Map = gitHubMethodLineMap(GitHubMethodsMeta, old_GitHub_Methods, self.cveid, "old")
        new_gitHub_Method_Line_Map = gitHubMethodLineMap(GitHubMethodsMeta, new_GitHub_Methods, self.cveid, "new")
        for githubMethod, linetuple in old_gitHub_Method_Line_Map.items():
            jarSimMethod = funcCloneDetection(
                "./systems/tmp_functions-blind-clones/tmp_functions-blind-clones-0.50.xml", 
                githubMethod.split("__split__")[0], linetuple[0], linetuple[1], "old", v)
            for v in jarSimMethod:
                if "old" not in methodMatchEachV[v]:
                    methodMatchEachV[v]["old"] = {}
                methodMatchEachV[v]["old"][githubMethod] = jarSimMethod[v]

        for githubMethod, linetuple in new_gitHub_Method_Line_Map.items():
            jarSimMethod = funcCloneDetection(
                "./systems/tmp_functions-blind-clones/tmp_functions-blind-clones-0.50.xml", 
                githubMethod.split("__split__")[0], linetuple[0], linetuple[1], "new", v)
            for v in jarSimMethod:
                if "new" not in methodMatchEachV[v]:
                    methodMatchEachV[v]["new"] = {}
                methodMatchEachV[v]["new"][githubMethod] = jarSimMethod[v]
        methodMatchEachV[v]["absPath"] = jar_abs_path
        return methodMatchEachV

    def nicadJarFileRemove(self):
        os.chdir(NiCad_PATH)
        allowedFiles = []
        with open(MethodSimSavePath, 'r') as fr:

            saveMethodResults = json.load(fr)
        for cveid, jarVersions in saveMethodResults.items():
            for version, Eachstatus in jarVersions.items():
                for githubStatus, fileMap in Eachstatus.items():
                    for githubFileName in fileMap:
                        allowedFiles.append(fileMap[githubFileName]["jarPath"])
        allowedFiles = list(set(allowedFiles))
        ic("allowedFiles: ")
        ic(allowedFiles)

        notallowedFiles = []
        for root, dirs, files in os.walk(NiCad_PATH+ "/systems/tmp/JAR"):
            for file_name in files:
                file_path = os.path.join(root, file_name).split("/nicad/NiCad-6.2/")[-1]
                if file_path not in allowedFiles:  
                    notallowedFiles.append(file_path)
                    
        for notallowedFile in notallowedFiles:
            os.remove(notallowedFile)
            
    def hunkSave(self):
        os.chdir(NiCad_PATH)
        hunkMatchEachV = {}
        
        with open(GitHubMethodPath, "r") as fr:
            GitHubMethodsMeta = json.load(fr)

        old_GitHub_Methods = [_.split("(")[0] for _ in self.old_methods]
        new_GitHub_Methods = [_.split("(")[0] for _ in self.new_methods]
        old_gitHub_Method_Line_Map = gitHubMethodLineMap(GitHubMethodsMeta, old_GitHub_Methods, self.cveid, "old")
        new_gitHub_Method_Line_Map = gitHubMethodLineMap(GitHubMethodsMeta, new_GitHub_Methods, self.cveid, "new")
        for githubMethod, linetuple in old_gitHub_Method_Line_Map.items():
            jarSimMethod = hunkCloneDetection(
                "./systems/tmp_blocks-blind-clones/tmp_blocks-blind-clones-0.50.xml", 
                githubMethod.split("__split__")[0], linetuple[0], linetuple[1], "old")
            for v in jarSimMethod:
                if v not in hunkMatchEachV:
                    hunkMatchEachV[v] = {}
                if "old" not in hunkMatchEachV[v]:
                    hunkMatchEachV[v]["old"] = {}
                hunkMatchEachV[v]["old"][githubMethod] = jarSimMethod[v]

        for githubMethod, linetuple in new_gitHub_Method_Line_Map.items():
            jarSimMethod = hunkCloneDetection(
                "./systems/tmp_blocks-blind-clones/tmp_blocks-blind-clones-0.50.xml", 
                githubMethod.split("__split__")[0], linetuple[0], linetuple[1], "new")
            for v in jarSimMethod:
                if v not in hunkMatchEachV:
                    hunkMatchEachV[v] = {}
                if "new" not in hunkMatchEachV[v]:
                    hunkMatchEachV[v]["new"] = {}
                hunkMatchEachV[v]["new"][githubMethod] = jarSimMethod[v]
        return hunkMatchEachV



if __name__ == '__main__':
    pass