'''

'''
import os, json
import subprocess
import logging
from concurrent.futures import ProcessPoolExecutor, as_completed
import time

from joern_utils.CPGWorkspace import CPGWorkspace
from jarMethod import methods_extract
from jarCall import calls_axonomy
from jarGraph import jarSlice
RUNPATH = os.getcwd()
cpgWorkspace = CPGWorkspace()

class JarPDGGenerate():
    def __init__(self, RUNPATH: str) -> None:
        self.mapPath = RUNPATH + "/jarJoernBin.json"
        self.runPATH = RUNPATH
        self.methodMatchPath = RUNPATH + "/../jar_statement_locate/MethodMatechResult.json"
        self.statementMatchPath = RUNPATH + "/../jar_statement_locate/lineMatechResult.json"
        # joern 1.1
        # self.joernPath = RUNPATH + "/../joern-cli"
        # joern 2.2
        self.joernPath = "tmp/joern/joern-cli"
        
        self.joernCachePath = RUNPATH + "/../joern-cli/jarcache"
        self.jargithubMapPath = RUNPATH + "../jar_statement_locate/lineMatechResult.json"
        self.JAR_PATH = os.path.join(RUNPATH, "../../4.jar/jarDecompile")

        self.maxWorkers = 16
    def jarParser(self):
        # input path
        joernPath = self.joernPath
        mapPath = self.mapPath        
        cachePath = self.joernCachePath
        

        try:
            with open(mapPath, "r") as fr:
                mappedJar = json.load(fr)
        except FileNotFoundError:

            with open(mapPath, 'w') as json_file:
                json.dump({}, json_file, indent = 4)
    

        jarPaths = {}

        folders = [d for d in os.listdir(self.JAR_PATH) if os.path.isdir(os.path.join(self.JAR_PATH, d))]
        for ga in folders:
            v_dic= self.version_acquire(ga)
            for v, absPath in v_dic.items():
                gaPath = absPath.split("/")[-2]
                if gaPath not in jarPaths:
                    jarPaths[gaPath] = []
                if absPath not in jarPaths[gaPath]:
                    jarPaths[gaPath].append(absPath)

        for gaPath, verisonPaths in jarPaths.items():
            if "amqp-spring-amqp" in gaPath: continue
            if gaPath not in mappedJar:
                mappedJar[gaPath] = {}
            for versionPath in verisonPaths:
                binName = str(hash(versionPath)) + ".bin"
                if versionPath in mappedJar[gaPath]: 
                    print(gaPath)
                    continue
                try:
                    os.chdir(joernPath)
                    save_path = os.path.join(cachePath, binName)
        
                    print(" ".join(['./joern-parse', '--language', "javasrc", versionPath, '--output', save_path]))
                    subprocess.run(['./joern-parse', '--language', "javasrc", versionPath, '--output', save_path], cwd=joernPath)
                    mappedJar[gaPath][versionPath] = binName
                    print("cpg saved at: ", save_path)
                except Exception as e:
                    raise


                with open(mapPath, "w") as fw:
                    json.dump(mappedJar, fw, indent = 4)

    def version_acquire(self, ga):
        v_lst = {}
        ga_folder = ga.replace(":", "-")
        a_name = ga.split(":")[-1]
        jar_ga_path = os.path.join(self.JAR_PATH, ga.replace(":", "-"))
        if os.path.exists(jar_ga_path) and os.path.isdir(jar_ga_path):

            file_names = os.listdir(jar_ga_path)
     
            for file_name in file_names:
                v = file_name.replace(a_name + "-", "")
                if v.startswith("CVE"):continue
                v_lst.update({v:os.path.join(jar_ga_path, file_name)})
        return v_lst

    def jarGraphGenerator(self):
        '''
        '''
        jargithubMapPath = self.jargithubMapPath = RUNPATH + "/../jar_statement_locate/lineMatchResult.json"
        jarJoernPath = "./jarJoernBin.json"
        cveJarPath = "1.empirical/cve_gav_all.json"
        metaMethodsPath = os.path.join(RUNPATH, "jar_file", "cves_methods.json")
        cveMeta40 = RUNPATH + "/../patch_callchain_generate/cves_methods_40.json"

        with open(jargithubMapPath, "r") as fr:
            jargithubMap = json.load(fr)
        with open(jarJoernPath, "r") as fr:
            jarJoernMap = json.load(fr)   
        with open(cveJarPath, "r") as fr:
            cveJarMap = json.load(fr)
        
        with open(metaMethodsPath, "r") as fr:
            cves_methods = json.load(fr)

        with open(cveMeta40, "r") as fr:
            cves_methods_40 = json.load(fr)

        with open("testcve.json", "r") as fr:
            failedcases = json.load(fr)
        failed_cves = []
        for key, cve_lst in failedcases.items():
            failed_cves += cve_lst
        
        jargraph_task_lsts = []

        for cve, jarVersionItems in jargithubMap.items():
            cves_methods[cve] = {}
            for jarV, jarMatchResult in jarVersionItems.items():

                cves_methods[cve][jarV] = {}
                gav_joernName = ""

                for jarGA, jarVItems in jarJoernMap.items():
                    if jarGA != cveJarMap[cve].replace(":", "-"): 
                        continue
                    for jarGAVPath, joernName in jarVItems.items():
                        if not jarGAVPath.endswith(f"-{jarV}"): 
                            continue
                        gav_joernName = joernName
                        gav_joernPath = os.path.join(self.joernCachePath, gav_joernName)
                        jargraph_task_lsts.append([cve, jarV, gav_joernPath, jarMatchResult["old"], jarMatchResult["new"], cpgWorkspace, cves_methods])
        freeJoern = []
        for i in range(1,17): 
            freeJoern.append(f"joern_distributed/joern-cli_{i}")
        with ProcessPoolExecutor(max_workers=self.maxWorkers) as executor:

            futures = []

            for i in range(min(self.maxWorkers, len(jargraph_task_lsts))):
                
                task = jargraph_task_lsts.pop(0)

                task.append(freeJoern.pop(0))

                future = executor.submit(JarPDGGenerate.generatePipeline, *task)
                futures.append(future)
                

            while jargraph_task_lsts or futures:

                for future in as_completed(futures):

                    releasedJoernPath = future.result()
        
                    freeJoern.append(releasedJoernPath)
   
                for future in as_completed(futures):
 
             
                    futures.remove(future)
    
                    if jargraph_task_lsts:
                        task = jargraph_task_lsts.pop(0)
                        task.append(freeJoern.pop(0))
                        new_future = executor.submit(JarPDGGenerate.generatePipeline, *task)
                        futures.append(new_future)

        with open(metaMethodsPath, 'w') as f:
            json.dump(cves_methods, f, indent=4)
    
    @staticmethod
    def generatePipeline(cve, jarV, gav_joernPath, jarMatchResult_old, jarMatchResult_new, cpgWorkspace, cves_methods, joernPath):
        print(f"{cve}: {jarV}: {joernPath}")

        #old
        old_methods = methods_extract(cve = cve, status = "old", joernBinPath = gav_joernPath, githubJarMapMethods = jarMatchResult_old, cpgWorkspace = cpgWorkspace, joernPath = joernPath)
        # new
        new_methods = methods_extract(cve = cve, status = "new", joernBinPath = gav_joernPath, githubJarMapMethods = jarMatchResult_new, cpgWorkspace = cpgWorkspace, joernPath = joernPath)
        cve_methods= {
            "old_methods_info": old_methods,
            "new_methods_info": new_methods
        }

        calls_axonomy(cve, jarV, cve_methods = cve_methods, RUNPATH = RUNPATH, joernBinPath = gav_joernPath, cpgWorkspace = cpgWorkspace, joernPath = joernPath)
        jarSlice(cve, jarV, cve_methods = cve_methods, RUNPATH = RUNPATH, joernBinPath = gav_joernPath, joernPath = joernPath)

        cves_methods[cve][jarV] = {
            "old_methods_info": old_methods,
            "new_methods_info": new_methods
        }
        return joernPath
if __name__ == "__main__":
    jarpDGGgenerate = JarPDGGenerate(RUNPATH)

    # jarpDGGgenerate.jarParser()
    

    jarpDGGgenerate.jarGraphGenerator()