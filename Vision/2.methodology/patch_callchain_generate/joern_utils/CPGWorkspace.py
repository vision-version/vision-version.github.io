import os
import re
import json
import git 
import subprocess
from icecream import ic


current_path = os.getcwd()
# joern_path = "2.methodology/joern-cli"
joern_path = os.path.join(current_path[:current_path.rfind("methodology") + len("methodology")], "joern-cli")
# cve_path = "2.methodology/patch_callchain_generate/CGs/"
cve_path = os.path.join(current_path[:current_path.rfind("methodology") + len("methodology")], "patch_callchain_generate/CGs/")
cache_path = os.path.join(joern_path, "cache")
repo_path = "GithubCache"
metainfo_path = "2.methodology/patch_callchain_generate/cves_metainfo.json"


class CPGWorkspace:
    _instance = None

    def __new__(cls, *args, **kwargs):
        '''
        Singleton
        '''
        if not cls._instance:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, CGpath: str = cve_path, joernpath: str = joern_path, cachepath: str = cache_path):
        '''
        @param: cve_meta_info includes: cve & local repo path
        @param: joern_path: path to joern-cli
        @param: CGpath: path to call graph folder
        @param: cachepath: path to cpg cache folder
        '''
        self.cvePath = CGpath
        self.joernPath = joernpath
        self.cachePath = cachepath
        self.cache_map = {}
        with open(metainfo_path, "r") as f:
            self.meta = json.load(f)

    def __del__(self):
        self.cache_map = {}
        CPGWorkspace._instance = None


    def FilenameParse(self, targetFilePath: str):
        '''
        '''
        file_name = targetFilePath[targetFilePath.rfind("/") + 1:]
        cve = file_name[:file_name.index("_")]
        label = file_name[file_name.index("_") + 1: file_name.index(".")]
        return file_name, cve, label
    
    def searchCache(self, filepath: str):
        if filepath in self.cache_map:
            return self.cache_map[filepath]
        else:
            return ""

    def generateCPG(self, cve: str, filepath: str, commit_hash: str, status: str = "", language: str = "javasrc",  overwrite: bool = False, modified_files: list = []):
        '''
        '''
        try:
            repo = git.Repo(filepath)

            if status == "old": commit_hash = repo.commit(commit_hash).parents[0]

            repo.git.reset('--hard', commit_hash)
        except:
            raise FileNotFoundError(f"Not a repo: {filepath}")
        
        save_path = os.path.join(self.cachePath, f'{cve}_{status}_{commit_hash}.bin')
        hash_key = f"{filepath}_{status}_{commit_hash}"
        
        for modified_file in modified_files:
            if not os.path.exists(modified_file):
                raise FileNotFoundError(f"not found file in {modified_file}")
            modified_file_name = modified_file.split("/")[-1]

            os.chdir(current_path)
            os.system(f"cp ./github_diff/{cve}/{status}files/{modified_file_name} {modified_file}")
        try:
            os.chdir(joern_path)
            if hash_key in self.cache_map:
                save_path = self.cache_map[hash_key]
            
            if os.path.exists(save_path):
                if overwrite:
                    subprocess.run(['rm', '-rf', save_path])

                    subprocess.run(['./joern-parse', '--language', language, os.path.abspath(filepath), '--output', save_path], cwd=joern_path)

                    # subprocess.run(['mv', os.path.join(self.joernPath, 'cpg.bin'), save_path], cwd=joern_path)
                    # cmd = f"./joern importCode={filepath}"
                    # result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
                    
                    self.cache_map[hash_key] = save_path
                    print("cpg saved at: ", save_path)
                    print("Load CPG finish. 1")
                    return save_path
                else:
                    print("cpg already saved at: ", save_path)
                    print("Load CPG finish. 2")
                    return save_path
            else:
                subprocess.run(['./joern-parse', '--language', language, os.path.abspath(filepath), '--output', save_path], cwd=joern_path)
                self.cache_map[hash_key] = save_path
                print("cpg saved at: ", save_path)
                print("Load CPG finish. 3")
                return save_path
            
        except Exception as e:
            raise


    def callSiteQuery(self, cpg_path: str, source_function_sign: str, target_function_sign: str):
        '''
        @params: cpg_path
        @params: source_function_sign (full name, including function path, func name and parameters)
        @params: target_function_sign (only include function name and parameters)
        @return: file name, line number
        '''
        source_function_sign = source_function_sign.replace(',', '__split__')
        target_function_sign = target_function_sign.replace(',', '__split__')

        target_function_sign = target_function_sign.split(":")[0].split(".")[-1] + ":" + target_function_sign.split(":")[-1]
        ic(target_function_sign)

        command = f"./joern --script callsite.sc --params cpgFile={cpg_path},callerMethodFullName='{source_function_sign}',calleeMethodFullName='{target_function_sign}'"
        ic(command)
        try:

            os.chdir(joern_path)
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            if result.returncode != 0:
                raise subprocess.CalledProcessError(result.returncode, command, result.stderr)
        
        except subprocess.CalledProcessError as e:
            print(f"1 Error executing command: {e.cmd}")
            print(f"1 Return code: {e.returncode}")
            print(f"1 Output:\n{e.output}")
            print(f"1 Error message:\n{e.stderr}")
            return []

        except:
            print("Error 2:", result.stderr)
        

        output = result.stdout
        print(f"joern return: {output}")
        callsite_list = []
        outputs = output.split(", List")
        for out in outputs:
            try:
                out = out.replace('(', '').replace(')', '').split(", Some")
                filename = out[0]
                linenumber = out[1]
                filename = filename.split("__split__")[-1]
                filename = filename[filename.find('/') + 1 : ]
                # linenumber = linenumber.find(')').replace('(', '').replace(')', '')
                print(f"file name: {filename}, line number: {linenumber}")
                callsite_list.append(f"{filename}__split__{linenumber}")
            except:
                print(f"{cpgPath} can't find callsite. ")
                raise RuntimeError("joern return error")
        return callsite_list


    def joernScript(self, script_path: str, params: str):
        '''
        '''
        os.chdir(joern_path)
        try:
            # os.system(ic(f"./joern --script {script_path} --params {params}"))
            command = f"./joern --script {script_path} --params {params}"
            ic(command)
            result = ic(subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True))
        except Exception as e:
            raise RuntimeError(e) 
        


if __name__ == '__main__':
    print(f"joern path: {joern_path}")
    print(f"cache path: {cache_path}")
    print(f"repo path: {repo_path}")
    print(f"cve path: {cve_path}")

    workspace1 = CPGWorkspace(CGpath=cve_path, joernpath=joern_path, cachepath=cache_path)

    cpgPath = '2.methodology/joern-cli/cache/apache__split__maven-shared-utils_old_76605ac236ee5fb64062581209e8ee941efcea77.bin'
    sourceFunction = "org.apache.maven.shared.utils.cli.shell.Shell.getRawCommandLine:java.util.List(java.lang.String,java.lang.String[])"
    targetFunction = "getExecutable:java.lang.String()"
    
    callsite_list = workspace1.callSiteQuery(cpg_path=cpgPath, source_function_sign=sourceFunction, target_function_sign=targetFunction)
    print(json.dumps(callsite_list, indent=4))
    workspace1.__del__

