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

    def callSiteQuery(self, cpg_path: str, source_function_sign: str, target_function_sign: str, JoernDistributedPath: str = None):
        '''
        @params: cpg_path
        @params: source_function_sign (full name, including function path, func name and parameters)
        @params: target_function_sign (only include function name and parameters)
        @return: file name, line number

        '''
        source_function_sign = source_function_sign.replace(',', '__split__')
        target_function_sign = target_function_sign.replace(',', '__split__')

        target_function_sign = target_function_sign.split(":")[0].split(".")[-1] + ":" + target_function_sign.split(":")[-1]
        # target_function_sign
        command = f"./joern --script callsite.sc --params cpgFile={cpg_path},callerMethodFullName='{source_function_sign}',calleeMethodFullName='{target_function_sign}'"
        ic(command)
        try:

            if JoernDistributedPath == None:
                os.chdir(joern_path) 
            else:
                os.chdir(JoernDistributedPath) 
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


    def joernScript(self, script_path: str, params: str, JoernDistributedPath: str = None):
        '''
        @params: script_path:
        @params: params:
        '''
 
        if JoernDistributedPath == None:
            os.chdir(joern_path)
        else:
            os.chdir(JoernDistributedPath)

        try:
            # os.system(ic(f"./joern --script {script_path} --params {params}"))
            command = f"./joern --script {script_path} --params {params}"
            result = ic(subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True))
        except Exception as e:
            raise RuntimeError(e) 
        


if __name__ == '__main__':
    print(f"joern path: {joern_path}")
    print(f"cache path: {cache_path}")
    print(f"repo path: {repo_path}")
    print(f"cve path: {cve_path}")

    workspace1 = CPGWorkspace(CGpath=cve_path, joernpath=joern_path, cachepath=cache_path)
    # workspace2 = CPGWorkspace(CGpath=cve_path, joernpath=joern_path, cachepath=cache_path)
    # print(workspace1, workspace2)

    cpgPath = '2.methodology/joern-cli/cache/apache__split__maven-shared-utils_old_76605ac236ee5fb64062581209e8ee941efcea77.bin'
    sourceFunction = "org.apache.maven.shared.utils.cli.shell.Shell.getRawCommandLine:java.util.List(java.lang.String,java.lang.String[])"
    targetFunction = "getExecutable:java.lang.String()"
    
    callsite_list = workspace1.callSiteQuery(cpg_path=cpgPath, source_function_sign=sourceFunction, target_function_sign=targetFunction)
    print(json.dumps(callsite_list, indent=4))
    workspace1.__del__

