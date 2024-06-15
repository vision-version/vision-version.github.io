import os
import sys
import json
from CommitFilesParser import sourtarCompare, sourtarContextMap, sourtarDiffMap
from icecream import ic

DIFF_FILE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.getcwd())), "patch_callchain_generate/github_diff")
FILEMAP_PATH = os.path.join(os.path.dirname(os.getcwd()), "fileMaps")
# print("Diff file path: ", DIFF_FILE_PATH)
# print("File map path: ", FILEMAP_PATH)

def prePatchFilesExtract():
    '''
    @args:
    '''

    for root, dirs, files in os.walk(DIFF_FILE_PATH):
        cve = root.split('/')[-2]
        fileMap = {}
        for file in files:
            try:
                file_name = file.split('/')[-1]
                modifiedLines = sourtarCompare(cve=cve, fileName=file_name)
        
                oldFileMap, newFileMap = sourtarContextMap(cve, file_name, modifiedLines)
  
                delLinesGroup, addLinesGroup = sourtarDiffMap(oldFileMap, newFileMap, modifiedLines)
                fileMap[file_name.split("/")[-1]] = {
                    "oldFileLineMap": oldFileMap,
                    "newFileLineMap": newFileMap,
                    "delLinesGroup": delLinesGroup,
                    "addLinesGroup": addLinesGroup
                }
            except Exception as e:
                ic(cve, file_name, "Error: ", e)
        with open(os.path.join(FILEMAP_PATH, f"{cve}_fileMap.json"), "w") as f:
            json.dump(fileMap, f, indent=4)
    
    print("Pre-patch files analysis done!")


if __name__ == "__main__":
    prePatchFilesExtract()
    