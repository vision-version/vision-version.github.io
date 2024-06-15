import os, json, sys

def methodReInit(GitHubSubGraph: dict, cve: str, status:str, missingStatus: str):

    missingFiles = []
    with open("../jar_statement_locate/initMatchResult.json", "r") as fr:
        initMatchResult = json.load(fr)
    with open("../patch_callchain_generate/cves_methods.json", "r") as fr:
        cves_methods = json.load(fr)
    modifiedFiles = cves_methods[cve][f"{status}_methods_info"]
    fakeFullNameKey = "addMethod" if status == "new" else "deleteMethod"
    for modifiedFile in modifiedFiles:
        missingFile = {}

        missingFile[f"{status}FilePath"] = modifiedFile[f"{status}FilePath"]
        missingFile[f"{fakeFullNameKey}Begin"] = modifiedFile[f"{fakeFullNameKey}Begin"]
        missingFile[f"{fakeFullNameKey}End"] = modifiedFile[f"{fakeFullNameKey}End"]
        missingFile[f"{fakeFullNameKey}Full"] = {}

        for modifiedMethodFake, modifiedMethodContent in modifiedFile[f"{fakeFullNameKey}Full"].items():
            missingContent = {
                "lineNumber": [],
                "originalFullName":modifiedMethodContent["originalFullName"],
                "paramType": modifiedMethodContent["paramType"]
            }

            for node in GitHubSubGraph["nodes"]:
                nodePath, nodeFullName, nodeMethodBeginLine, nodeMethodEndLine, nodeModifiedLine = node.split("__split__")
                if nodeFullName == modifiedMethodContent["originalFullName"]:

                    missingContent["lineNumber"].append({nodeModifiedLine: get_line_content(nodePath, int(nodeModifiedLine))})
            missingFile[f"{fakeFullNameKey}Full"][modifiedMethodFake] = missingContent
        missingFiles.append(missingFile)
    return missingFiles
def get_line_content(file_path, line_number):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()
            if 0 < line_number <= len(lines):
                return lines[line_number - 1].strip()
            else:
                return "Line number out of range."
    except FileNotFoundError:
        return "File not found."
    except Exception as e:
        return f"An error occurred: {str(e)}"