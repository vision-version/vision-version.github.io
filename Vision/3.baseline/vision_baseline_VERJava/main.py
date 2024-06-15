import argparse
import json
import logging
import os
import time

import definitions
from commit import Commit
from git import Repo
from meta import Method, Package
from tqdm import tqdm


class PatchFunc:
    def __init__(self, signature: str, path: str,
                 a_start_line, a_end_line, b_start_line, b_end_line):
        self.signature = signature
        self.file = path
        self.a_start_line = a_start_line
        self.a_end_line = a_end_line
        self.b_start_line = b_start_line
        self.b_end_line = b_end_line
        self.addline = set()
        self.delline = set()


class TargetFunc:
    def __init__(self, signature: str, source_code: str, start_line: int, end_line: int):
        self.signature = signature
        self.line = set()
        self.safe = True

        source_code_lines = source_code.split("\n")
        for line in source_code_lines:
            if not isValidCodeLine(line):
                continue
            self.line.add(line.strip().replace(" ", ""))


def isValidCodeLine(code: str) -> bool:
    code = code.strip()
    if (code == "" or code.startswith("//") or
            code.startswith("/*") or code.startswith("*/") or code == "{" or code == "}" or code == ";"
            or code == "(" or code == ")" or code == "[" or code == "]" or code == "/*" or code == "*/"):
        return False
    return True


def patch_parser(repo_path: str, commit_id: str) -> list[PatchFunc]:
    patch = Commit(repo_path, commit_id)
    patchFunctions: list[PatchFunc] = []
    for blob in patch.blobs:
        if blob.change_type != "C" or "test/" in blob.a_path:
            continue
        a_package = Package(blob.a_blob_content)
        b_package = Package(blob.b_blob_content)
        a_methods: set[Method] = set()
        b_methods: set[Method] = set()
        for clazz in a_package.classes:
            for method in clazz.methods:
                a_methods.add(method)
        for clazz in b_package.classes:
            for method in clazz.methods:
                b_methods.add(method)

        matchPatchFunctions: list[PatchFunc] = []
        for am in a_methods:
            for bm in b_methods:
                if am.signature == bm.signature:
                    matchPatchFunctions.append(PatchFunc(am.signature, blob.b_path,
                                                         am.start_line, am.end_line, bm.start_line, bm.end_line))
                    break

        for hunk in blob.hunks:
            for line, code in hunk.added_lines.items():
                if not isValidCodeLine(code):
                    continue
                for matchfunc in matchPatchFunctions:
                    if matchfunc.b_start_line <= line <= matchfunc.b_end_line:
                        matchfunc.addline.add(code.strip().replace(" ", ""))
            for line, code in hunk.deleted_lines.items():
                if not isValidCodeLine(code):
                    continue
                for matchfunc in matchPatchFunctions:
                    if matchfunc.a_start_line <= line <= matchfunc.a_end_line:
                        matchfunc.delline.add(code.strip().replace(" ", ""))

        for matchfunc in matchPatchFunctions:
            if len(matchfunc.addline) != 0 or len(matchfunc.delline) != 0:
                patchFunctions.append(matchfunc)

    return patchFunctions


def vulFuncCal(patchFunction: PatchFunc, targetFunction: TargetFunc) -> bool:
    targetFuncLineSet = targetFunction.line
    delLineSet_n = len(patchFunction.delline)
    addLineSet_n = len(patchFunction.addline)
    delSim = 0
    addSim = 0
    if delLineSet_n != 0:
        delSim = len(patchFunction.delline & targetFuncLineSet) / delLineSet_n
    if addLineSet_n != 0:
        addSim = len(patchFunction.addline & targetFuncLineSet) / addLineSet_n
    if delLineSet_n != 0 and addLineSet_n != 0:
        if delSim >= definitions.tDel and addSim <= definitions.tAdd:
            targetFunction.safe = False
    elif addLineSet_n == 0:
        if delSim >= definitions.tDel:
            targetFunction.safe = False
    elif delLineSet_n == 0:
        if addSim <= definitions.tAdd:
            targetFunction.safe = False
    else:
        targetFunction.safe = True
    return targetFunction.safe


def vulVerCal(repo_path: str, patchFunctions: list[PatchFunc]) -> tuple[list[str], list[str]]:
    repo = Repo(repo_path)
    vultag = []
    novultag = []
    for tag in repo.tags:
        targetFunctions: list[TargetFunc] = []
        try:
            targe_commit = repo.commit(tag)
        except:
            continue

        for func in patchFunctions:
            try:
                target_blob = targe_commit.tree[func.file]
            except:
                continue
            target_package = Package(target_blob.data_stream.read().decode())
            for clazz in target_package.classes:
                for method in clazz.methods:
                    if method.signature == func.signature:
                        targetFunctions.append(TargetFunc(
                            method.signature, method.body_source_code, method.start_line, method.end_line))

        totalNum = len(patchFunctions)
        for patchfunc in patchFunctions:
            targetFunc = next((tf for tf in targetFunctions if tf.signature ==
                              patchfunc.signature), None)
            if targetFunc is None:
                totalNum -= 1
                continue
            vulFuncCal(patchfunc, targetFunc)

        if totalNum == 0:
            novultag.append(tag.name)
            continue

        vulNum = sum(1 for func in targetFunctions if not func.safe)
        if ((totalNum > 3 and vulNum / totalNum >= definitions.T)
                or (totalNum <= 3 and vulNum / totalNum == 1.0)):
            vultag.append(tag.name)
        else:
            novultag.append(tag.name)
    return vultag, novultag


def vulVerCalJar(jar_path: str, patchFunctions: list[PatchFunc]) -> list[str]:
    vultag = []
    for ver in os.listdir(jar_path):
        targetFunctions: list[TargetFunc] = []
        ver_path = os.path.join(jar_path, ver)
        if not os.path.isdir(ver_path):
            continue

        for patchfunc in patchFunctions:
            index = patchfunc.file.find("src/main/java/")
            if index == -1:
                continue
            real_path = patchfunc.file[index + len("src/main/java/"):]
            real_path = os.path.join(ver_path, real_path)
            if not os.path.exists(real_path):
                continue
            with open(real_path) as f:
                source_code = f.read()
            target_package = Package(source_code)
            for clazz in target_package.classes:
                for method in clazz.methods:
                    if method.signature == patchfunc.signature:
                        targetFunctions.append(TargetFunc(
                            method.signature, method.body_source_code, method.start_line, method.end_line))

        totalNum = len(patchFunctions)
        for patchfunc in patchFunctions:
            targetFunc = next((tf for tf in targetFunctions if tf.signature ==
                              patchfunc.signature), None)
            if targetFunc is None:
                totalNum -= 1
                continue
            vulFuncCal(patchfunc, targetFunc)

        if totalNum == 0:
            continue

        vulNum = sum(1 for func in targetFunctions if not func.safe)
        if ((totalNum > 3 and vulNum / totalNum >= definitions.T)
                or (totalNum <= 3 and vulNum / totalNum == 1.0)):
            vultag.append(ver[ver.rfind("-") + 1:])
        else:
            pass
    return vultag


def cli():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--repo", dest="repo", help="path to the repo", type=str,
                        required=True)
    parser.add_argument("-c", "--commit", dest="commit", help="commit to patch", type=str,
                        default="", required=True)
    parser.add_argument("-m", "--mode", dest="mode", help="mode", type=str,
                        default="", required=True)
    parser.add_argument("-j", "--jar", dest="jar", help="jar", type=str,
                        default="", required=False)
    parser.add_argument("-l", "--log", dest="logpath", help="log file path", type=str,
                        default="log.log")
    parser.add_argument("--loglevel", dest="loglevel", help="log level", type=int,
                        default=logging.ERROR)
    args = parser.parse_args()
    repo_path = args.repo
    commit_id = args.commit
    mode = args.mode
    jar_path = args.jar
    patch_func: list[PatchFunc] = patch_parser(repo_path, commit_id)
    if mode == "code":
        vultag = vulVerCal(repo_path, patch_func)[0]
        print(vultag)
    elif mode == "jar":
        vultag = vulVerCalJar(jar_path, patch_func)
        print(vultag)


if __name__ == '__main__':
    cli()
