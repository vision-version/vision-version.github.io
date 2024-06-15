import os
import sys
import hashlib
import time
import argparse

def getHashValue(file_path):
    hashValues = {}
    with open(file_path, "r") as f:
        lines = f.readlines()
        for i, line in enumerate(lines):
            if i == 0:
                continue
            if line == '=====\n':
                break
            info = line.strip().split("\t")
            funcLen = info[0]
            for j, hashValue in enumerate(info):
                if j == 0:
                    continue
                else:
                    try:
                        hashValues[funcLen].append(hashValue)
                    except KeyError:
                        hashValues[funcLen] = [hashValue]
    return hashValues

def getFuncs2CVE(file_path):
    funcs2cve = {}
    with open(file_path, "r") as f:
        lines = f.readlines()
        flag = False
        for i, line in enumerate(lines):
            if line == '=====\n':
                flag = True
            if flag:
                info = line.strip().split("\t")
                hashValue = info[0]
                for j, cvePath in enumerate(info):
                    if j == 0:
                        continue
                    elif "./" not in cvePath:
                        continue
                    else:
                        cveid = cvePath.split("/")[-1].split("_")[0]
                        try:
                            funcs2cve[hashValue].append(cveid)
                        except KeyError:
                            funcs2cve[hashValue] = [cveid]
    return funcs2cve

def getFuncsInfo(file_path):
    funcsInfo = {}
    filePathInfo = {}
    with open(file_path, "r") as f:
        lines = f.readlines()
        flag = False
        for i, line in enumerate(lines):
            if "===" in line:
                flag = True
            if flag:
                info = line.strip().split("\t")
                hashValue = info[0]
                j = 1
                while j + 1 < len(info):
                    try:
                        funcsInfo[hashValue].append(info[j+1])
                        filePathInfo[hashValue].append(info[j])
                    except KeyError:
                        funcsInfo[hashValue] = [info[j+1]]
                        filePathInfo[hashValue] = [info[j]]
                    j += 2
    return funcsInfo,filePathInfo

def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('REPO',
                            help='''signature path''')
    arg_parser.add_argument('-a', '--abstract-level', required=True, type=int, nargs=1, choices=[0, 4],
                            help='''Abstract Level''')

    args = arg_parser.parse_args()
    intendedAbsLvl = 4
    if args.abstract_level:
        intendedAbsLvl = args.abstract_level[0]
    signatureDirectory = "signature_java"
    targetRepo = "hashmark_{0}_{1}.hidx".format(intendedAbsLvl, args.REPO)
    targetHash = getHashValue("targetRepo_java/" + targetRepo)
    funcsInfo,filePathInfo = getFuncsInfo("targetRepo_java/" + targetRepo)
    time0 = time.time()    
    walkList = os.walk(signatureDirectory)
    cveNums = 0
    matches = {}
    for path, dirs, files in walkList:
        for fileName in files:
            file_path = os.path.join(path, fileName)
            signatures = getHashValue(file_path)
            funcs2cve = getFuncs2CVE(file_path)
            for funcLens in signatures.keys():
                if funcLens not in targetHash.keys():
                    continue
                for targetHashValue in targetHash[funcLens]:
                    if targetHashValue in signatures[funcLens]:
                        cveNums += len(funcs2cve[targetHashValue])
                        for cveId in funcs2cve[targetHashValue]:
                            i = 0
                            while i < len(funcsInfo[targetHashValue]):
                                try:
                                    matches[cveId].append((funcsInfo[targetHashValue][i], filePathInfo[targetHashValue][i]))
                                except KeyError:
                                    matches[cveId] = [(funcsInfo[targetHashValue][i], filePathInfo[targetHashValue][i])]
                                i += 1
    for cveId in matches.keys():
        with open("./results_Java_tree.txt", "a") as f:
            f.write("Found {0} in {1} !\n".format(cveId, args.REPO))    
            for match in matches[cveId]:
                f.write("Match! Method {0} in file {1} is homologous with {2}\n".format(match[0], match[1], cveId))    
    with open("./results_Java_tree.txt", "a") as f:
        f.write("Total CVE numbers of {0} detected: {1}\n\n".format(args.REPO,str(cveNums)))
    
    time1 = time.time()
    print("Elapsed time:{0} to detect {1}".format(str(time1 - time0),args.REPO))

if __name__ == "__main__":
    main()
