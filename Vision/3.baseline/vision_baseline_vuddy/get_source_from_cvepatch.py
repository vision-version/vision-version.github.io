#!/usr/bin/env python

import os
import sys
import re
import glob
import argparse
import multiprocessing as mp
from functools import partial
import platform
import time


sys.path.append(os.path.dirname(os.path.abspath(__file__)))
try: 
    import hmark.parseutility as parseutility
except ImportError:
    import tools.parseutility as parseutility

import config


originalDir = os.path.dirname(os.path.abspath(__file__))
diffDir = os.path.join(originalDir, "diff_java")

dummyFunction = parseutility.function(None)
multimodeFlag = 0
debugMode = False

parseutility.setEnvironment("")

t1 = time.time()

""" re patterns """
pat_src = '[\n](?=diff --git a/)'
pat_chunk = r'[\n](?=@@\s[^a-zA-Z]*\s[^a-zA-Z]*\s@@)'
pat_linenum = r"-(\d+,\d+) \+(\d+,\d+) "
pat_linenum = re.compile(pat_linenum)


def init():
    global CVEID
    global multimodeFlag
    global total
    global debugMode
    global repoName
    global gitStoragePath

    
    parser = argparse.ArgumentParser()
    parser.add_argument('CVEID',
                        help='''CVE-ID''')
    parser.add_argument('REPO',
                        help='''REPO''')
    parser.add_argument('-m', '--multimode', action="store_true",
                        help='''Turn on Multimode''')
    parser.add_argument('-d', '--debug', action="store_true", help=argparse.SUPPRESS)  # Hidden Debug Mode

    args = parser.parse_args()

    if args.CVEID is None:
        parser.print_help()
        exit()
    CVEID = args.CVEID
    repoName = args.REPO
    gitStoragePath = os.path.join(config.gitStoragePath, repoName)

    if args.multimode:
        multimodeFlag = 1
    if args.debug:
        debugMode = True

    msg = "Retrieve vulnerable functions from {0}\nMulti-repo mode: ".format(CVEID)
    if multimodeFlag:
        print(msg + "On")
    else:
        print(msg + "Off")

    try:
        os.makedirs(os.path.join(originalDir, 'tmp'))
    except OSError as e:
        pass
    try:
        os.makedirs(os.path.join(originalDir, 'vul_java', CVEID))
    except OSError as e:
        pass

    total = len(os.listdir(os.path.join(diffDir, CVEID)))


def source_from_cvepatch(ctr, diffFileName):
    global CVEID
    global debugMode
    global total
    global multimodeFlag
    global dummyFunction
    global diffDir
    global originalDir
    global repoName
    global gitStoragePath

    chunksCnt = 0  
    currentCounter = 0

    with ctr.diffFileCntLock:
        currentCounter = ctr.diffFileCnt.value
        print(str(ctr.diffFileCnt.value + 1) + '/' + str(total))
        ctr.diffFileCnt.value += 1

    if os.path.getsize(os.path.join(diffDir, CVEID, diffFileName)) > 1000000:
        print("[-]", diffFileName, "\t(file too large)")
    else:
        diffFileNameSplitted = diffFileName.split('_')
        cveId = diffFileNameSplitted[0] 
        commitHashValue = diffFileNameSplitted[-1].split('.')[0]

        print("[+]", diffFileName, "\t(proceed)")
        with open(os.path.join(diffDir, CVEID, diffFileName), 'r') as fp:
            patchLines = ''.join(fp.readlines())
            patchLinesSplitted = re.split(pat_src, patchLines)
            commitLog = patchLinesSplitted[0]
            affectedFilesList = patchLinesSplitted[1:]

        numAffectedFiles = len(affectedFilesList)
        for aidx, affectedFile in enumerate(affectedFilesList):
            if debugMode:
                print("\tFile # " + str(aidx + 1) + '/' + str(numAffectedFiles))
            firstLine = affectedFile.split('\n')[0] 
            affectedFileName = firstLine.split("--git ")[1].split(" ")[0].split("/")[-1]
            codePath = firstLine.split(' b')[1].strip() 

            if not codePath.endswith(".java"):
                if debugMode:
                    print("\t[-]", codePath, "(wrong extension)")
            else:
                secondLine = affectedFile.split('\n')[1]

                if secondLine.startswith("index") == 0:
                    if debugMode:
                        print("\t[-]", codePath, "(invalid metadata)")
                else:
                    if debugMode:
                        print("\t[+]", codePath)
                    indexHashOld = secondLine.split(' ')[1].split('..')[0]
                    indexHashNew = secondLine.split(' ')[1].split('..')[1]

                    chunksList = re.split(pat_chunk, affectedFile)[1:]
                    chunksCnt += len(chunksList)

                    if multimodeFlag:
                        os.chdir(os.path.join(gitStoragePath, repoName))
                    else:
                        os.chdir(gitStoragePath)                    

                    tmpOldFileName = os.path.join(originalDir, "tmp", "{0}_{1}_old".format(CVEID, currentCounter))
                    command_show = "\"{0}\" show {1} > {2}".format(config.gitBinary, indexHashOld, tmpOldFileName)
                    os.system(command_show)

                    tmpNewFileName = os.path.join(originalDir, "tmp", "{0}_{1}_new".format(CVEID, currentCounter))
                    command_show = "\"{0}\" show {1} > {2}".format(config.gitBinary, indexHashNew, tmpNewFileName)
                    os.system(command_show)

                    os.chdir(originalDir)
                    oldFunctionInstanceList = parseutility.parseFile_shallow(tmpOldFileName, "")
                    newFunctionInstanceList = parseutility.parseFile_shallow(tmpNewFileName, "")

                    finalOldFunctionList = []

                    numChunks = len(chunksList)
                    for ci, chunk in enumerate(chunksList):
                        if debugMode:
                            print("\t\tChunk # " + str(ci + 1) + "/" + str(numChunks))

                        chunkSplitted = chunk.split('\n')
                        chunkFirstLine = chunkSplitted[0]
                        chunkLines = chunkSplitted[1:]

                        if debugMode:
                            print(chunkLines)
                        lineNums = pat_linenum.search(chunkFirstLine)
                        oldLines = lineNums.group(1).split(',')
                        newLines = lineNums.group(2).split(',')
                        if debugMode:
                            print(oldLines, newLines)
                        offset = int(oldLines[0])
                        pmList = []
                        lnList = []
                        for chunkLine in chunkSplitted[1:]:
                            if len(chunkLine) != 0:
                                pmList.append(chunkLine[0])
                        for i, pm in enumerate(pmList):
                            if pm == ' ' or pm == '-':
                                lnList.append(offset + i)
                            elif pm == '+':
                                lnList.append(offset + i - 1)
                                offset -= 1

                        hitOldFunctionList = []
                        for f in oldFunctionInstanceList:

                            for num in range(f.lines[0], f.lines[1] + 1):
                                if num in lnList:
                                    print("Hit at", num, lnList)

                                    hitOldFunctionList.append(f)
                                    break

                        for f in hitOldFunctionList:
                            for num in range(f.lines[0], f.lines[1] + 1):
                                try:
                                    listIndex = lnList.index(num)
                                except ValueError:
                                    pass
                                else:
                                    if lnList.count(num) > 1:
                                        listIndex += 1
                                    if pmList[listIndex] == '+' or pmList[listIndex] == '-':
                                        flag = 0
                                        for commentKeyword in ["/*", "*/", "//", "*"]:
                                            if chunkLines[listIndex][1:].lstrip().startswith(commentKeyword):
                                                flag = 1
                                                break
                                        if flag:
                                            pass
                                        else:
                                            finalOldFunctionList.append(f)
                                            break
                                    else:
                                        pass

                    finalOldFunctionList = list(set(finalOldFunctionList))

                    finalNewFunctionList = []
                    for fold in finalOldFunctionList:
                        flag = 0
                        for fnew in newFunctionInstanceList:
                            if fold.name == fnew.name:
                                finalNewFunctionList.append(fnew)
                                flag = 1
                                break
                        if not flag:
                            finalNewFunctionList.append(dummyFunction)

                    if debugMode:
                        print("\t\t\t", len(finalNewFunctionList), "functions found.")
                    vulFileNameBase = diffFileName.split('.diff')[0] + '_' + affectedFileName


                    for index, f in enumerate(finalOldFunctionList):
                        os.chdir(originalDir)
                        oldFuncInstance = finalOldFunctionList[index]

                        fp = open(oldFuncInstance.parentFile, 'r')
                        srcFileRaw = fp.readlines()
                        fp.close()
                        finalOldFunction = ''.join(srcFileRaw[oldFuncInstance.lines[0]-1:oldFuncInstance.lines[1]])

                        finalOldFuncId = str(oldFuncInstance.funcId)

                        newFuncInstance = finalNewFunctionList[index]

                        if newFuncInstance.name is None:
                            finalNewFunction = ""
                        else:
                            fp = open(newFuncInstance.parentFile, 'r')
                            srcFileRaw = fp.readlines()
                            fp.close()
                            finalNewFunction = ''.join(srcFileRaw[newFuncInstance.lines[0]-1:newFuncInstance.lines[1]])

                        finalOldBody = finalOldFunction[finalOldFunction.find('{')+1:finalOldFunction.rfind('}')]
                        finalNewBody = finalNewFunction[finalNewFunction.find('{')+1:finalNewFunction.rfind('}')]
                        tmpold = parseutility.normalize(parseutility.removeComment(finalOldBody))
                        tmpnew = parseutility.normalize(parseutility.removeComment(finalNewBody))

                        if tmpold != tmpnew and len(tmpnew) > 0:
                            with ctr.functionCntLock:
                                ctr.functionCnt.value += 1
                            os.chdir(os.path.join(originalDir, "vul_java", CVEID))
                            vulOldFileName = vulFileNameBase + '_' + finalOldFuncId + "_OLD.vul"
                            vulNewFileName = vulFileNameBase + '_' + finalOldFuncId + "_NEW.vul"
                            with open(vulOldFileName, 'w') as fp:
                                fp.write(finalOldFunction)
                            with open(vulNewFileName, 'w') as fp:
                                if finalNewFunctionList[index].name is not None:
                                    fp.write(finalNewFunction)
                                else:
                                    fp.write("")
                            diffCommand = "\"{0}\" -u {1} {2} > {3}_{4}.patch".format(config.diffBinary,
                                                                                       vulOldFileName,
                                                                                       vulNewFileName,
                                                                                       vulFileNameBase,
                                                                                       finalOldFuncId)
                            os.system(diffCommand)


def main():
    
    ctr = Counter()
    diffList = os.listdir(os.path.join(diffDir, CVEID))
    if debugMode or "Windows" in platform.platform():
        for diffFile in diffList:
            source_from_cvepatch(ctr, diffFile)
    else:
        pool = mp.Pool()
        parallel_partial = partial(source_from_cvepatch, ctr)
        pool.map(parallel_partial, diffList)
        pool.close()
        pool.join()

    wildcard_temp = os.path.join(originalDir, "tmp", CVEID + "_*")

    print("")
    print("Done getting vulnerable functions from", CVEID)
    print("Reconstructed", ctr.functionCnt.value, "vulnerable functions from", ctr.diffFileCnt.value, "patches.")
    print("Elapsed: %.2f sec" % (time.time()-t1))


if __name__ == "__main__":
    mp.freeze_support()
    class Counter:
        diffFileCnt = mp.Value('i', 0)
        diffFileCntLock = mp.Manager().Lock()
        functionCnt = mp.Value('i', 0)
        functionCntLock = mp.Manager().Lock()
    init()
    main()
