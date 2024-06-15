#!/usr/bin/env python

import os
import sys
import hashlib
import time
import argparse
import multiprocessing as mp
from functools import partial
import get_cpu_count

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
try:
    import hmark.parseutility as parser
except ImportError:
    import tools.parseutility as parser
import config


def parse_function(absLvl, srcFile):
    if absLvl == 0:
        functionInstanceList = parser.parseFile_shallow(srcFile, "")
        return srcFile, functionInstanceList
    elif absLvl == 4:
        functionInstanceList = parser.parseFile_deep(srcFile, "")
        return srcFile, functionInstanceList


def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('REPO',
                            help='''Repository path''')
    arg_parser.add_argument('-a', '--abstract-level', required=True, type=int, nargs=1, choices=[0, 4],
                            help='''Abstract Level''')

    args = arg_parser.parse_args()

    projName = os.path.join(config.projName, args.REPO)
    proj = projName.replace('\\', '/').split('/')[-1]
    intendedAbsLvl = 4
    if args.abstract_level:
        intendedAbsLvl = args.abstract_level[0]

    projDictList = []
    hashFileMapList = []
    for i in range(0, 5):
        projDictList.append({})
        hashFileMapList.append({})

    print("loading source")
    srcFileList = parser.loadSource(projName)
    print("(done)")

    numFiles = len(srcFileList)
    if numFiles == 0:
        print("Error: Failed loading source files.\n - Check if you selected proper directory, or if your project " \
              "contains .c or .cpp files.\n")
    else:
        print("Load complete. Generating hashmark...")
    numFuncs = 0
    numLines = 0

    time0 = time.time()
    cpu_count = get_cpu_count.get_cpu_count()
    if cpu_count != 1:
        cpu_count -= 1

    pool = mp.Pool(processes=16)
    func = partial(parse_function, intendedAbsLvl)
    for srcFileIdx, returnTuple in enumerate(pool.imap(func, srcFileList)):
        srcFile = returnTuple[0]
        pathOnly = srcFile.split(proj, 1)[1][1:]
        functionInstanceList = returnTuple[1]

        numFuncs += len(functionInstanceList)
        if len(functionInstanceList) > 0:
            numLines += functionInstanceList[0].parentNumLoc

        for fi, f in enumerate(functionInstanceList):
            f.removeListDup()
            path = f.parentFile

            absBody = parser.abstract(f, intendedAbsLvl)[1]
            absBody = parser.normalize(absBody)
            funcLen = len(absBody)

            if funcLen > 50:
                hashValue = hashlib.md5(absBody.encode('utf-8')).hexdigest()

                try:
                    projDictList[intendedAbsLvl][funcLen].append(hashValue)
                except KeyError:
                    projDictList[intendedAbsLvl][funcLen] = [hashValue]
                try:
                    hashFileMapList[intendedAbsLvl][hashValue].extend([pathOnly, f.name])
                except KeyError:
                    hashFileMapList[intendedAbsLvl][hashValue] = [pathOnly, f.name]
            else:
                numFuncs -= 1  # decrement numFunc by 1 if funclen is under threshold

    pool.close()
    pool.join()

    try:
        os.mkdir("targetRepo_java")
    except:
        pass
    packageInfo = str(config.version) + ' ' + str(proj) + ' ' + str(numFiles) + ' ' + str(numFuncs) + ' ' + str(
        numLines) + '\n'
    with open("targetRepo_java/hashmark_" + str(intendedAbsLvl) + "_" + proj + ".hidx", 'w') as fp:
        fp.write(packageInfo)

        for key in sorted(projDictList[intendedAbsLvl]):
            fp.write(str(key) + '\t')
            for h in list(set(projDictList[intendedAbsLvl][key])):
                fp.write(h + '\t')
            fp.write('\n')

        fp.write('\n=====\n')

        for key in sorted(hashFileMapList[intendedAbsLvl]):
            fp.write(str(key) + '\t')
            for f in hashFileMapList[intendedAbsLvl][key]:
                fp.write(str(f) + '\t')
            fp.write('\n')

    print("Hash index saved to:", os.getcwd().replace("\\", "/") + "/targetRepo_java/hashmark_" + str(
        intendedAbsLvl) + "_" + proj + ".hidx")
    time1 = time.time()
    print("Elapsed time:", time1 - time0)


if __name__ == "__main__":
    mp.freeze_support()
    main()
