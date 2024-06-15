#!/usr/bin/env python

import os
import sys
import hashlib

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
try:
    from hmark.parseutility import normalize
except ImportError:
    from tools.parseutility import normalize

hashdict = {}
cntdict = {}
vulcntlist = []
repolist = []

originalDir = os.path.dirname(os.path.abspath(__file__))
vulsDir = os.path.join(originalDir, "vul")
dirs = os.listdir(vulsDir)
dirs.sort()
os.chdir(vulsDir)
for d in dirs:
    if os.path.isdir(d):
        repolist.append(d)
        cntdict[d] = 0
        vulcntlist.append(len(os.listdir(d)))
        for vul in os.listdir(d):
            if vul.endswith("OLD.vul"):
                with open(os.path.join(d, vul), "r", encoding="utf-8", errors="replace") as fp:
                    text = '\n'.join(fp.readlines())
                    text = normalize(text)
                    checksum = hashlib.md5(text.encode('utf-8')).hexdigest()
                    try:
                        hashdict[checksum].append(d + ' ' + vul)
                    except:
                        hashdict[checksum] = [d + ' ' + vul]

cnt = 0

for key in hashdict:
    if len(hashdict[key]) > 1:
        for vul in hashdict[key][1:]:
            cnt += 1
            repo = vul.split(' ')[0]
            rest = vul.split(' ')[1]
            base = rest[:-8]
            cntdict[repo] += 1
            os.remove(os.path.join(repo, rest))
            try:
                os.remove(os.path.join(repo, base + "_NEW.vul"))
                os.remove(os.path.join(repo, base + ".patch"))
            except:
                pass

print("[RESULT]")
for idx, r in enumerate(repolist):
    print('\t' + r + ":\tdeleted " + str(cntdict[r]) + " duplicate files from " + str(vulcntlist[idx]) + " files.")

print("Total:", cnt, "duplicate files.")
