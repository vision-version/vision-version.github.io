#!/usr/bin/env python

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
try:
    import hmark.parseutility as pu
except ImportError:
    import tools.parseutility as pu


def getBody(original):
    return original[original.find('{')+1:original.rfind('}')]

originalDir = os.path.dirname(os.path.abspath(__file__))
vulsDir = os.path.join(originalDir, "vul")
dirs = os.listdir(vulsDir)
rmcntDict = {}
for dir in dirs:
    for vul in os.listdir(os.path.join(vulsDir, dir)):
        if vul.endswith("OLD.vul"):
            with open(os.path.join(vulsDir, dir, vul), "r", encoding="utf-8", errors="replace") as fp:
                raw = ''.join(fp.readlines())
                body = getBody(pu.removeComment(raw))
            
            if body.count(";") == 1:
                kill = 1
            else:
                kill = 0

            cnt = 0
            for line in body.split('\n'):
                if len(line.strip()) > 0:
                    cnt += 1

            with open(os.path.join(vulsDir, dir, vul[:-8] + "_NEW.vul"), 'r', encoding="utf-8", errors="replace") as fp:
                newraw = ''.join(fp.readlines())
                newbody = getBody(pu.removeComment(newraw))

            if kill == 1 or cnt == 1 or pu.normalize(body) == pu.normalize(newbody) or len(newraw) == 0:
                vulBase = vul[:-8]
                os.remove(os.path.join(vulsDir, dir, vulBase + "_OLD.vul"))
                os.remove(os.path.join(vulsDir, dir, vulBase + "_NEW.vul"))
                os.remove(os.path.join(vulsDir, dir, vulBase + ".patch"))
                try:
                    rmcntDict[dir] += 1
                except:
                    rmcntDict[dir] = 1

for dir in rmcntDict:
    print("removed", rmcntDict[dir], "FP records from", dir)
