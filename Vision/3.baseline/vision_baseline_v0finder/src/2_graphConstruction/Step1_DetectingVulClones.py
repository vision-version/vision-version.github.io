import os
import sys
import subprocess
import re
import tlsh # Please intall python-tlsh
from datetime import datetime

currentPath	= os.getcwd()
vulFuncPath = "../1_poolConstruction/CVEPool/vulFuncs/"
nvdVulPath  = "../1_poolConstruction/CVEPool/NVD_vulhashes"	
repoPath	= "../1_poolConstruction/SoftwarePool/repo_functions/"
funcPath 	= "../1_poolConstruction/SoftwarePool/raw_functions/"
cloneResPath = currentPath + "/clone_detection_res"


def main():
	fres 	= open(cloneResPath, 'w')
	vulDict = {}

	with open(nvdVulPath, 'r', encoding = "UTF-8") as fp:
		body = ''.join(fp.readlines()).strip()
		for each in body.split('\n'):
			vulHash = each.split('\t')[0]
			vulInfo = each.split('\t')[1]
			if vulHash not in vulDict.keys():
				vulDict[vulHash] = []
			vulDict[vulHash].append(vulInfo)


	total = len(os.listdir(repoPath))
	index1 = 0
	for oss in os.listdir(repoPath):
		ossHashes = []
		index1 += 1
		with open("./progress_detect.txt","a") as f:
			now_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
			f.write("["+now_time+"]"+" detect "+oss+" now. Progress:"+index1.__str__()+"/"+total.__str__()+"\n")
		for files in os.listdir(repoPath + oss):
			with open(repoPath + oss + '/' + files, 'r', encoding = "UTF-8") as fp:
				ver = files.split('fuzzy_')[1].split('.hidx')[0]
				body = ''.join(fp.readlines()).strip()

				for eachLine in body.split('\n')[1:]:
					functionHash = eachLine.split('\t')[0]
					functionPath = eachLine.split('\t')[1]

					if functionHash in vulDict:
						for vulDictInfo in vulDict[functionHash]:
							CVE 	= vulDictInfo.split('_')[0]
							vulInfo = vulDictInfo
							isModi 	= "E"
							
							printStr = CVE + '\t' + functionHash + '\t' + functionPath + '\t' + isModi + '\t' + vulInfo + '\t' + oss + '\t' + ver
							fres.write(printStr + '\n')

					else:
						for eachVulHash in vulDict:
							
							score = tlsh.diffxlen(functionHash, eachVulHash)

							if int(score) <= 30:
								delLines = []
								addLines = []
								rawFunc  = []
								for vulDictInfo in vulDict[eachVulHash]:
									try:
										with open(vulFuncPath + vulDictInfo.replace('OLD.vul', 'DELLINES.vul'), 'r', encoding = "UTF-8") as fdel:
											delBody = ''.join(fdel)
											for eachDel in delBody.split('\n'):
												if eachDel.strip() != '':
													delLines.append(eachDel[1:].lstrip())

										with open(vulFuncPath + vulDictInfo.replace('OLD.vul', 'INSLINES.vul'), 'r', encoding = "UTF-8") as fadd:
											addBody = ''.join(fadd)
											for eachAdd in addBody.split('\n'):
												if eachAdd.strip() != '':
													addLines.append(eachAdd[1:].lstrip())

										with open(funcPath + oss + '/' + functionHash, 'r', encoding = "UTF-8") as fr:
											rawBody = ''.join(fr)
											for eachRaw in rawBody.split('\n'):
												rawFunc.append(eachRaw.lstrip())
									except:
										print ("No file error..")
										continue

									delFlag = 0
									addFlag = 0

									for eachDel in delLines:
										if eachDel not in rawFunc:
											delFlag = 1

									for eachAdd in addLines:
										if eachAdd in rawFunc:
											addFlag = 1

									if delFlag == 0 and addFlag == 0:
										CVE 	= vulDictInfo.split('_')[0]
										vulInfo = '_'.join(vulDictInfo.split('_')[4:])
										isModi 	= "M"
										printStr = CVE + '\t' + functionHash + '\t' + functionPath + '\t' + isModi + '\t' + vulInfo + '\t' + oss + '\t' + ver
										fres.write(printStr + '\n')
	fres.close()


if __name__ == "__main__":
	main()