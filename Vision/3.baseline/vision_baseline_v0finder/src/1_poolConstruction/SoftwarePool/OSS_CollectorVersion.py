
"""
Dataset Collection Tool.
Author:		Seunghoon Woo (seunghoonwoo@korea.ac.kr)
Modified: 	August 1, 2021.
"""

import os
import sys
import subprocess
import re
import shutil
import tlsh # Please intall python-tlsh
from tree_sitter import Language, Parser, Node
from tree_sitter_languages import get_language, get_parser
import tree_sitter_cpp as tscpp
import tree_sitter_java as tsjava
from datetime import datetime


TS_METHOD = "(method_declaration) @method (constructor_declaration) @method"
TS_METHODNAME = "(method_declaration 	(identifier)@id)(constructor_declaration 	(identifier)@id)"
class ASTParser:
	def __init__(self, code: str | bytes, language: str):
		if language == "cpp":
			self.LANGUAGE = Language(tscpp.language())
		elif language == "java":
			self.LANGUAGE = Language(tsjava.language())
		self.parser = Parser(self.LANGUAGE)
		if isinstance(code, str):
			self.root = self.parser.parse(bytes(code, "utf-8")).root_node
		else:
			self.root = self.parser.parse(code).root_node

	@staticmethod
	def children_by_type_name(node: Node, type: str) -> list[Node]:
		node_list = []
		for child in node.named_children:
			if child.type == type:
				node_list.append(child)
		return node_list

	@staticmethod
	def child_by_type_name(node: Node, type: str) -> Node | None:
		for child in node.named_children:
			if child.type == type:
				return child
		return None

	def query_oneshot(self, query_str: str) -> Node | None:
		query = self.LANGUAGE.query(query_str)
		captures = query.captures(self.root)
		result = None
		for capture in captures:
			result = capture[0]
			break
		return result

	def query(self, query_str: str):
		try:
			query = self.LANGUAGE.query(query_str)
			captures = query.captures(self.root)
		except Exception as e:
			return []
		return captures

	def traverse_and_find_eq(self, node, op, ansNodes):
		if node.type == 'binary_expression':
			operator_node = node.child_by_field_name('operator')
			if operator_node and operator_node.text.decode() == op:
				ansNodes.append(node)
		
		for child in node.children:
			self.traverse_and_find_eq(child, op, ansNodes)

	def traverse_and_find_nt(self, node, ansNodes):
		if node.type == 'unary_expression':
			operator_node = node.child_by_field_name('operator')
			if operator_node and operator_node.text.decode() == "!":
				ansNodes.append(node)
		
		for child in node.children:
			self.traverse_and_find_nt(child, ansNodes)


currentPath	= os.getcwd()
clonePath 	= "/path/to/jar/decompile/"
resultPath	= currentPath + "/repo_functions/"
funcPath 	= currentPath + "/raw_functions/"

shouldMake = [resultPath, funcPath]
for eachRepo in shouldMake:
	if not os.path.isdir(eachRepo):
		os.mkdir(eachRepo)

def computeTlsh(string):
	string 	= str.encode(string)
	hs 		= tlsh.forcehash(string)
	return hs


def removeComment(string):
	c_regex = re.compile(
		r'(?P<comment>//.*?$|[{}]+)|(?P<multilinecomment>/\*.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"]*)',
		re.DOTALL | re.MULTILINE)
	return ''.join([c.group('noncomment') for c in c_regex.finditer(string) if c.group('noncomment')])

def normalize(string):
	return ''.join(string.replace('\n', '').replace('\r', '').replace('\t', '').replace('{', '').replace('}', '').split(' ')).lower()

def hashing(repoPath, repoName):
	possible = (".java")

	fileCnt  = 0
	funcCnt  = 0
	lineCnt  = 0

	resDict  = {}



	for path, dir, files in os.walk(repoPath):
		for file in files:
			filePath = os.path.join(path, file)
			if file.endswith(possible):
				try:
					f = open(filePath, 'r', encoding = "UTF-8")
					lines 		= f.readlines()
					f.close()
					body = ''.join(lines)
					methods = ASTParser(body, language="java").query(TS_METHOD)
					for i, method in enumerate(methods):
						funcSearch	= re.compile(r'{([\S\s]*)}')
						tmpString	= ""
						funcBody	= ""

						fileCnt 	+= 1
						funcBody 	= ""
						funcStartLine 	 = method[0].start_point[0] + 1
						funcEndLine 	 = method[0].end_point[0] + 1

						tmpString	= ""
						tmpString	= tmpString.join(lines[funcStartLine - 1 : funcEndLine])

						if funcSearch.search(tmpString):
							funcBody = funcBody + funcSearch.search(tmpString).group(1)
						else:
							funcBody = " "


						nocoFuncBody = removeComment(funcBody)
						normalizedFuncBody = normalize(nocoFuncBody)
						funcHash = computeTlsh(normalizedFuncBody)


						if len(funcHash) == 72 and funcHash.startswith("T1"):
							funcHash = funcHash[2:]
						elif funcHash == "TNULL" or funcHash == "" or funcHash == "NULL":
							continue

						storedPath = filePath.replace(repoPath, "")
						if funcHash not in resDict:
							resDict[funcHash] = []
						resDict[funcHash].append(storedPath)

						lineCnt += len(lines)
						funcCnt += 1

				except subprocess.CalledProcessError as e:
					print("Parser Error:", e)
					continue
				except Exception as e:
					print ("Subprocess failed", e)
					continue

	return resDict, fileCnt, funcCnt, lineCnt 

def indexing(resDict, title, filePath):
	fres = open(filePath, 'w')
	fres.write(title + '\n')

	for hashval in resDict:
		if hashval == '' or hashval == ' ':
			continue

		fres.write(hashval)
		
		for funcPath in resDict[hashval]:
			fres.write('\t' + funcPath)
		fres.write('\n')

	fres.close()


def main():
	total = 0
	for ga in os.listdir(clonePath):
		for av in os.listdir(os.path.join(clonePath, ga)):
			total += 1
	index1 = 0
	for ga in os.listdir(clonePath):
		for av in os.listdir(os.path.join(clonePath, ga)):
			try:
				repoName = ga + ":" + av
				index1 += 1
				with open("./progress_file.txt","a") as f:
					now_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
					f.write("["+now_time+"]"+" generate "+repoName+" now. Progress:"+index1.__str__()+"/"+total.__str__()+"\n")
				if not os.path.isdir(funcPath + repoName):
					os.mkdir(funcPath + repoName)					
				resDict, fileCnt, funcCnt, lineCnt = hashing(os.path.join(clonePath, ga, av), repoName)
				if len(resDict) > 0:
					if not os.path.isdir(resultPath + repoName):
						os.mkdir(resultPath + repoName)	
					title = '\t'.join([repoName, str(fileCnt), str(funcCnt), str(lineCnt)])
					resultFilePath 	= resultPath + repoName + '/fuzzy_' + repoName + '.hidx'
					indexing(resDict, title, resultFilePath)
			except Exception as e:
				print ("Subprocess failed", e)
				continue


if __name__ == "__main__":
	main()