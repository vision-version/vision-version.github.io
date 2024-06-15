import os
import subprocess
import json
import sys
from bs4 import BeautifulSoup
import urllib.request
import urllib.parse
import time
import random
import re
import tlsh
import pandas as pd
from tree_sitter import Language, Parser, Node
from tree_sitter_languages import get_language, get_parser
import tree_sitter_cpp as tscpp
import tree_sitter_java as tsjava


## CONFIGURE ##
TS_METHOD = "(method_declaration) @method (constructor_declaration) @method"
TS_METHODNAME = "(method_declaration 	(identifier)@id)(constructor_declaration 	(identifier)@id)"
TS_FPARAM = "(formal_parameters)@name"
homePath 	= os.getcwd()
diffPath	= homePath + "/CVEcommit/"
clonePath	= "./clones/"
progressPath = "./progress.txt"
vulFuncPath = homePath + "/vulFuncs/"

shouldMake = [diffPath, clonePath, vulFuncPath]
for eachRepo in shouldMake:
	if not os.path.isdir(eachRepo):
		os.mkdir(eachRepo)

vf = open(homePath + '/NVD_vulhashes', 'w')

URLS = {}
META = {}


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
			print(child.type)
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
				# print('Found >= expression:', node.text.decode('utf8'))
		
		for child in node.children:
			self.traverse_and_find_eq(child, op, ansNodes)

	def traverse_and_find_nt(self, node, ansNodes):
		if node.type == 'unary_expression':
			operator_node = node.child_by_field_name('operator')
			if operator_node and operator_node.text.decode() == "!":
				ansNodes.append(node)
				# print('Found >= expression:', node.text.decode('utf8'))
		
		for child in node.children:
			self.traverse_and_find_nt(child, ansNodes)



def compute_tlsh(string):
	hs = tlsh.forcehash(string)
	return hs

def removeComment(string):
	c_regex = re.compile(
		r'(?P<comment>//.*?$|[{}]+)|(?P<multilinecomment>/\*.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"]*)',
		re.DOTALL | re.MULTILINE)
	return ''.join([c.group('noncomment') for c in c_regex.finditer(string) if c.group('noncomment')])

def normalize(string):
	return ''.join(string.replace('\n', '').replace('\r', '').replace('\t', '').replace('{', '').replace('}', '').split(
		' ')).lower()

def get_old_new_map(delete_lines,add_lines):
    old_new_map = {}
    new_old_map = {}
    delete = 1
    add = 1
    for i in range(1, 10000):
        while delete in delete_lines:
            delete += 1
        while add in add_lines:
            add += 1
        old_new_map[delete] = add
        new_old_map[add] = delete
        delete += 1
        add += 1
    return old_new_map, new_old_map


def main():
	for diffs in os.listdir(diffPath):
		if diffs != "CVE-2020-5408.txt":
			continue
		time0 = time.time()
		os.chdir(homePath)
		with open(os.path.join(diffPath, diffs), 'r', encoding = "UTF-8", errors="replace") as fd:
			body			= ''.join(fd.readlines())
			splitedBody = body.split('\n')

			pack 	= body.split('\n')[0].split('PACK:')[1].split("/")[-1].strip()
			if pack =='':
				print (diffs + '\t' + ": this vul. cannot be parsed automatically..")
				continue

			os.chdir(clonePath + pack)
			os.system(f"git config --global --add safe.directory {clonePath + pack}")
			files = []
			file_seperator = []
			lines = splitedBody
			for i in range(len(lines)):
				if lines[i].startswith("diff --git"):
					file_seperator.append(i)
			for i in range(len(file_seperator) - 1):
				files.append(lines[file_seperator[i] : file_seperator[i + 1] - 1])
			files.append(lines[file_seperator[len(file_seperator) - 1] : len(lines)])
			for file in files:
				extension = ["java"]
				info = {}
				info["oldFileName"] = file[0].split(" ")[2]
				info["newFileName"] = file[0].split(" ")[3]
				if (
					info["oldFileName"].split(".")[-1] not in extension
					or info["newFileName"].split(".")[-1] not in extension
				):
					continue
				test = "test"
				infos = info["oldFileName"].lower().split("/")
				infos_new = info["newFileName"].lower().split("/")
				flag_old = True 
				flag_new = True  
				if (
					test.lower() in infos
					or test.lower() in infos_new
					or test.lower() in infos[-1]
					or test.lower() in infos_new[-1]
				):
					continue
				if file[1].startswith("old mode"):
					oldIdx = file[3].split(" ")[1].split("..")[0].replace("\n", "")
					newIdx = file[3].split(" ")[1].split("..")[1].replace("\n", "")
				elif file[1].startswith("new file mode"):
					oldIdx = file[2].split(" ")[1].split("..")[0].replace("\n", "")
					newIdx = file[2].split(" ")[1].split("..")[1].replace("\n", "")
					flag_old = False
				elif file[1].startswith("similarity index"):
					continue
				elif file[1].startswith("deleted file mode"):
					oldIdx = file[2].split(" ")[1].split("..")[0].replace("\n", "")
					newIdx = file[2].split(" ")[1].split("..")[1].replace("\n", "")
					flag_new = False
				else:
					oldIdx = file[1].split(" ")[1].split("..")[0]
					newIdx = file[1].split(" ")[1].split("..")[1]

				old_name = oldIdx + "-" + info["oldFileName"].split("/")[-1]
				new_name = newIdx + "-" + info["newFileName"].split("/")[-1]
				oldIdx += " -- " + info["oldFileName"].split("/")[-1]
				newIdx += " -- " + info["newFileName"].split("/")[-1]
				print(info)
				info["add"] = []
				info["delete"] = []
				vulfile = homePath + "/vulfile.java"
				patchfile = homePath + "/patchfile.java"
				if "000000" in oldIdx:
					continue
				command = "git show " + oldIdx + " > " + vulfile
				command1 = "git show " + newIdx + " > " + patchfile
				res = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
				res = subprocess.check_output(command1, stderr=subprocess.STDOUT, shell=True)
				commitsFile = homePath + "/commit.txt"
				os.system("git diff -w " + vulfile + " " + patchfile + "> " + commitsFile)
				add_line = 0
				delete_line = 0
				commits = open(commitsFile, "r")
				lines = commits.readlines()

				for line in lines:
					if line.startswith("@@"):
						delete_line = int(line.split("-")[1].split(",")[0]) - 1
						add_line = int(line.split("+")[1].split(",")[0]) - 1
					elif line.startswith("+") and not line.startswith("+++"):
						add_line += 1
						info["add"].append(add_line)
					elif line.startswith("-") and not line.startswith("---"):
						delete_line += 1
						info["delete"].append(delete_line)
					else:
						add_line += 1
						delete_line += 1


				delLines = {}
				insLines = {}
				with open(patchfile, 'r') as fp:
					body = ''.join(fp.readlines())
					methods = ASTParser(body,language="java").query(TS_METHOD)
					methodNames = ASTParser(body, language="java").query(TS_METHODNAME)
					fps = ASTParser(body, language="java").query(TS_FPARAM) 
					for i, method in enumerate(methods):
						funcname = methodNames[i][0].text.decode()
						fp = fps[i][0].text.decode()
						startline = method[0].start_point[0] + 1
						endline = method[0].end_point[0] + 1
						for line in info["add"]:
							if line >= startline and line <= endline:
								if funcname + fp not in insLines.keys():
									insLines[funcname + fp] = []
								insLines[funcname + fp].append(body.split('\n')[line-1])
				with open(vulfile, 'r') as fp:
					body = ''.join(fp.readlines())
					methods = ASTParser(body,language="java").query(TS_METHOD)
					methodNames = ASTParser(body, language="java").query(TS_METHODNAME)
					fps = ASTParser(body, language="java").query(TS_FPARAM)
					for i, method in enumerate(methods):
						funcname = methodNames[i][0].text.decode()
						startline = method[0].start_point[0] + 1
						endline = method[0].end_point[0] + 1
						fp = fps[i][0].text.decode()
						for line in info["delete"]:
							if line >= startline and line <= endline:
								if funcname + fp not in delLines.keys():
									delLines[funcname + fp] = []
								delLines[funcname + fp].append(body.split('\n')[line-1])

						for line in info["delete"]:
							if line >= startline and line <= endline:
								funcbody = ''.join(''.join('\n'.join(body.split('\n')[startline-1: endline]).split('{')[1:]).split('}')[:-1])
								funcbody = removeComment(funcbody)
								funcbody = normalize(funcbody)
								fuzzyhash = compute_tlsh(funcbody.encode())

								funcPath = diffs.split('.txt')[0] + '_' + pack + '_' + info["oldFileName"].split('/')[-1] + '@@' + funcname + '_' + fuzzyhash[2:] + '_OLD.vul'
								delPath  = diffs.split('.txt')[0] + '_' + pack + '_' + info["oldFileName"].split('/')[-1] + '@@' + funcname + '_' + fuzzyhash[2:] + '_DELLINES.vul'
								insPath  = diffs.split('.txt')[0] + '_' + pack + '_' + info["oldFileName"].split('/')[-1] + '@@' + funcname + '_' + fuzzyhash[2:] + '_INSLINES.vul'

								f = open(vulFuncPath + funcPath, 'w')
								f.write(funcbody)
								f.close()

								fdel = open(vulFuncPath + delPath, 'w')
								for dels in delLines[funcname + fp]:
									fdel.write(dels + '\n')
								fdel.close()

								fins = open(vulFuncPath + insPath, 'w')
								if funcname + fp in insLines.keys():
									for ins in insLines[funcname + fp]:
										fins.write(ins + '\n')
								fins.close()

								if len(fuzzyhash) == 72 and fuzzyhash.startswith("T1"):
									fuzzyhash = fuzzyhash[2:]
								elif fuzzyhash == "TNULL" or fuzzyhash == "" or fuzzyhash == "NULL":
									continue

								vf.write(fuzzyhash + '\t' + funcPath + '\n')
				for mfs in insLines.keys():
					if mfs in delLines.keys():
						continue
					old_new_map, new_old_map = get_old_new_map(info["delete"], info["add"])
					modified = []
					with open(patchfile, 'r') as fp2:
						body = ''.join(fp2.readlines())
						methods = ASTParser(body,language="java").query(TS_METHOD)
						methodNames = ASTParser(body, language="java").query(TS_METHODNAME)
						fps = ASTParser(body, language="java").query(TS_FPARAM)
						for i, method in enumerate(methods):
							funcname = methodNames[i][0].text.decode()
							startline = method[0].start_point[0] + 1
							endline = method[0].end_point[0] + 1
							fp = fps[i][0].text.decode()
							if mfs == funcname + fp:
								flag = False
								for l in range(startline, endline+1):
									if l in new_old_map.keys():
										flag = True
										modified.append(new_old_map[l])
								if not flag:
									continue
								with open(vulfile, 'r') as fp1:
									body = ''.join(fp1.readlines())
									methods_vul = ASTParser(body,language="java").query(TS_METHOD)
									methodNames_vul = ASTParser(body, language="java").query(TS_METHODNAME)
									fps_vul = ASTParser(body, language="java").query(TS_FPARAM)
									for j, method in enumerate(methods_vul):
										funcname = methodNames_vul[j][0].text.decode()
										startline = method[0].start_point[0] + 1
										endline = method[0].end_point[0] + 1
										fp = fps_vul[j][0].text.decode()
										find = False
										for l in modified:
											if not (l >= startline and l <= endline):
												continue
											else:
												find = True
												break
										if not find:
											continue
										funcbody = ''.join(''.join('\n'.join(body.split('\n')[startline-1: endline]).split('{')[1:]).split('}')[:-1])


										funcbody = removeComment(funcbody)
										funcbody = normalize(funcbody)
										fuzzyhash = compute_tlsh(funcbody.encode())

										funcPath = diffs.split('.txt')[0] + '_' + pack + '_' + info["oldFileName"].split('/')[-1] + '@@' + funcname + '_' + fuzzyhash[2:] + '_OLD.vul'
										delPath  = diffs.split('.txt')[0] + '_' + pack + '_' + info["oldFileName"].split('/')[-1] + '@@' + funcname + '_' + fuzzyhash[2:] + '_DELLINES.vul'
										insPath  = diffs.split('.txt')[0] + '_' + pack + '_' + info["oldFileName"].split('/')[-1] + '@@' + funcname + '_' + fuzzyhash[2:] + '_INSLINES.vul'
										# print(funcPath)

										f = open(vulFuncPath + funcPath, 'w')
										f.write(funcbody)
										f.close()
										
										if startline not in info["delete"]:
											fdel = open(vulFuncPath + delPath, 'w')
											if funcname + fp in delLines.keys():
												for dels in delLines[funcname + fp]:
													fdel.write(dels + '\n')
											fdel.close()

										fins = open(vulFuncPath + insPath, 'w')
										for ins in insLines[mfs]:
											fins.write(ins + '\n')
										fins.close()
										
										if len(fuzzyhash) == 72 and fuzzyhash.startswith("T1"):
											fuzzyhash = fuzzyhash[2:]
										elif fuzzyhash == "TNULL" or fuzzyhash == "" or fuzzyhash == "NULL":
											continue

										vf.write(fuzzyhash + '\t' + funcPath + '\n')	
		progress = open(progressPath,"a")
		progress.write(f"Elapsed time to grnerate signature of {diffs.split('.txt')[0]}:{time.time()-time0}\n")
	vf.close()


	

""" EXECUTE """
if __name__ == "__main__":
	main()
