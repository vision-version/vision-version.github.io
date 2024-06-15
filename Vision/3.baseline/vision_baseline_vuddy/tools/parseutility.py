import os
import sys
import subprocess
import re
import platform
from tree_sitter import Language, Parser, Node
from tree_sitter_languages import get_language, get_parser
import tree_sitter_cpp as tscpp
import tree_sitter_java as tsjava


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

TS_QUERY_PACKAGE = "(package_declaration (scoped_identifier) @package)(package_declaration (identifier) @package)"
TS_IMPORT = "(import_declaration (scoped_identifier) @import)"
TS_CLASS = "(class_declaration) @class"
TS_FIELD = "(field_declaration) @field"
TS_METHOD = "(method_declaration) @method (constructor_declaration) @method"
TS_METHODNAME = "(method_declaration 	(identifier)@id)(constructor_declaration 	(identifier)@id)"
TS_LVAR = "(local_variable_declaration 	(variable_declarator (identifier)@identifier))"
TS_FPARAM = "(method_declaration		(formal_parameters (formal_parameter (identifier)@id)))"
TS_FUNCCALL = "(method_invocation	(identifier)@name)"
TS_DTYPE = "(type_identifier)@ID"

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

def get_platform():
    global osName
    global bits

    pf = platform.platform()
    bits, _ = platform.architecture()
    if "Windows" in pf:
        osName = "win"
        bits = ""
    elif "Linux" in pf:
        osName = "linux"
        if "64" in bits:
            bits = "64"
        else:
            bits = "86"
    else:
        osName = "osx"
        bits = ""


def setEnvironment(caller):
    get_platform()
    global javaCallCommand
    if caller == "GUI":
        cwd = os.getcwd()
        if osName == "win":
            javaCallCommand = os.path.join(cwd, "FuncParser-opt.exe ")

        elif osName == "linux" or osName == "osx":
            javaCallCommand = "\"{0}\" -Xmx1024m -jar \"{1}\" ".format(config.javaBinary, os.path.join(cwd, "FuncParser-opt.jar"))

    else:
        if osName == "win":
            base_path = os.path.dirname(os.path.abspath(__file__))
            javaCallCommand = os.path.join(base_path, "FuncParser-opt.exe ")
        elif osName == "linux" or osName == "osx":
            base_path = os.path.dirname(os.path.abspath(__file__))
            javaCallCommand = "\"{0}\" -Xmx1024m -jar \"{1}\" ".format(config.javaBinary, os.path.join(base_path, "FuncParser-opt.jar"))


class function:
    parentFile = None  
    parentNumLoc = None
    name = None 
    lines = None
    funcId = None 
    parameterList = []
    variableList = []
    dataTypeList = []
    funcCalleeList = []
    funcBody = None

    def __init__(self, fileName):
        self.parentFile = fileName
        self.parameterList = []
        self.variableList = []
        self.dataTypeList = []
        self.funcCalleeList = []

    def removeListDup(self):
        self.parameterList = list(set(self.parameterList))
        self.variableList = list(set(self.variableList))
        self.dataTypeList = list(set(self.dataTypeList))
        self.funcCalleeList = list(set(self.funcCalleeList))


def loadSource(rootDirectory):
    maxFileSizeInBytes = None
    maxFileSizeInBytes = 2097152
    walkList = os.walk(rootDirectory)
    srcFileList = []
    for path, dirs, files in walkList:
        if "codeclone" in path:
            continue
        for fileName in files:
            ext = fileName.lower()
            if ext.endswith(".java"):
                absPathWithFileName = path.replace('\\', '/') + '/' + fileName
                if os.path.islink(absPathWithFileName):
                    continue
                if maxFileSizeInBytes is not None:
                    if os.path.getsize(absPathWithFileName) < maxFileSizeInBytes:
                        srcFileList.append(absPathWithFileName)
                else:
                    srcFileList.append(absPathWithFileName)
    return srcFileList


def loadVul(rootDirectory):
    maxFileSizeInBytes = None
    walkList = os.walk(rootDirectory)
    srcFileList = []
    for path, dirs, files in walkList:
        for fileName in files:
            if fileName.endswith('OLD.vul'):
                absPathWithFileName = path.replace('\\', '/') + '/' + fileName
                if maxFileSizeInBytes is not None:
                    if os.path.getsize(absPathWithFileName) < maxFileSizeInBytes:
                        srcFileList.append(absPathWithFileName)
                else:
                    srcFileList.append(absPathWithFileName)
    return srcFileList


def removeComment(string):
    c_regex = re.compile(
        r'(?P<comment>//.*?$|[{}]+)|(?P<multilinecomment>/\*.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"]*)',
        re.DOTALL | re.MULTILINE)
    return ''.join([c.group('noncomment') for c in c_regex.finditer(string) if c.group('noncomment')])


def normalize(string):
    return ''.join(string.replace('\n', '').replace('\r', '').replace('\t', '').replace('{', '').replace('}', '').split(
        ' ')).lower()


def abstract(instance, level):
    originalFunctionBody = instance.funcBody
    originalFunctionBody = removeComment(originalFunctionBody)
    if int(level) >= 0:
        abstractBody = originalFunctionBody

    if int(level) >= 1:
        parameterList = instance.parameterList
        for param in parameterList:
            if len(param) == 0:
                continue
            try:
                paramPattern = re.compile("(^|\W)" + param + "(\W)")
                abstractBody = paramPattern.sub("\g<1>FPARAM\g<2>", abstractBody)
            except:
                pass

    if int(level) >= 2:
        dataTypeList = instance.dataTypeList
        for dtype in dataTypeList:
            if len(dtype) == 0:
                continue
            try:
                dtypePattern = re.compile("(^|\W)" + dtype + "(\W)")
                abstractBody = dtypePattern.sub("\g<1>DTYPE\g<2>", abstractBody)
            except:
                pass

    if int(level) >= 3:
        variableList = instance.variableList
        for lvar in variableList:
            if len(lvar) == 0:
                continue
            try:
                lvarPattern = re.compile("(^|\W)" + lvar + "(\W)")
                abstractBody = lvarPattern.sub("\g<1>LVAR\g<2>", abstractBody)
            except:
                pass

    if int(level) >= 4:
        funcCalleeList = instance.funcCalleeList
        for fcall in funcCalleeList:
            if len(fcall) == 0:
                continue
            try:
                fcallPattern = re.compile("(^|\W)" + fcall + "(\W)")
                abstractBody = fcallPattern.sub("\g<1>FUNCCALL\g<2>", abstractBody)
            except:
                pass

    return (originalFunctionBody, abstractBody)


delimiter = "\r\0?\r?\0\r"


def parseFile_shallow(srcFileName, caller):
    global javaCallCommand
    global delimiter
    setEnvironment(caller)
    javaCallCommand += "\"" + srcFileName + "\" 0"
    f = open(srcFileName)
    code = f.readlines()
    f.close()
    parentNumLoc = len(code)
    code = "".join(code)
    functionInstanceList = []
    try:
        methodNames = ASTParser(code, language="java").query(TS_METHODNAME)
        methods = ASTParser(code, language="java").query(TS_METHOD)
        inMethod = []
        for i, method in enumerate(methods):
            if method[0].text.decode() in inMethod:
                continue
            for m in ASTParser(method[0].text.decode(), language="java").query(TS_METHOD):
                if method[0].text.decode()==m[0].text.decode():
                    continue
                inMethod.append(m[0].text.decode())
            functionInstance = function(srcFileName)
            functionInstance.parentNumLoc = parentNumLoc
            functionInstance.name = methodNames[i][0].text.decode()
            functionInstance.funcId = i + 1
            functionInstance.lines = (method[0].start_point[0] + 1, method[0].end_point[0] + 1)
            functionInstance.funcBody = method[0].text.decode()
            functionInstanceList.append(functionInstance)
    except subprocess.CalledProcessError as e:
        print("Parser Error:", e)
        astString = ""

    return functionInstanceList


def parseFile_deep(srcFileName, caller):
    global javaCallCommand
    global delimiter
    setEnvironment(caller)
    javaCallCommand += "\"" + srcFileName + "\" 1"
    f = open(srcFileName)
    code = f.readlines()
    f.close()
    parentNumLoc = len(code)
    code = "".join(code)
    functionInstanceList = []

    try:
        methodNames = ASTParser(code, language="java").query(TS_METHODNAME)
        methods = ASTParser(code, language="java").query(TS_METHOD)
        inMethod = []
        for i, method in enumerate(methods):
            if method[0].text.decode() in inMethod:
                continue
            for m in ASTParser(method[0].text.decode(), language="java").query(TS_METHOD):
                if method[0].text.decode()==m[0].text.decode():
                    continue
                inMethod.append(m[0].text.decode())
            functionInstance = function(srcFileName)
            functionInstance.parentNumLoc = parentNumLoc
            functionInstance.name = methodNames[i][0].text.decode()
            functionInstance.funcId = i + 1
            functionInstance.lines = (method[0].start_point[0] + 1, method[0].end_point[0] + 1)
            functionInstance.funcBody = method[0].text.decode()
            functionInstanceList.append(functionInstance)
            parameterList = []
            params = ASTParser(method[0].text.decode(), language="java").query(TS_FPARAM)
            for param in params:
                if param[0].text.decode() not in parameterList:
                    parameterList.append(param[0].text.decode())
            variableList = []
            variables = ASTParser(method[0].text.decode(), language="java").query(TS_LVAR)
            for variable in variables:
                if variable[0].text.decode() not in variableList:
                    variableList.append(variable[0].text.decode())
            dataTypeList = []
            dataTypes = ASTParser(method[0].text.decode(), language="java").query(TS_DTYPE)
            for dataType in dataTypes:
                if dataType[0].text.decode() not in dataTypeList:
                    dataTypeList.append(dataType[0].text.decode())
            funcCalleeList = []
            funcCallees = ASTParser(method[0].text.decode(), language="java").query(TS_FUNCCALL)
            for funcCallee in funcCallees:
                if funcCallee[0].text.decode() not in funcCalleeList:
                    funcCalleeList.append(funcCallee[0].text.decode())
            functionInstance.parameterList = parameterList
            functionInstance.variableList = variableList
            functionInstance.dataTypeList = dataTypeList
            functionInstance.funcCalleeList = funcCalleeList
            
            functionInstanceList.append(functionInstance)
    except subprocess.CalledProcessError as e:
        print("Parser Error:", e)

    return functionInstanceList
