import re
import regex
import string
import requests
import json
import jpype
import os
import atexit


def _jvm_start():
    print("get class path: ", jpype.getClassPath())
    if jpype.isJVMStarted():
        # jpype.shutdownJVM()
        print("Java")
    else:
        jpype.startJVM(jpype.getDefaultJVMPath())
        print("Java")

def _jvm_close():

    jpype.shutdownJVM()
    print("java")


def text2sourceevidence(text,base_path):
    os.chdir(os.path.join(base_path, "DescNodeReg"))
    text = text.replace(", ", " ").replace(") ", " ").replace(" (", " ")
    '''

    '''

    _jvm_start()

    RegularMethodName = jpype.JClass("RegularMethodName")

    regex_method = RegularMethodName()

    method_names = list(set([str(each) for each in list(regex_method.findMatches(text))]))


    RegularClaName = jpype.JClass("RegularClaName")
  
    regex_class = RegularClaName()
    

    class_names = set([str(each) for each in list(regex_class.findMatches(text))])
 
    class_black_set = set(["GitHub", "JavaScript", "ActiveMQ", "NiFi", "OrientDB", "DoS", "MySQL", "JetBrains", "GitLab", "GitBox", "PoC", "IoT"])
    class_names = list(class_names - class_black_set)
    # print(class_names)

  
    RegularPathName = jpype.JClass("RegularPathName")
    
    regex_path = RegularPathName()

    path_black_set = set(["e.g."])
    path_names = set([str(each) for each in list(regex_path.findMatches(text))])
    path_names = list(path_names - path_black_set)
    
  
    # Find all matches of the pattern in the description

    slash_path_matches = set(re.findall(r"[\w]*/[\w]+(?:/[\w-]+)*/[\w]*\.*[\w]*", text))
    dot_path_matches = set(re.findall(r"[A-Za-z]+\.[\w]+(?:\.[\w-]+)*\.[\w]*\.*[A-Za-z1-9]*", text))
    print(dot_path_matches)
    path_matches = list(slash_path_matches.union(dot_path_matches))

    # filename_dic = {"java": [], "python": [], "go": [], "javascript": []}
    filename_list = []
    java_extensions = ['\.java', '\.class', '.jar', '\.war', '\.ear', '\.jsp']
    python_extensions = ['\.py', '\.pyc', '\.pyd', '\.pyo', '\.pyw', '\.pyx', "\.whl"]
    go_extensions = ['\.go']
    javascript_extensions = ['\.js', '\.mjs', '\.cjs']
    # index_mpa = {0: "java", 1: "python", 2: "go", 3: "javascript"}
    languages_extensions = [java_extensions, python_extensions, go_extensions, javascript_extensions]

    for index, language_extensions in enumerate(languages_extensions):
        for extension in language_extensions:
            pattern = rf"\b[\w\.\-]+{extension}\b"
 
            matches = re.findall(pattern, text, re.IGNORECASE)
            # filename_dic[index_mpa[index]] += matches
            filename_list.extend(matches)
    
    # _jvm_close()
    return {"method_names": method_names, "classnamelst": class_names, "pathlst": path_matches, "langrelatedfiles": filename_list}


if __name__ == '__main__':
    text = """
    [MSHARED-297] - BourneShell unconditionally single quotes executable …
    …and arguments
    """
    print(text2sourceevidence(text))
