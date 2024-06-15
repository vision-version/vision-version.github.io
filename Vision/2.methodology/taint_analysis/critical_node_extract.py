import json
import os
import sys
import re
from icecream import ic
# from ..jar_statement_locate.JarProject import JarProject
sys.path.append("2.methodology/jar_statement_locate/")
from JarProject import JarProject


parent_directory = os.path.dirname(os.getcwd())
print("parent directory:", parent_directory)
PATCH_CALLCHAIN_GENERATE_PATH = os.path.join(parent_directory, "patch_callchain_generate")
CVE_METHOD_PATH = os.path.join(parent_directory, "patch_callchain_generate/cves_methods.json")
JOERN_PATH = os.path.join(parent_directory, "joern-cli")
GIT_DIFF_PATH = os.path.join(parent_directory, "patch_callchain_generate/github_diff")
# print("cve method path:", CVE_METHOD_PATH)
# print("joern path:", JOERN_PATH)
# print("git diff path:", GIT_DIFF_PATH)


def is_function_call(string):
    '''
    @param: string
    @return: bool
    '''
    function_patterns = {
        'java': {
            'definition': r'^\s*(public\s+|private\s+)?\s*(static\s+)?\s*\w+\s+\w+\s*\([^)]*\)\s*{',
            'call': r'\b\w+\s*\([^)]*\)\s*;'
        },
        'python': {
            'definition': r'^\s*def\s+\w+\s*\([^)]*\)\s*:',
            'call': r'\b\w+\s*\([^)]*\)\s*'
        },
        'javascript': {
            'definition': r'^\s*function\s+\w+\s*\([^)]*\)\s*{',
            'call': r'\b\w+\s*\([^)]*\)\s*;'
        },
        'go': {
            'definition': r'^\s*func\s+\w+\s*\([^)]*\)\s*{',
            'call': r'\b\w+\s*\([^)]*\)\s*'
        }
    }

    for language, patterns in function_patterns.items():
        if re.match(patterns['call'], string) or re.match(patterns['definition'], string):
            return True

    return False

def source_sink_detection(cve_id: str, lines: list, cve_methods: dict, status: str):
    source_keywords = ['def', 'function', 'private', 'public', 'static', 'func', 'if', 'else', 'elif', 'while', 'for', 'switch']
    sink_keywords = ['throw', 'except', 'return', 'assert', 'try', 'catch', 'if', 'else', 'elif', 'while', 'for', 'switch']
    sink_list = {}
    source_list = {}
    undefined_list = {}
    
    try:
        for method_info in cve_methods:
            filename = method_info[f'{status}FilePath']
            source_list[filename] = {}
            sink_list[filename] = {}
            undefined_list[filename] = {}

            try: 
                n = len(lines)
                for line_no in range(n): 
                    line_content = lines[line_no].strip()
                    pro_line_content = line_content.lower()

                    tokens = re.findall(r'\b\w+\b', pro_line_content)
                    
                    source_intersect = set(tokens) & set(source_keywords)
                    sink_intersect = set(tokens) & set(sink_keywords)

                    if source_intersect and not sink_intersect:
                        if status == 'old':
                            for method, begin in method_info['deleteMethodBegin'].items():
                                if line_no + 1 in range(begin, method_info['deleteMethodEnd'][method]):
                                    source_list[filename][line_no + 1] = line_content
                                    break
                        else:
                            for method, begin in method_info['addMethodBegin'].items():
                                if line_no + 1 in range(begin, method_info['addMethodEnd'][method]):
                                    source_list[filename][line_no + 1] = line_content
                                    break
                        # print(f"source added: {line_content}")
                    elif sink_intersect and not source_intersect:
                        sink_list[filename][line_no + 1] = line_content
                        # print(f"sink added: {line_content}")
                    elif sink_intersect and source_intersect:
                        undefined_list[filename][line_no + 1] = line_content
                        # print(f"undefined added: {line_content}")
                    else:
                        pass
            except FileNotFoundError:
                ic(cve_id, filename, status, "File not found")
              
        return source_list, sink_list, undefined_list
    except Exception as e:
        raise(e)

def reg_main():
    '''
    @return: Dict 
        {
            < File Name >: {
                'source': {
                    'old': {
                        < line no >: < line content >
                    }, 
                    'new': {
                        < line no >: < line content >
                    }
                }, 
                'sink': {...}, 
                'undefined': {...}
            }
        }
    '''
    
    staint_collect = {}
    with open(CVE_METHOD_PATH, 'r') as method_info_f:
        cves_methods = json.load(method_info_f)
    
    for root, dirs, files in os.walk(GIT_DIFF_PATH):
        cve = root.split('/')[-2]
        if cve not in cves_methods:
            continue
        if cve not in staint_collect:
            staint_collect[cve] = {
                'source': {
                    'old': {}, 
                    'new': {}
                }, 
                'sink':{
                    'old': {}, 
                    'new': {}
                }, 
                'undefined': {
                    'old': {}, 
                    'new': {}
                }
            }
        for file in files:
            try:
                with open(os.path.join(root, file)) as f:
                    lines = f.readlines()
                if root.split('/')[-1] == 'oldfiles':
                    source_list, sink_list, undefined_list = source_sink_detection(cve_id=cve, lines=lines, cve_methods=cves_methods[cve]['old_methods_info'], status='old')
                    staint_collect[cve]['sink']['old'].update(sink_list)
                    staint_collect[cve]['source']['old'].update(source_list)
                    staint_collect[cve]['undefined']['old'].update(undefined_list)
                if root.split('/')[-1] == 'newfiles':
                    source_list, sink_list, undefined_list = source_sink_detection(cve_id=cve, lines=lines, cve_methods=cves_methods[cve]['new_methods_info'], status='new')
                    staint_collect[cve]['sink']['new'].update(sink_list)
                    staint_collect[cve]['source']['new'].update(source_list)
                    staint_collect[cve]['undefined']['new'].update(undefined_list)
                else:
                    continue
            except Exception as e:
                ic(cve, file, "Error: ", e)
        print(f"Proceed {cve} {root.split('/')[-1]} complete! ")
    
    with open("staint_collect.json", 'w') as f:
        json.dump(staint_collect, f, indent=4)


def treesitter_parse(filepath: str, cve: str):
    try:
        jar_project = JarProject(filepath)
        print(jar_project.class_methods_lines)

    except Exception as e:
        ic(cve, filepath, e)


if __name__ == '__main__':
    # reg_main()
    for cve_folder in os.walk(GIT_DIFF_PATH):
        for old_file in os.walk(os.path.join(cve_folder[0], 'oldfiles')):
            for file in old_file[2]:
                if file.endswith('.java'):
                    treesitter_parse(os.path.join(old_file[0], file), cve_folder.split('/')[-2])
        for new_file in os.walk(os.path.join(cve_folder[0], 'newfiles')):
            for file in new_file[2]:
                if file.endswith('.java'):
                    treesitter_parse(os.path.join(new_file[0], file), cve_folder.split('/')[-2])
    