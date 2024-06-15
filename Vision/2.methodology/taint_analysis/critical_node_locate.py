import json
import os
import sys
import re
from icecream import ic

sys.path.append("2.methodology/jar_statement_locate/")
from JarProject import JarProject
from tree_sitter import Node


parent_directory = os.path.dirname(os.getcwd())
print("parent directory:", parent_directory)
PATCH_CALLCHAIN_GENERATE_PATH = os.path.join(parent_directory, "patch_callchain_generate")
CVE_METHOD_PATH = os.path.join(parent_directory, "patch_callchain_generate/cves_methods.json")
JOERN_PATH = os.path.join(parent_directory, "joern-cli")
GIT_DIFF_PATH = os.path.join(parent_directory, "patch_callchain_generate/github_diff")
HUNK_MAPPING_PATH = os.path.join(parent_directory, "taint_analysis/hunkmap")

SINK_TYPES = ['return_statement', 'throw_statement', 'assert_statement', 'try_statement', 'catch_clause', 'method_invocation']
UNDEFINED_TYPES = ['if_statement', 'else_statement', 'elif_statement', 'switch_expression', 'for_statement', 'while_statement']

NODE_TYPES = ['source', 'sink', 'undefined']

# DISCARDED
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
# DISCARDED END


def remove_duplicates(lst):
    """
    Removes duplicates from a list while preserving the order.
    
    Args:
    lst (list): The list to remove duplicates from.
    
    Returns:
    list: A new list with duplicates removed.
    """
    seen = set()
    return [x for x in lst if not (x in seen or seen.add(x))]


def rec_identifier_extraction(root: Node, node_type: list = ['identifier']) -> list:
    '''
    @param: root: Node

    @return: identifier list
    @desc: using recursive searching to search for all identifiers in the subtree
    '''
    identifier_list = []
    stack = []
    stack.append(root)
    while stack:
        node = stack.pop()
        if node.type in node_type:
            identifier_list.append(node)
        for child in node.children:
            stack.append(child)
    return identifier_list


def treesitter_parse(filepath: str, cve: str):
    '''
    @param: filepath: str
    @param: cve: str

    @return: critical nodes dict extracted using tree-sitter
    @desc: critical_nodes.json file format
    {
        < cve >: {
            < filename >: {
                'old': {
                    'source': {
                        < line no >: {
                            'code': < code snippet >,
                            'variable': < variable list > 
                        }, 
                        ...
                    }, 
                    'sink': {
                        ...
                    }, 
                    'undefined': {
                        ...
                    }
                },
                'new': {
                    'source': {...}, 
                    'sink': {...}, 
                    'undefined': {...}
                }
            },
            ...
        },
        ...
    }
    '''
    critical_nodes = {}
    try:
        jar_project = JarProject(filepath)
        for file in jar_project.files:
            filename = file.path.split('/')[-1]
            if filename not in critical_nodes:
                critical_nodes[filename] = {
                    'old': {}, 
                    'new': {}
                }

            if 'old' in file.path:
                status = 'old'
            else:
                status = 'new'
            critical_nodes[filename][status] = {
                'source': {}, 
                'sink': {}, 
                'undefined': {}
            }
            identifier_list = {}

            for method in file.methods:
                variable_str = method.signature.split('(')[1].split(')')[0]
                if variable_str:
                    variables = variable_str.split(',')
                else:
                    variables = []
                line_no = int(method.start_line + 1)
                critical_nodes[filename][status]['source'].update({
                    str(line_no): {
                        'code': method.code, 
                        'variable': variables
                    }
                })

                stack = []
                stack.append(method.node)
                while stack:
                    node = stack.pop()
                    line_no = int(node.start_point[0] + 1)

                    if node.type == 'identifier':
                        if line_no not in identifier_list:
                            identifier_list[line_no] = set()
                        
                        identifier_list[line_no].add(node.text.decode())

                    elif node.type in SINK_TYPES:
                        critical_nodes[filename][status]['sink'].update({
                            line_no: {
                                'code': node.text.decode(), 
                                'variable': []
                            }
                        })
                    
                    elif node.type in UNDEFINED_TYPES:
                        critical_nodes[filename][status]['undefined'].update({
                            line_no: {
                                'code': node.text.decode(), 
                                'variable': []
                            }
                        })
                    for child in node.children:
                        stack.append(child)
                
                sorted_sink = dict(sorted(critical_nodes[filename][status]['sink'].items(), key=lambda x: x[0]))
                critical_nodes[filename][status]['sink'] = sorted_sink
                sorted_undefined = dict(sorted(critical_nodes[filename][status]['undefined'].items(), key=lambda x: x[0]))  
                critical_nodes[filename][status]['undefined'] = sorted_undefined

            for line_no in critical_nodes[filename][status]['sink']:
                if line_no in identifier_list:
                    for var in list(set(identifier_list[line_no])):
                        if var in critical_nodes[filename][status]['sink'][line_no]['code']:
                            critical_nodes[filename][status]['sink'][line_no]['variable'].append(var)
            
            for line_no in critical_nodes[filename][status]['undefined']:
                if line_no in identifier_list:
                    for var in list(set(identifier_list[line_no])):
                        if var in critical_nodes[filename][status]['undefined'][line_no]['code']:
                            critical_nodes[filename][status]['undefined'][line_no]['variable'].append(var)
                
        return critical_nodes

    except Exception as e:
        ic(cve, filepath, e)


def pruning(critical_nodes_file: str, hunk_mapping_files: str) -> dict:
    '''
    @desc: pruning the critical nodes extracted from tree-sitter

    file format: 
    < CVE >: {
        "added": {
            < file name >: []
        },
        "deleted": {
            "BCrypt.java": []
        },
        "modified": {
            "BCrypt.java": {
                "add modify": [
                    [
                        356,
                        "for_check",
                        "sink"
                    ]
                ],
                "del modify": []
            }
        }
    },
    '''
    with open(critical_nodes_file, 'r') as f:
        critical_nodes = json.load(f)
    with open(hunk_mapping_files, 'r') as f:
        hunk_mapping = json.load(f)
    
    pruned_critical_nodes = {}

    for cve in critical_nodes:
        pruned_critical_nodes[cve] = {
            "added": {}, 
            "deleted": {}, 
            "modified": {}
        }
        for file in critical_nodes[cve]:
            try:
                pruned_critical_nodes[cve]['modified'][file] = []
                pruned_critical_nodes[cve]['added'][file] = []
                pruned_critical_nodes[cve]['deleted'][file] = []
                
                file_hunk_mapping = hunk_mapping[cve][file]
                add_lines = file_hunk_mapping['add']
                delete_lines = file_hunk_mapping['delete']
                modified_lines = file_hunk_mapping['match']

                for add_line in add_lines:
                    for node_type in NODE_TYPES: 
                        if str(add_line) in critical_nodes[cve][file]['new'][node_type]:
                            for var in critical_nodes[cve][file]['new'][node_type][str(add_line)]['variable']:
                                # if (add_line, var, node_type) not in pruned_critical_nodes[cve]['added'][file]:
                                pruned_critical_nodes[cve]['added'][file].append((add_line, var, node_type))
                
                for deleted_line in delete_lines: 
                    for node_type in NODE_TYPES: 
                        if str(deleted_line) in critical_nodes[cve][file]['old'][node_type]:
                            for var in critical_nodes[cve][file]['old'][node_type][str(deleted_line)]['variable']:
                                # if (del_matched_line, var) not in pruned_critical_nodes[cve]['deleted'][file]:
                                pruned_critical_nodes[cve]['deleted'][file].append((deleted_line, var, node_type))
                
                for matched_pair in modified_lines:
                    del_matched_line = matched_pair[0]
                    add_matched_line = matched_pair[1]
                    modified_vars = {
                        'old': [], 
                        'new': []
                    }
                    for node_type in NODE_TYPES:
                        if str(del_matched_line) in critical_nodes[cve][file]['old'][node_type]:
                            for var in critical_nodes[cve][file]['old'][node_type][str(del_matched_line)]['variable']:
                                # if (del_matched_line, var) not in modified_vars['old']:
                                modified_vars['old'].append((del_matched_line, var, node_type))
                        if str(add_matched_line) in critical_nodes[cve][file]['new'][node_type]:
                            for var in critical_nodes[cve][file]['new'][node_type][str(add_matched_line)]['variable']:
                                # if (add_matched_line, var) not in modified_vars['new']:
                                modified_vars['new'].append((add_matched_line, var, node_type))
                    add_vars = set(_[1] for _ in modified_vars['new'])
                    del_vars = set(_[1] for _ in modified_vars['old'])
                    add_modify = list(add_vars - del_vars)
                    del_modify = list(del_vars - add_vars)
                    pruned_critical_nodes[cve]['modified'][file] = {
                        'add modify': [tup for tup in modified_vars['new'] if tup[1] in add_modify], 
                        'del modify': [tup for tup in modified_vars['old'] if tup[1] in del_modify]
                    }
                
            except Exception as e:
                ic(cve, e)
    return pruned_critical_nodes
                    
            
if __name__ == '__main__':
    # critical_nodes = {}
    # for root, cve_files, files in os.walk(GIT_DIFF_PATH):
    #     for cve_file in cve_files:
    #         if 'CVE' in cve_file:
    #             critical_nodes[cve_file] = treesitter_parse(filepath=os.path.join(root, cve_file), cve=cve_file)
    
    # with open("critical_nodes.json", 'w') as f:
        # json.dump(critical_nodes, f, indent=4)

    pruned_dict = pruning(critical_nodes_file="critical_nodes.json", hunk_mapping_files=os.path.join(HUNK_MAPPING_PATH, 'cves_hunk_mapping.json'))
    with open("pruned_result.json", 'w') as f:
        json.dump(pruned_dict, f, indent=4)
