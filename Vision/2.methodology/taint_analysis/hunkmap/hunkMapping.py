import json
import os
from icecream import ic
import Levenshtein

SOURCE_CODE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.getcwd())), 'patch_callchain_generate/github_diff')
FILEMAP_PATH = os.path.join(os.path.dirname(os.getcwd()), 'fileMaps')
print("source code path:", SOURCE_CODE_PATH)
print("file map path:", FILEMAP_PATH)


def hunk_mapping(cve_id: str, hunk_map: dict):
    '''
    @desc: cve_hunk_mapping.json file format: 
    {
        < cve id >: {
            < file name >: {
                "match": [
                    [ < deleted_line in old file >, < added_line in new file > ], 
                    ...
                ],
                "add": [  < add lines in new files > ],
                "delete": [ < add lines in new files > ]
            }
        }, 
        ...
    }
    '''
    code_map = {}
    for file, file_mapping in hunk_map.items():
        deleted_hunks = file_mapping['delLinesGroup']
        added_hunks = file_mapping['addLinesGroup']
        code_map[file] = {
            'match': [], 
            'add': [], 
            'delete': []
        }

        if cve_id == 'CVE-2017-7957' and file == 'SunLimitedUnsafeReflectionProvider.java':
            print()

        if not deleted_hunks and added_hunks:
            code_map[file] = {
                'match': [], 
                'add': [], 
                'delete': []
            }
            for add_hunk in added_hunks:
                code_map[file]['add'] += add_hunk
            continue
        
        if not added_hunks and deleted_hunks:
            code_map[file] = {
                'match': [], 
                'add': [], 
                'delete': deleted_hunks
            }
            for del_hunk in deleted_hunks:
                code_map[file]['delete'] += del_hunk
            continue
        
        matched_add_hunks = []
        matched_del_hunks = []

        for deleted_hunk in deleted_hunks:
            del_start_line = deleted_hunk[0] - 1 if deleted_hunk[0] != 1 else 1
            del_end_line = deleted_hunk[-1] + 1
            try:
                for added_hunk in added_hunks:
                    add_start_line = added_hunk[0] - 1 if added_hunk[0] != 1 else 1
                    add_end_line = added_hunk[-1] + 1
                    if str(del_start_line) in file_mapping['oldFileLineMap'] and str(add_start_line) in file_mapping['newFileLineMap'] and \
                        file_mapping['oldFileLineMap'][str(del_start_line)] == file_mapping['newFileLineMap'][str(add_start_line)] and \
                        str(del_end_line) in file_mapping['oldFileLineMap'] and str(add_end_line) in file_mapping['newFileLineMap'] and \
                        file_mapping['oldFileLineMap'][str(del_end_line)] == file_mapping['newFileLineMap'][str(add_end_line)]:
                        matched_pair = distance_calculate(cve_id=cve_id, filename=file, del_hunk=deleted_hunk, add_hunk=added_hunk)
                        if matched_pair:
                            code_map[file]['match'] += [matched_pair]
                        matched_add_hunks.append([line for line in added_hunk if line not in matched_pair])
                matched_del_hunks.append([line for line in deleted_hunk if line not in matched_pair])
            except Exception as e:
                ic(cve_id, file, deleted_hunk, added_hunk, e)
        
        for added_hunk in matched_add_hunks:
            code_map[file]['add'].extend(added_hunk)
        for deleted_hunk in matched_del_hunks:
            code_map[file]['delete'].extend(deleted_hunk)

    return code_map


def distance_calculate(cve_id: str, filename: str, del_hunk: list, add_hunk: list):
    with open(os.path.join(SOURCE_CODE_PATH, f'{cve_id}/oldfiles/{filename}'), 'r') as f:
        del_code_lines = f.readlines()
    with open(os.path.join(SOURCE_CODE_PATH, f'{cve_id}/newfiles/{filename}'), 'r') as f:
        add_code_lines = f.readlines()

    for del_line_no in del_hunk:
        del_code = del_code_lines[del_line_no - 1].strip()
        max_sim = 0.6
        sim_pair = []
        for add_line_no in add_hunk:
            add_code = add_code_lines[add_line_no - 1].strip()
            distance = Levenshtein.distance(del_code, add_code)
            sim_socre = 1 - distance / max(len(del_code), len(add_code))
            
            if sim_socre > max_sim:
                print(f"{add_code} __MATCHES__ {del_code}")
                sim_pair = (del_line_no, add_line_no)
                max_sim = sim_socre

        if sim_pair:
            return sim_pair
    
    return []


def cves_hunk_mapping():
    cves_mapping = {}
    for root, dirs, files in os.walk(FILEMAP_PATH):
        for file in files:
            cve = file.split('_')[0]
            print(cve)
            if 'CVE' in cve:
                with open(os.path.join(FILEMAP_PATH, file), 'r') as f:
                    line_mapping = json.load(f)
                cve_mapping = hunk_mapping(cve_id=cve, hunk_map=line_mapping)
                cves_mapping[cve] = cve_mapping
    with open("cves_hunk_mapping.json", 'w') as f:
        json.dump(cves_mapping, f, indent=4)


if __name__ == '__main__':
    cves_hunk_mapping()
