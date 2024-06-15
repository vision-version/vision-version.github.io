import os
import json
from icecream import ic
def getcdg_ddg(PDG_FILE):
    label_line_map = {}
    cdg_map = {}
    ddg_map = {}
    with open(PDG_FILE,encoding="utf8") as f:
        json_object = json.load(f)
        if len(json_object) == 0: 
            list1 = []
        else:
            list1 = json_object[0].split("\n")
        for line in list1:
            if not line.startswith("digraph"):
                if line.startswith('"'):
                    num_end = line.find('"', 1)
                    label_number = int(line[1:num_end])
                    # print(label_number)
                    line_number_start = line.find("<SUB>")
                    line_number_end = line.find("</SUB>")
                    line_number = -1 
                    if line_number_start != -1 and line_number_end != -1: 
                        line_number = int(
                            line[line_number_start + 5:line_number_end])
                    # print(line_number)
                    label_line_map[label_number] = line_number
                elif len(line) > 1:
                    # print(line)
                    from_end = line.find('"', 3)
                    from_label = int(line[3:from_end])
                    to_start = line.find('"', from_end + 1)
                    to_end = line.find('"', to_start + 1)
                    to_label = int(line[to_start + 1:to_end])
                    # print(from_label.__str__() + " " + to_label.__str__())
                    label_start = line.find('[ label = "')
                    label = line[label_start + 11:-3]
                    # print(label)
                    if label_line_map[from_label] != label_line_map[to_label] and label_line_map[from_label] != -1 and label_line_map[to_label] != -1:
                        if label.startswith("CDG"):
                            if label_line_map[from_label] not in cdg_map.keys():
                                cdg_map[label_line_map[from_label]] = set()
                            cdg_map[label_line_map[from_label]].add(
                                label_line_map[to_label])
                        else:
                            if label_line_map[from_label] not in ddg_map.keys():
                                ddg_map[label_line_map[from_label]] = set()
                            ddg_map[label_line_map[from_label]].add(
                                label_line_map[to_label])
    return cdg_map, ddg_map

def get_infoSet(path):
    ret_set = set()
    with open(path, "r", encoding="utf8") as f:
        list1 = json.load(f)
        for line in list1:
            ret_set.add(line)
    return ret_set

def detect_slicing1(i):
    return getcdg_ddg("slicingJson/PDG" + i.__str__() + ".json")

def slicing(joern_path, file_name, method_fullname, method_fullname_para_escape, modifiedLines, methodName, binfile):
    os.chdir(joern_path)
    ic(f"./joern --script slice_ver.sc --params cpgFile=\"{binfile}\",methodFullName=\"{method_fullname}\"")
    method_fullname_nocomma = method_fullname.replace(",", "__split__")
    os.system(
        f"./joern --script slice_ver.sc --params cpgFile=\"{binfile}\",methodFullName=\"{method_fullname_nocomma}\"")

    throw_line = []
    with open(file_name,"r") as f:
        lines = f.readlines()
        for i in range(len(lines)):
            line = lines[i].strip()
            if line.startswith("throw"):
                throw_line.append(i+1)
    cdg_map = {}
    ddg_map = {}
    slicing_set = set()
    cdg_map,ddg_map = getcdg_ddg("PDG.json")
    assignment_set = get_infoSet("assignment.json")
    return_set = get_infoSet("return.json")
    control_set = get_infoSet("control.json")

    
    criterion_set = []
    for each_line in modifiedLines:
        for linenum in each_line:
            criterion_set.append(linenum)
    criterion_set = list(set(criterion_set))

    slicing_set.update(criterion_set)
    # # slicing
    for line in criterion_set:
        # normal backward slicing
        for key in cdg_map.keys():
            if line in cdg_map[key]:
                slicing_set.add(key)
        for key in ddg_map.keys():
            if line in ddg_map[key]:
                slicing_set.add(key)

        # customized forward slicing

        # case1: assignment -> normal forward slicing
        if line in assignment_set:
            if line in cdg_map.keys():
                for l in cdg_map[line]:
                    slicing_set.add(l)
            if line in ddg_map.keys():
                for l in ddg_map[line]:
                    slicing_set.add(l)
        # case2: conditional -> backward on ddg, then forward on ddg, if nil, forward on cdg
        elif line in control_set:
            temp_criterion_set = set()
            res = set()
            for key in ddg_map.keys():
                if line in ddg_map[key]:
                    temp_criterion_set.add(key)
            for cri in temp_criterion_set:
                # if cri in cdg_map.keys():
                #     for l in cdg_map[cri]:
                #         res.add(l)
                if cri in ddg_map.keys():
                    for l in ddg_map[cri]:
                        res.add(l)
            if len(res) == 0:
                if line in cdg_map.keys():
                    for l in cdg_map[line]:
                        slicing_set.add(l)
            else:
                for l in res:
                    slicing_set.add(l)
        # case3: return -> do nothing
        elif line in return_set:
            pass
        # case4: other -> backward on ddg, then forward on ddg
        else:
            temp_criterion_set = set()
            res = set()
            for key in ddg_map.keys():
                if line in ddg_map[key]:
                    temp_criterion_set.add(key)
            for cri in temp_criterion_set:
                # if cri in cdg_map.keys():
                #     for l in cdg_map[cri]:
                #         res.add(l)
                if cri in ddg_map.keys():
                    for l in ddg_map[cri]:
                        res.add(l)
            for l in res:
                slicing_set.add(l)
    # print(cdg_map)
    # print(ddg_map)
    # print(slicing_set)
    return cdg_map, ddg_map, slicing_set

if __name__ == '__main__':
    cdg_map, ddg_map, slicing_set = slicing(
        "2.methodology/joern-cli",
        "2.methodology/patch_featuregraph_generate/tmp.java","stop","", [{10:"10"}],"")
    ic(cdg_map)
    ic(ddg_map)
    ic(slicing_set)
