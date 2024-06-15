import os
import json
import config

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
                    line_number_start = line.find("<SUB>")
                    line_number_end = line.find("</SUB>")
                    line_number = -1 
                    if line_number_start != -1 and line_number_end != -1:
                        line_number = int(
                            line[line_number_start + 5:line_number_end])
                    label_line_map[label_number] = line_number
                elif len(line) > 1:
                    from_end = line.find('"', 3)
                    from_label = int(line[3:from_end])
                    to_start = line.find('"', from_end + 1)
                    to_end = line.find('"', to_start + 1)
                    to_label = int(line[to_start + 1:to_end])
                    label_start = line.find('[ label = "')
                    label = line[label_start + 11:-3]
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

def detect_slicing1(i, work_id):
    return getcdg_ddg("slicingJson_" + work_id.__str__() + "/PDG" + i.__str__() + ".json")

def slicing(file_name, method_name, lineNumber,methodFullName, sess):
    os.chdir(config.workspace)
    sess.import_code(file_name)
    worker_id = sess.worker_id.replace("/","_")
    sess.run_script("slice", params={"line": lineNumber, "i":str(worker_id)})
    throw_line = []
    with open(file_name,"r") as f:
        lines = f.readlines()
        for i in range(len(lines)):
            line = lines[i].strip()
            if line.startswith("throw"):
                throw_line.append(i+1)
    file_name = file_name.split("/")[-1]
    label_line_map = {}
    cdg_map = {}
    ddg_map = {}
    slicing_set = set()
    cdg_map,ddg_map = getcdg_ddg(f"PDG/PDG_{worker_id}.json")
    assignment_set = get_infoSet(f"assign/assignment_{worker_id}.json")
    return_set = get_infoSet(f"ret/return_{worker_id}.json")
    control_set = get_infoSet(f"control/control_{worker_id}.json")
    criterion_set = set()
    with open(f"method_info_{worker_id}.json", "r", encoding="utf8") as f:
        json_object = json.load(f)
        for pair in json_object:
            if file_name == pair["oldFile"]:
                criterion_set = set(
                    pair["deleteMethodFull"][methodFullName]["lineNumber"]
                )
                break
            elif file_name == pair["newFile"]:
                criterion_set = set(pair["addMethodFull"][methodFullName]["lineNumber"])
                break

    slicing_set.update(criterion_set)
    for line in criterion_set:
        for key in cdg_map.keys():
            if line in cdg_map[key]:
                slicing_set.add(key)
        for key in ddg_map.keys():
            if line in ddg_map[key]:
                slicing_set.add(key)

        if line in assignment_set:
            if line in cdg_map.keys():
                for l in cdg_map[line]:
                    slicing_set.add(l)
            if line in ddg_map.keys():
                for l in ddg_map[line]:
                    slicing_set.add(l)

        elif line in control_set:
            temp_criterion_set = set()
            res = set()
            for key in ddg_map.keys():
                if line in ddg_map[key]:
                    temp_criterion_set.add(key)
            for cri in temp_criterion_set:
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
        elif line in return_set:
            pass
        else:
            temp_criterion_set = set()
            res = set()
            for key in ddg_map.keys():
                if line in ddg_map[key]:
                    temp_criterion_set.add(key)
            for cri in temp_criterion_set:
                if cri in ddg_map.keys():
                    for l in ddg_map[cri]:
                        res.add(l)
            for l in res:
                slicing_set.add(l)
    return cdg_map, ddg_map, slicing_set