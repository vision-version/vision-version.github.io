import sys
import os
import json
import hashlib

def informationCalc(add_line,delete_line,vul_syn,indirect_vul_syn,new_slicing_set,old_file_location,old_new_map):
    infoNum = 0
    stmts = []
    t = 5
    with open(old_file_location,"r") as f:
        lines = f.readlines()
        for vul in vul_syn:
            lines[vul-1] = lines[vul-1].replace(" ", "").replace("{", "").replace("}", "").replace("\t", "").replace("\n", "") 
            stmts.append(lines[vul-1])
        
        for vul in vul_syn:
            infoNum += 1 / stmts.count(lines[vul-1])
        
                 
        while infoNum > t:
            if indirect_vul_syn==[]:
                break
            
            farthestx = 0
            maxdis = 0
            old_x = -1
            new_x = -1
            for indirect in indirect_vul_syn:
                
                if indirect in old_new_map.keys():
                    new_line = old_new_map[indirect]
                else:
                    new_line = -1
                if delete_line != []:
                    old_x = min(delete_line, key=lambda x: abs(x - indirect))
                if add_line != [] and new_line != -1:
                    new_x = min(add_line, key=lambda x: abs(x - new_line))
                if old_x==-1 and abs(new_x-new_line) > maxdis and new_line != -1:
                    maxdis = abs(new_x-new_line)
                    farthestx = indirect
                elif new_x==-1 and abs(old_x-indirect) > maxdis:
                    maxdis = abs(old_x-indirect)
                    farthestx = indirect
                elif min(abs(old_x-indirect),abs(new_x-new_line)) > maxdis:
                    maxdis = min(abs(old_x-indirect),abs(new_x-new_line))
                    farthestx = indirect
                    
            stmts.remove(lines[farthestx-1])
            if farthestx in old_new_map.keys() and old_new_map[farthestx] in new_slicing_set:
                new_slicing_set.remove(old_new_map[farthestx])
            vul_syn.remove(farthestx)
            indirect_vul_syn.remove(farthestx)
            
            infoNum = 0
            for vul in vul_syn:
                infoNum += 1 / stmts.count(lines[vul-1])
            
    return vul_syn,new_slicing_set
