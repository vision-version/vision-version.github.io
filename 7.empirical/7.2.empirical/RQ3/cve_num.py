import os
import json

with open("version_analysis.json", "r", encoding="utf-8") as f:
    cves = json.load(f)

with open("vul_eco.json", "r", encoding="utf-8") as f:
    vul_eco = json.load(f)
    
other_ecos = set()
my_ecos = set(['Linux', 'Python', 'npm', 'Maven', 'PHP', "Unmanaged (C/C++)"])

eco_cve_num = {
    "c/c++": 0,
    "java": 0,
    "python": 0,
    "js": 0,
    "php": 0
}

my_cve_num = 0

print("Total number of CVEs:", len(cves))

for cve in cves:
    if cve not in vul_eco:
        print(cve)
    elif vul_eco[cve][0] not in my_ecos:
        other_ecos.add(vul_eco[cve][0])
    elif vul_eco[cve][0] in my_ecos:
        if vul_eco[cve][0] == "npm":
            eco_cve_num["js"] += 1
        elif vul_eco[cve][0] == "Python":
            eco_cve_num["python"] += 1
        elif vul_eco[cve][0] == "Maven":
            eco_cve_num["java"] += 1
        elif vul_eco[cve][0] == "PHP":
            eco_cve_num["php"] += 1
        else:
            eco_cve_num["c/c++"] += 1
        my_cve_num += 1

print("Number of vulnerabilities from five ecosystems:", my_cve_num, "Percentage:", my_cve_num / len(cves))

print(other_ecos)

print(eco_cve_num)
# print(len(vul_eco))

# print(len(cves) - len(vul_eco))





