import json
from distutils.version import LooseVersion
import functools

sortFilePath = "trueresult.json"
with open(sortFilePath, 'r') as file:
    data = json.load(file)

def compare_versions(version1, version2):
    print(version1)
    print(version2)
    version1 = str(version1)
    version2 = str(version2)
    try:
        if LooseVersion(version1) < LooseVersion(version2):
            return -1
        elif LooseVersion(version1) == LooseVersion(version2):
            return 0
        else:
            return 1
    except Exception as e:
        return 0
def sort_cve_version():
    for cve_number in data.keys():
        print(cve_number)

        affected_versions = data[cve_number]['affected']
        unaffected_versions = data[cve_number]['unaffected']

        affected_versions = sorted(affected_versions, key=functools.cmp_to_key(compare_versions))
        unaffected_versions = sorted(unaffected_versions, key=functools.cmp_to_key(compare_versions))

        data[cve_number] = {
                'affected': affected_versions,
                'unaffected': unaffected_versions
        }

    with open(sortFilePath, 'w') as fw:
        json.dump(data, fw, indent=4)

if __name__ == "__main__":
    sort_cve_version()
    # print(LooseVersion("3.9.1.1.Final") > LooseVersion("3.9.1.Final",))