import json
from sklearn.metrics import cohen_kappa_score

def parse_cve_file(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def get_version_labels(cve_data):
    version_labels = {}
    for cve, data in cve_data.items():
        for version in data['affected']:
            version_labels[version] = 1
        for version in data['unaffected']:
            version_labels[version] = 0
    return version_labels

def align_labels(file1_labels, file2_labels):
    all_versions = sorted(set(file1_labels.keys()).union(set(file2_labels.keys())))
    file1_aligned = [file1_labels.get(version, -1) for version in all_versions]
    file2_aligned = [file2_labels.get(version, -1) for version in all_versions]
    return file1_aligned, file2_aligned

file1_data = parse_cve_file('trueresultA.json')
file2_data = parse_cve_file('trueresultB.json')


file1_labels = get_version_labels(file1_data)
file2_labels = get_version_labels(file2_data)


file1_aligned, file2_aligned = align_labels(file1_labels, file2_labels)

kappa = cohen_kappa_score(file1_aligned, file2_aligned)
print(f'Cohen\'s Kappa: {kappa}')