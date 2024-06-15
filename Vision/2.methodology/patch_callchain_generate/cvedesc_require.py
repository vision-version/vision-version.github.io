import requests
import json
import time
def get_cve_details(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    print(url)
    response = requests.get(url)
    if response.status_code == 200:
        cve_data = response.json()
        details = cve_data.get('vulnerabilities', {})[0].get('cve', []).get('descriptions', {})[0].get('value', 'No description available.')
        return details
    else:
        print(response.status_code)
        return 'Failed to retrieve details'

# Example usage:
cve_meta_path = "../../0.groundtruth/cve_metainfo_all.json"
with open(cve_meta_path, "r") as fr:
    cve_meta = json.load(fr)

with open("CVE_DESC.json", "r") as fr:
    cves_details = json.load(fr) 

cve_ids = cve_meta.keys()  # Replace this list with your CVE IDs

for cveid in cve_ids:
    if cveid in cves_details: continue
    cves_details[cveid] = get_cve_details(cveid)
    time.sleep(15)
    with open("CVE_DESC.json", "w") as fw:
        json.dump(cves_details, fw, indent = 4)    