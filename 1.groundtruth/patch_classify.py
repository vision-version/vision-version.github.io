import openpyxl
from copy import deepcopy
import os
import json
import requests
import time

script_dir = os.path.dirname(os.path.abspath(__file__))

os.chdir(script_dir)

PATCH_PATH = "PATCH_JAVA.json"


def CWE_fetch(CVE_ID):
    print(CVE_ID)
    cwe = None
    cve_id = CVE_ID
    # Construct the API URL
    api_url = f'https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}'

    # Send a GET request to the API
    response = requests.get(api_url)

    # Define the maximum number of retry attempts
    max_retry_attempts = 3

    # Initialize a variable to keep track of the current retry attempt
    retry_attempt = 0

    while retry_attempt < max_retry_attempts:
        # Construct the API URL
        api_url = f'https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}'

        # Send a GET request to the API
        response = requests.get(api_url)
        time.sleep(5)
        if response.status_code == 200:
            data = response.json()
            # CWE information is typically available under 'cwe' in the JSON response
            cwe = data['result']['CVE_Items'][0]['cve']['problemtype']['problemtype_data'][0]['description'][0]['value']
            print(f'CWE for {cve_id}: {cwe}')
            break  # Break out of the loop if successful
        else:
            print(f"Failed to fetch CWE information for {cve_id}. Status code: {response.status_code}")
            retry_attempt += 1
            if retry_attempt < max_retry_attempts:
                # Sleep for a moment before retrying
                time.sleep(5)  # You can adjust the sleep duration as needed
            else:
                print(f"Max retry attempts reached. Could not fetch CWE information for {cve_id}.")
    return cwe
def extract_info():
    matrix= []
    with open(PATCH_PATH, "r") as fr:
        LANG_patch = json.load(fr)

    if "Java" not in LANG_patch:
        raise KeyError("no key named Java")
    

    try: 
        with open("cwe_cache.json", "r") as fr:
            cwe_cache = json.load(fr)
    except FileNotFoundError:
        cwe_cache = {}
        with open("cwe_cache.json", "w") as fw:
            json.dump(cwe_cache, fw, indent = 4)
   

    for cve_id, patchs in LANG_patch["Java"].items():
        matrix_template = {"project": None, "CVE": None, "patch": None, "cwe": None}
        matrix_template["project"] = "/".join(patchs[0]["url"].split("/")[3:5])
        matrix_template["CVE"] = cve_id

        urls = [patch["url"] for patch in patchs]
        matrix_template["patch"] = "\n".join(urls)
        
        
        matrix.append(matrix_template)

        if cve_id not in cwe_cache:
            matrix_template["cwe"] = CWE_fetch(cve_id)
            cwe_cache[cve_id] = matrix_template["cwe"]
        else:
            matrix_template["cwe"] = cwe_cache[cve_id]
            
        with open("cwe_cache.json", "w") as fw:
            json.dump(cwe_cache, fw, indent = 4)

        # print(matrix_template)
    return matrix

def save_excel():

    workbook = openpyxl.Workbook()


    sheet = workbook.active


    for col_num, header_text in enumerate(HEADERs, 1):
        cell = sheet.cell(row=1, column=col_num)
        cell.value = header_text

    column_template = { HEADER: "pending"  for HEADER in HEADERs}

    matrix = extract_info()
    
    for column in matrix:
        # column example: {"key": value}
        tmp_dic = deepcopy(column_template)
        for key in column:
            tmp_dic[key] = column[key]

        column_cells = []
        for key, value in tmp_dic.items():
            column_cells.append(value)
        sheet.append(column_cells)


    workbook.save('example.xlsx')

if __name__ == '__main__':
    save_excel()
    # extract_info()