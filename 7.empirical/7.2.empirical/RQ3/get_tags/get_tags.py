import os
import re
import json
import warnings
import requests
import pandas as pd

# Suppress openpyxl default style warnings
warnings.filterwarnings("ignore", category=UserWarning, module="openpyxl")

def get_repo_full_names_from_excel(file_path):
    """
    Extract repo_full_name lists from the "补丁" column of "PHP", "JS", "Python" sheets in Excel file, and output in CVE_ID:repo_name format
    :param file_path: Excel file path
    :return: A dictionary with sheet names as keys and CVE_ID:repo_full_name lists as values
    """
    repo_dict = {}
    sheet_names = ["PHP", "JS", "Python"]
    for sheet in sheet_names:
        try:
            df = pd.read_excel(file_path, sheet_name=sheet)
        except Exception as e:
            print(f"Failed to read sheet {sheet}: {e}")
            repo_dict[sheet] = []
            continue
        if '补丁' not in df.columns or 'CVEID' not in df.columns:
            print(f"Sheet {sheet} not found '补丁' or 'CVEID' column")
            repo_dict[sheet] = []
            continue
        cve_repo_list = []
        for idx, row in df.iterrows():
            patch = row['补丁']
            cve_id = str(row['CVEID']).strip()
            if not cve_id or cve_id.lower() == 'nan':
                continue
            repo_full_name = None
            if isinstance(patch, str):
                # Prioritize matching github.com/owner/repo
                match = re.search(r'github\.com/([^/\s]+)/([^/\s]+)', patch)
                if match:
                    repo_full_name = f"{match.group(1)}/{match.group(2)}"
                else:
                    # Directly match owner/repo format
                    parts = patch.strip().split('/')
                    if len(parts) >= 2:
                        repo_full_name = f"{parts[0]}/{parts[1]}"
            if repo_full_name:
                cve_repo_list.append(f"{cve_id}:{repo_full_name}")
        # Remove duplicates
        cve_repo_list = list(set(cve_repo_list))
        repo_dict[sheet] = cve_repo_list
    return repo_dict

def print_repo_counts(repo_dict):
    """
    Print the number of repo_full_name extracted from each sheet
    :param repo_dict: Dictionary returned by get_repo_full_names_from_excel
    """
    for sheet, cve_repo_list in repo_dict.items():
        print(f"Sheet '{sheet}' extracted repo_full_name count: {len(cve_repo_list)}")

def get_github_tags(repo_full_name):
    """
    Get all tags for the specified GitHub repository
    :param repo_full_name: Repository full name, e.g. "owner/repo"
    :return: List of tag names
    """
    github_token = os.getenv('GITHUB_TOKEN')
    tags = []
    page = 1
    headers = {}
    if github_token:
        headers['Authorization'] = f'token {github_token}'
    while True:
        url = f"https://api.github.com/repos/{repo_full_name}/tags?page={page}&per_page=100"
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print(f"Failed to get tags, status code: {response.status_code}, content: {response.text}")
            break
        data = response.json()
        if not data:
            break
        tags.extend([tag['name'] for tag in data])
        page += 1
    return tags

def main():
    excel_file = "php python js version annotation.xlsx"
    repo_full_names_dict = get_repo_full_names_from_excel(excel_file)
    print_repo_counts(repo_full_names_dict)
    # Output CVE_ID:repo_full_name list for each sheet
    for sheet, cve_repo_list in repo_full_names_dict.items():
        print(f"{sheet} page automatically extracted CVE_ID:repo_full_name list:")
        for item in cve_repo_list:
            print(item)
    # Only store {cve_id: tags}, not including repo names
    
    cve_tags_dict = {}
    for sheet, cve_repo_list in repo_full_names_dict.items():
        cve_tags_dict[sheet] = {}
        for cve_repo in cve_repo_list:
            try:
                cve_id, repo_full_name = cve_repo.split(":", 1)
                tags = get_github_tags(repo_full_name)
                cve_tags_dict[sheet][cve_id] = tags
                print(f"{cve_id} got {len(tags)} tags")
            except Exception as e:
                print(f"Error getting {cve_repo} tags: {e}")
                cve_tags_dict[sheet][cve_id] = []
    with open("cve_repo_tags.json", "w", encoding="utf-8") as f:
        json.dump(cve_tags_dict, f, ensure_ascii=False, indent=2)
    print("Written to cve_repo_tags.json")

if __name__ == "__main__":
    main()
