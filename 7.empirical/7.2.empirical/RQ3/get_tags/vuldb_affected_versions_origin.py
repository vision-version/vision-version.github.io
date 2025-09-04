import re
import os
import json
from collections import defaultdict

# ==== Path Configuration ====
files_path = "/path/to/vuldb/"
metadata_path = "/path/to/metadata.json"
repo_tags_path = "/path/to/cve_repo_tags.json"
output_path = "/path/to/vuldb_affected_versions.json"


with open(metadata_path, "r", encoding="utf-8") as f:
    metadata = json.load(f)

with open(repo_tags_path, "r", encoding="utf-8") as f:
    repo_tags = json.load(f)

ecos = ["PHP", "JS", "Python"]

# Extract affected versions based on intervals
def extract_affected_versions(Start, End, Start_equal, End_equal, full_version_list):
    if Start == End and Start_equal and End_equal:
        return [Start]
    version_set = set()
    Start_flag = True
    End_flag = False
    if Start == 0 and End == 0:
        return []
    elif Start == 0:
        for v in full_version_list:
            if re.search(re.escape(End), v):
                if End_equal:
                    version_set.add(v)
                End_flag = True
            elif End_flag:
                version_set.add(v)
    elif End == 0:
        for v in full_version_list:
            if re.search(re.escape(Start), v):
                if Start_equal:
                    version_set.add(v)
                break
            else:
                version_set.add(v)
    else:
        for v in full_version_list:
            if re.search(re.escape(End), v):
                End_flag = True
            elif re.search(re.escape(Start), v):
                version_set.add(v)
                Start_flag = False
            elif Start_flag and End_flag:
                version_set.add(v)
    return list(version_set)


def clean_version(version):
    """
    Optimized version number cleaning function, removing common irrelevant suffixes and prefixes, preserving core version number parts.
    """
    if not isinstance(version, str):
        return version

    # Remove common suffixes
    suffix_patterns = [
        r"--.*$",         # Content after --
        r":source$",      # :source ending
        r"-exp\..*$",     # Content after -exp.
        r":py3$",         # :py3 ending
        r":py2$",         # :py2 ending
        r":cp.*$",        # :cp from start to end
    ]
    for pat in suffix_patterns:
        version = re.sub(pat, "", version)

    # Special handling for alpine, debian, maven prefixes
    if version.startswith("alpine:") or version.startswith("debian:") or version.startswith("maven:"):
        # e.g. alpine:3.14.0, maven:org.apache.struts:struts2-core:2.5.26
        parts = version.split(":")
        # Take the last non-empty part as version number
        for part in reversed(parts):
            if part and re.match(r"^\d+(\.\d+)*", part):
                version = part.split("+")[0]
                break
        else:
            version = parts[-1] if parts else version

    # Remove extra colons
    version = version.rstrip(":")
    # Remove leading and trailing spaces
    version = version.strip()
    return version

# Initialize final_result as {"ECO": {"CVEID": {"vuldb": []}}} structure
final_result = {}
for eco in ecos:
    final_result[eco] = {}
    for cve_id in repo_tags[eco].keys():
        final_result[eco][cve_id] = {"github": [], "osv": [], "veracode": [], "cve": [], "gitlab": [], "snyk": []}

for eco in ecos:
    repo_tags_eco = repo_tags[eco]
    for cve_id in repo_tags_eco.keys():
        fuxi_name = metadata.get(cve_id)
        file_path = os.path.join(files_path, fuxi_name + ".json")
        # If file not found, only report error but do not abort
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            continue
        with open(file_path, "r", encoding="utf-8") as f:
            vul_data = json.load(f)
        for repo in vul_data.keys():
            if repo == "schema_version":
                continue
            repo_groups = defaultdict(list)
            for key, value in vul_data.items():
                if key == "schema_version":
                    continue
                repo = key.split("_")[0]
                repo_groups[repo].append(value)
        for repo, entries in repo_groups.items():
            if repo == "github":
                versions_set = set()
                for entry in entries:
                    for aff in entry.get("affected", []):
                        for range in aff["ranges"]:
                            for event in range["events"]:
                                final_result[eco][cve_id][repo].append(event)

            elif repo == "osv":
                versions_set = set()
                for entry in entries:
                    for aff in entry.get("affected", []):
                        for v in aff.get("versions", []):
                            versions_set.add(v)
                final_result[eco][cve_id][repo].extend(list(versions_set))

            elif repo == "veracode":
                versions_set = set()
                for entry in entries:
                    for aff in entry.get("affected", []):
                        versions_set.update(aff["versions"])
                final_result[eco][cve_id][repo].extend(list(versions_set))

            elif repo == "cve":
                versions_set = set()
                for entry in entries:
                    for cpe in entry.get("cpe", []):
                        for match in cpe["cpe_match"]:
                            final_result[eco][cve_id][repo].append(match)
            elif repo == "gitlab":
                versions_set = set()
                # Parse GitLab-style affected version range strings and use extract_affected_versions to get affected version list
                ranges_set = set()
                for entry in entries:
                    for aff in entry.get("affected", []):
                        ranges_set.add(aff.get("ranges"))
                final_result[eco][cve_id][repo].extend(list(ranges_set))

            elif repo == "snyk":
                # INSERT_YOUR_CODE
                # If CVEID is in the specified list, directly set snyk version list to empty
                skip_cveids = {
                    "CVE-2023-43655",
                    "CVE-2020-4046",
                    "CVE-2020-22452",
                    "CVE-2020-28948",
                    "CVE-2021-33502",
                    "CVE-2018-14732",
                    "CVE-2021-23562",
                    "CVE-2021-23383",
                    "CVE-2022-33987",
                    "CVE-2022-0613",
                    "CVE-2024-28245",
                    "CVE-2018-1999024",
                    "CVE-2023-29159",
                    "CVE-2021-40839",
                    "CVE-2018-18074",
                    "CVE-2020-15275",
                    "CVE-2018-1000872",
                    "CVE-2022-23579",
                    "CVE-2011-4357",
                    "CVE-2024-21520",
                    "CVE-2020-14019",
                    "CVE-2014-1933",
                    "CVE-2023-41334",
                    "CVE-2024-21507",
                    "CVE-2023-26303",
                    "CVE-2019-15782",
                    "CVE-2018-7651",
                    "CVE-2020-1920",
                    "CVE-2021-4307",
                    "CVE-2022-36067",
                    "CVE-2017-16006"
                }
                if cve_id in skip_cveids:
                    continue
                versions_set = set()
                for entry in entries:
                    for aff in entry.get("affected", []):
                        final_result[eco][cve_id][repo].append(aff["ranges"])

with open(output_path, "w", encoding="utf-8") as f:
    json.dump(final_result, f, ensure_ascii=False, indent=2)
print(f"Written to {output_path}")

# Count the number of non-empty versions in each of the six repos
repos = ["github", "osv", "veracode", "cve", "gitlab", "snyk"]
repo_non_empty_count = {repo: 0 for repo in repos}
for eco in final_result:
    for cve in final_result[eco]:
        for repo in repos:
            versions = final_result[eco][cve].get(repo, [])
            if isinstance(versions, list) and len(versions) > 0:
                repo_non_empty_count[repo] += 1
for repo in repos:
    print(f'Number of non-empty versions in {repo}: {repo_non_empty_count[repo]}')