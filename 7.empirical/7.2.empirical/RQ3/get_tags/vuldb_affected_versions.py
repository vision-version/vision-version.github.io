import re
import os
import json
from collections import defaultdict
from packaging.version import Version, InvalidVersion

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

def clean_version(version):
    """
    Clean and semantically standardize version numbers:
    - Remove suffixes and extra markers;
    - Extract core version parts;
    - Standardize using packaging.version.Version (e.g. 1.2 -> 1.2.0).
    """
    if not isinstance(version, str):
        version = str(version)

    # Remove common useless suffixes
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

    # Remove leading and trailing extra characters
    version = version.strip(":")
    version = version.split("+")[0]
    version = version.strip("bis")
    if "/" in version:
        parts = version.split("/")
        version = parts[-1]  # Take the last part
        # Safely handle cases containing "-"
        if "-" in version and "@" not in version:
            dash_parts = version.split("-")
            if len(dash_parts) > 1:
                version = dash_parts[1]
            else:
                version = dash_parts[0]

    # Standardize using Version object
    try:
        standardized = Version(version)
        return str(standardized)
    except InvalidVersion:
        return version  # Return cleaned original value to avoid exceptions

def extract_affected_versions(Start, End, Start_equal, End_equal, full_version_list):
    """
    Extract affected version numbers from full_version_list based on given version intervals.
    Use Version comparison method to ensure strict comparison.
    """

    def safe_version(v):
        try:
            if not isinstance(v, str):
                v = str(v) if v is not None else ""
            return Version(v)
        except InvalidVersion:
            return None
    result = []
    start_v = safe_version(Start) if Start != "0" else None
    end_v = safe_version(End) if End != "0" else None

    for v in full_version_list:
        v_clean = clean_version(v)
        v_obj = safe_version(v_clean)
        if v_obj is None:
            continue
        in_range = True
        if start_v:
            if Start_equal:
                in_range &= v_obj >= start_v
            else:
                in_range &= v_obj > start_v
        if end_v:
            if End_equal:
                in_range &= v_obj <= end_v
            else:
                in_range &= v_obj < end_v
        if in_range:
            result.append(v_clean)
    return result

def parse_version_range(sub_range):
    """
    Parse version range string into a set of conditions (operator, version).
    Supports the following formats:
    - >=1.2.3 <2.0.0
    - >=1.2.3,<2.0.0
    - >=1.2.3<2.0.0
    - [1.0.0,2.0.0)
    - =1.2.3
    """
    sub_range = sub_range.strip()

    # Special handling: "[1.0.0,2.0.0)", "(1.0.0,2.0.0]" etc. intervals
    bracket_match = re.match(r'^([\[\(])\s*([^,\s]+)\s*,\s*([^,\s]+)\s*([\]\)])$', sub_range)
    if bracket_match:
        left_bracket, start, end, right_bracket = bracket_match.groups()
        return [
            (">=" if left_bracket == "[" else ">", start),
            ("<=" if right_bracket == "]" else "<", end)
        ]

    # General processing: extract combinations of >=, <=, >, <, = followed by version numbers
    pattern = r'(>=|<=|>|<|=)\s*([^\s,<>!=]+)'
    matches = re.findall(pattern, sub_range)
    if matches:
        return matches

    # Special case: no spaces but multiple conditions stuck together, like ">=1.0.0<2.0.0"
    pattern_concat = r'(>=|<=|>|<|=)([^\s,<>!=]+)'
    matches = re.findall(pattern_concat, sub_range)
    return matches  # 可能为空列表


cve_ban = [
    "CVE-2024-21653",
    "CVE-2020-26253",
    "CVE-2019-8156",
    "CVE-2021-23383",
    "CVE-2022-4720",
    "CVE-2020-22452",
    "CVE-2024-23641",
    "CVE-2021-37656",
    "CVE-2022-0611"
]

# Initialize final_result as {"ECO": {"CVEID": {"vuldb": []}}} structure
final_result = {}
for eco in ecos:
    final_result[eco] = {}
    for cve_id in repo_tags[eco].keys():
        if cve_id in cve_ban:
            continue
        final_result[eco][cve_id] = {"github": [], "osv": [], "veracode": [], "cve": [], "gitlab": [], "snyk": []}

for eco in ecos:
    repo_tags_eco = repo_tags[eco]
    for cve_id in repo_tags_eco.keys():
        if cve_id in cve_ban:
            continue
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
                                Start = "0"
                                End = "0"
                                Start_equal = False
                                End_equal = False
                                if event.get("introduced"):
                                    Start = event.get("introduced")
                                    if Start == 0:
                                        Start_equal = False
                                    else:
                                        Start_equal = True
                                else:
                                    Start = 0
                                    Start_equal = False
                                if event.get("fixed"):
                                    End = event.get("fixed")
                                    End_equal = False
                                elif event.get("last_affected"):
                                    End = event.get("last_affected")
                                    End_equal = True
                                else:
                                    End = 0
                                    End_equal = False
                                versions = extract_affected_versions(Start, End, Start_equal, End_equal, repo_tags_eco[cve_id])
                                versions_set.update(versions)
                final_result[eco][cve_id][repo].extend(sorted(list(versions_set)))

            elif repo == "osv":
                versions_set = set()
                for entry in entries:
                    for aff in entry.get("affected", []):
                        for v in aff.get("versions", []):
                            versions_set.add(clean_version(v))
                final_result[eco][cve_id][repo].extend(sorted(list(versions_set)))

            elif repo == "veracode":
                versions_set = set()
                for entry in entries:
                    for aff in entry.get("affected", []):
                        for v in aff.get("versions", []):
                            if ".x" in v or ".dev" in v:
                                continue
                            versions_set.add(clean_version(v))
                final_result[eco][cve_id][repo].extend(sorted(list(versions_set)))

            elif repo == "cve":
                versions_set = set()
                for entry in entries:
                    for cpe in entry.get("cpe", []):
                        for match in cpe["cpe_match"]:
                            if match.get("cpe23Uri"):
                                cpe23Uri = match.get("cpe23Uri")
                                if cpe23Uri.split(":")[5] != "*":
                                    versions_set.add(cpe23Uri.split(":")[5])
                                else:
                                    Start = "0"
                                    End = "0"
                                    Start_equal = False
                                    End_equal = False
                                    if match.get("versionStartExcluding"):
                                        Start = match.get("versionStartExcluding")
                                        Start_equal = False
                                    elif match.get("versionStartIncluding"):
                                        Start = match.get("versionStartIncluding")
                                        Start_equal = True
                                    if match.get("versionEndIncluding"):
                                        End = match.get("versionEndIncluding")
                                        End_equal = True
                                    elif match.get("versionEndExcluding"):
                                        End = match.get("versionEndExcluding")
                                        End_equal = False
                                    versions = extract_affected_versions(Start, End, Start_equal, End_equal, repo_tags_eco[cve_id])
                                    versions_set.update(versions)
                final_result[eco][cve_id][repo].extend(sorted(list(versions_set)))
            elif repo == "gitlab":
                versions_set = set()
                for entry in entries:
                    for aff in entry.get("affected", []):
                        range_str = aff.get("ranges")
                        if not range_str or not isinstance(range_str, str):
                            continue
                        # Split multiple intervals with "||"
                        for sub_range in range_str.split("||"):
                            sub_range = sub_range.strip()
                            if not sub_range:
                                continue
                            # Split multiple conditions with "," or space
                            # Support like ">=2.2,<2.2.10" or ">=8.8.0 <8.8.5"
                            conditions = parse_version_range(sub_range)
                            Start = "0"
                            End = "0"
                            Start_equal = False
                            End_equal = False

                            for op, ver in conditions:
                                if op == ">=":
                                    Start = ver
                                    Start_equal = True
                                elif op == ">":
                                    Start = ver
                                    Start_equal = False
                                elif op == "<=":
                                    End = ver
                                    End_equal = True
                                elif op == "<":
                                    End = ver
                                    End_equal = False
                                elif op == "=":
                                    Start = ver
                                    End = ver
                                    Start_equal = True
                                    End_equal = True
                            # Pass to extract_affected_versions
                            versions = extract_affected_versions(Start, End, Start_equal, End_equal, repo_tags_eco.get(cve_id, []))
                            versions_set.update(versions)
                final_result[eco][cve_id][repo].extend(sorted(list(versions_set)))


            elif repo == "snyk":
                snyk_skip_cveids = {
                    "CVE-2023-43655", "CVE-2020-4046", "CVE-2020-22452", "CVE-2020-28948",
                    "CVE-2021-33502", "CVE-2018-14732", "CVE-2021-23562", "CVE-2021-23383",
                    "CVE-2022-33987", "CVE-2022-0613", "CVE-2024-28245", "CVE-2018-1999024",
                    "CVE-2023-29159", "CVE-2021-40839", "CVE-2018-18074", "CVE-2020-15275",
                    "CVE-2018-1000872", "CVE-2022-23579", "CVE-2011-4357", "CVE-2024-21520",
                    "CVE-2020-14019", "CVE-2014-1933", "CVE-2023-41334", "CVE-2024-21507",
                    "CVE-2023-26303", "CVE-2019-15782", "CVE-2018-7651", "CVE-2020-1920",
                    "CVE-2021-4307", "CVE-2022-36067", "CVE-2017-16006"
                }
                if cve_id in snyk_skip_cveids:
                    continue
                versions_set = set()
                for entry in entries:
                    for aff in entry.get("affected", []):
                        range_str = aff["ranges"]
                        if not range_str or not isinstance(range_str, str):
                            continue
                        range_str = range_str.strip()
                        # Special case: * means include all
                        if range_str == "*":
                            versions_set.update(repo_tags_eco.get(cve_id, []))
                            continue
                        # Normal parsing of range conditions
                        conditions = parse_version_range(range_str)
                        Start = "0"
                        End = "0"
                        Start_equal = False
                        End_equal = False
                        for op, ver in conditions:
                            if op == ">=":
                                Start = ver
                                Start_equal = True
                            elif op == ">":
                                Start = ver
                                Start_equal = False
                            elif op == "<=":
                                End = ver
                                End_equal = True
                            elif op == "<":
                                End = ver
                                End_equal = False
                            elif op == "=":
                                Start = ver
                                End = ver
                                Start_equal = True
                                End_equal = True
                        versions = extract_affected_versions(Start, End, Start_equal, End_equal,repo_tags_eco.get(cve_id, []))
                        versions_set.update(versions)
                final_result[eco][cve_id][repo].extend(sorted(list(versions_set)))

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