import json
import os
from packaging import version
from openai import OpenAI
from tqdm import tqdm

# Initialize OpenAI client
client = OpenAI(
    base_url="https://ark.cn-beijing.volces.com/api/v3",
    api_key="99498966-3113-41bc-b38a-77048995ca02",
)

def normalize_version(version_str):
    """Normalize version string to a standard format."""
    try:
        # Remove any 'v' prefix and trailing colon
        version_str = version_str.lower().strip()
        if version_str.startswith('v'):
            version_str = version_str[1:]
        if version_str.endswith(':'):
            version_str = version_str[:-1]
        return str(version.parse(version_str))
    except:
        return version_str

def normalize_version_range(versions):
    """Normalize a list of versions."""
    if isinstance(versions, list):
        if any(',' in v for v in versions):  # Handle Snyk-style ranges
            try:
                range_str = versions[0]
                parts = range_str.split(',')
                min_ver = parts[0].replace('>=', '').strip()
                max_ver = parts[1].replace('<', '').strip()
                return [v for v in [min_ver, max_ver] if v]
            except:
                return []
        return [normalize_version(v) for v in versions if v]
    return []

def compare_version_ranges(versions1, versions2):
    """Compare two version ranges and determine their relationship."""
    set1 = set(normalize_version_range(versions1))
    set2 = set(normalize_version_range(versions2))
    
    if not set1 or not set2:
        return "Unknown"
    
    if set1 == set2:
        return "Equal"
    elif not (set1 & set2):
        return "Disjoint"
    elif set1 > set2:
        return "Contain"
    elif set2 > set1:
        return "Contained"
    else:
        return "Overlap"

def process_cve_versions(versions):
    new_versions = []
    for version in versions:
        if "versionStartIncluding" in version.keys() or "versionStartExcluding" in version.keys() or "versionEndIncluding" in version.keys() or "versionEndExcluding" in version.keys():
            endversion_next = ""
            if "versionEndExcluding" in version.keys():
                endversion_next = "<" + version["versionEndExcluding"]
            endversion =""
            if "versionEndIncluding" in version.keys():
                endversion = "<=" + version["versionEndIncluding"]
                
            startversion = ""
            if "versionStartIncluding" in version.keys():
                startversion = ">= " + version["versionStartIncluding"]
            startversion_back = ""
            if "versionStartExcluding" in version.keys():
                startversion_back = ">" + version["versionStartExcluding"]
            return f"{startversion} {endversion} {startversion_back} {endversion_next}"
        else:
            new_versions.append(version["cpe23Uri"].split(":")[5])
    return new_versions

def process_cve_pair(pair):
    """Process a single CVE pair using LLM for complex cases."""
    try:
        # Get the database names and their version lists
        db1, db2 = list(pair.keys())[:2]  # Get only the first two keys (excluding inconsistency if it exists)
        db1_versions = pair[db1]
        db2_versions = pair[db2]
        if db1 == "cve":
            # print("before process_cve_versions", db1_versions)
            db1_versions = process_cve_versions(db1_versions)
            # print("after process_cve_versions", db1_versions)
        if db2 == "cve":
            # print("before process_cve_versions", db2_versions)
            db2_versions = process_cve_versions(db2_versions)
            # print("after process_cve_versions", db2_versions)
        
        prompt = f"""
        Compare these two version ranges and determine their relationship:
        {db1} versions: {db1_versions}
        {db2} versions: {db2_versions}

        Classify as one of: Equal, Disjoint, Contain, Contained, Overlap
        You should tolerant the version format, like: 11.0 v11.0 v11.0: 11.00 ... they are all the same version.
        Only return the classification word.
        
        For Equal, IF the version range of DB1 is : <=12.1.0, then the version range of DB2 should like <=12.1.0 or 11.0 11.1 12.0 .... You don' know the exact version set, but you can infer the version set from the version range.
        For Equal, IF the version range of DB1 is : "v2.0.2:" "v2.0.3:" "v2.0.1:", then the version range of DB2 should like >=2.0.1,<2.0.4
        For Disjoint, IF the version range of DB1 is : <=12.1.0 or 11.0 11.1 11.2 12.0, then the version range of DB2 should like >12.1.0.
        For Contain, IF the version range of DB1 is : <=12.1.0, then the version range of DB2 should like 11.0 11.1 11.2.
        For Contained, IF the version range of DB1 is : <=12.1.0, then the version range of DB2 should like 11.0 11.1 11.2 12.0 12.1 or <=12.1.
        For Overlap, IF the version range of DB1 is : <=12.1.0 or 11.0 11.1 11.2 12.0, then the version range of DB2 should like 11.2, 12.0 12.1.
        
        For different databases, there are important record format, for example,
        for some database that provide affected range:
        "fixed": "2.0.4" means "< 2.0.4"
        If there are only <2.0.13, it means all versions "< 2.0.13" are affected
        for some database that provide affected versions separately not range, for some cve and veracode, it may be like:
            1.1 1.2 1.3 1.4, it means the version affected range is from 1.1 to 1.4
        """
        
        completion = client.chat.completions.create(
            model="deepseek-v3-250324",
            messages=[
                {"role": "system", "content": "You are an expert in analyzing software version ranges."},
                {"role": "user", "content": prompt},
            ],
        )
        inconsistency = completion.choices[0].message.content.strip()

        
        pair["inconsistency"] = inconsistency
        return pair
    except Exception as e:
        print(f"Error processing pair: {e}")
        pair["inconsistency"] = "Error"
        return pair

def main():
    input_file = "pair_wise_versions.json"
    output_file = "version_analysis.json"
    checkpoint_file = "checkpoint.json"
    SAVE_INTERVAL = 5000  # 每100轮保存一次

    # Load existing progress if any
    processed_cves = set()
    result_data = {}
    if os.path.exists(checkpoint_file):
        with open(checkpoint_file, 'r') as f:
            checkpoint_data = json.load(f)
            processed_cves = set(checkpoint_data.get("processed_cves", []))
            result_data = checkpoint_data.get("result_data", {})

    # Load input data
    with open(input_file, 'r') as f:
        data = json.load(f)

    # Process entries
    counter = 0
    for cve_id, pairs in tqdm(data.items()):
        # Skip if already processed
        if cve_id in processed_cves:
            continue

        # Process each pair for this CVE
        processed_pairs = []
        for pair in pairs:
            processed_pair = process_cve_pair(pair)
            processed_pairs.append(processed_pair)

        # Store results
        result_data[cve_id] = processed_pairs

        # Update checkpoint
        processed_cves.add(cve_id)
        counter += 1

        # 每SAVE_INTERVAL轮保存一次
        if counter % SAVE_INTERVAL == 0:
            with open(checkpoint_file, 'w') as f:
                json.dump({
                    "processed_cves": list(processed_cves),
                    "result_data": result_data
                }, f, indent=2)
            with open(output_file, 'w') as f:
                json.dump(result_data, f, indent=2)

    # 循环结束后，确保最后一次也保存
    with open(checkpoint_file, 'w') as f:
        json.dump({"processed_cves": list(processed_cves), "result_data": result_data}, f, indent=2)
    with open(output_file, 'w') as f:
        json.dump(result_data, f, indent=2)

if __name__ == "__main__":
    main()