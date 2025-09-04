import json

with open("additional_results.json", "r") as f:
    data = json.load(f)

def remove_prefix(version):
    """Remove common prefixes from version strings"""
    prefixes = ['ethereal-', 'wireshark-', 'v', 'release-', "openssl-", "OpenSSL_"]
    version_clean = version.strip()
    
    for prefix in prefixes:
        if version_clean.lower().startswith(prefix.lower()):
            version_clean = version_clean[len(prefix):]
            break
    
    return version_clean.strip()

def version_key(s):
    import re
    # Remove prefixes first
    s = remove_prefix(s)
    # Extract all numeric and non-numeric parts
    parts = re.split(r'(\d+)', s)
    key = []
    for part in parts:
        if part.isdigit():
            # Convert to string with leading zeros for proper sorting
            key.append(f"{int(part):010d}")
        elif part:
            key.append(part.lower())
    return key

for cve, value in data.items():
    for sources, item in value.items():
        if item is None:
            continue
        if "affected" in item:
            # Remove prefixes and deduplicate
            affected_versions = [remove_prefix(v) for v in item["affected"]]
            affected_versions = list(set(affected_versions))  # Remove duplicates
            item["affected"] = sorted(affected_versions, key=version_key)
            print(item["affected"])
        
        if "unaffected" in item:
            # Remove prefixes and deduplicate
            unaffected_versions = [remove_prefix(v) for v in item["unaffected"]]
            unaffected_versions = list(set(unaffected_versions))  # Remove duplicates
            item["unaffected"] = sorted(unaffected_versions, key=version_key)

with open("additional_results_formatted.json", "w") as f:
    json.dump(data, f, indent=4)