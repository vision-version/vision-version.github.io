import json
import sys
from pathlib import Path
from collections import defaultdict
from itertools import combinations

input_file = "../vul_num_version_patch_all.json"

try:
    # Check if file exists
    if not Path(input_file).exists():
        print(f"Error: File '{input_file}' not found!")
        sys.exit(1)

    # Try to load and parse JSON
    with open(input_file) as fr:
        try:
            data = json.load(fr)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON format in '{input_file}'")
            print(f"Details: {str(e)}")
            sys.exit(1)

    # First, collect all version information for each CVE from each database
    cve_versions = defaultdict(dict)
    for db, vul_items in data.items():
        for vul_info in vul_items:
            for cve_id, cve_info in vul_info.items():
                try:
                    if ("version" in cve_info and 
                        cve_info["version"] is not None and 
                        cve_info["version"] != []):
                        cve_versions[cve_id][db] = cve_info["version"]
                except Exception as e:
                    print(f"Warning: Error processing version for CVE {cve_id} in database '{db}': {str(e)}")
                    continue

    # Create pair-wise version combinations for CVEs that appear in at least two databases
    pair_wise_versions = {}
    for cve_id, db_versions in cve_versions.items():
        if len(db_versions) >= 2:  # Only process CVEs that appear in at least two databases
            pairs = []
            for db1, db2 in combinations(db_versions.keys(), 2):
                # Skip pairs that include 'osv'
                if 'osv' in [db1, db2]:
                    continue
                pair = {
                    db1: db_versions[db1],
                    db2: db_versions[db2]
                }
                pairs.append(pair)
            if pairs:  # Only add if we have pairs
                pair_wise_versions[cve_id] = pairs

    # Save the pair-wise versions to a new JSON file
    output_file = "pair_wise_versions.json"
    with open(output_file, 'w') as fw:
        json.dump(pair_wise_versions, fw, indent=4)

    print(f"\nPair-wise version information has been saved to {output_file}")
    print(f"Total CVEs with pair-wise versions: {len(pair_wise_versions)}")
    
    # Sample output for verification (first CVE)
    if pair_wise_versions:
        first_cve = next(iter(pair_wise_versions))
        print(f"\nSample output for first CVE ({first_cve}):")
        print(json.dumps(pair_wise_versions[first_cve], indent=4))

    # Collect CVE IDs with non-empty versions for each database
    db_cve_sets = {}
    
    for db, vul_items in data.items():
        cve_set = set()
        for vul_info in vul_items:
            for cve_id, cve_info in vul_info.items():
                try:
                    # Check if version is not empty (not None and not empty list)
                    has_non_empty_version = (
                        "version" in cve_info and 
                        cve_info["version"] is not None and 
                        cve_info["version"] != []
                    )
                    
                    if has_non_empty_version:
                        cve_set.add(cve_id)
                        
                except Exception as e:
                    print(f"Warning: Error processing item in database '{db}': {str(e)}")
                    continue
        
        db_cve_sets[db] = cve_set

    # Calculate overlaps between databases
    databases = list(db_cve_sets.keys())
    
    print("\nAnalyzing CVE overlap between databases (non-empty versions only):")
    print("-" * 100)
    print(f"{'Database Pair':<50} {'Overlap Count':<15} {'Database 1 Total':<20} {'Database 2 Total':<20}")
    print("-" * 100)

    for i in range(len(databases)):
        for j in range(i + 1, len(databases)):
            db1, db2 = databases[i], databases[j]
            overlap = len(db_cve_sets[db1] & db_cve_sets[db2])
            db1_total = len(db_cve_sets[db1])
            db2_total = len(db_cve_sets[db2])
            
            pair_name = f"{db1} & {db2}"
            print(f"{pair_name[:50]:<50} {overlap:<15} {db1_total:<20} {db2_total:<20}")

    print("-" * 100)
    
    # Also show individual database statistics
    print("\nIndividual database statistics (non-empty versions):")
    print("-" * 60)
    print(f"{'Database':<30} {'CVE Count':<15} {'Total Items':<15}")
    print("-" * 60)
    
    for db, vul_items in data.items():
        cve_count = len(db_cve_sets[db])
        total_items = len(vul_items)
        print(f"{db[:30]:<30} {cve_count:<15} {total_items:<15}")

    print("-" * 60)

    # Calculate total unique CVEs across all databases
    all_cves_wz_version = set()
    for cve_set in db_cve_sets.values():
        all_cves_wz_version.update(cve_set)
    
    print(f"\nTotal unique CVEs across all databases (with non-empty versions): {len(all_cves_wz_version)}")

except Exception as e:
    print(f"Unexpected error occurred: {str(e)}")
    sys.exit(1)