import json
import re
import sys
from pathlib import Path
from packaging.version import parse as parse_version, Version, InvalidVersion
from packaging.specifiers import SpecifierSet
from typing import Set, List, Dict, Tuple, Optional
from tqdm import tqdm

def parse_version_safe(version_str: str) -> Optional[Version]:
    """Safely parse a version string, removing any 'v' prefix and handling special cases."""
    try:
        # Remove 'v' prefix if present
        version_str = str(version_str).strip().lstrip('v')
        # Remove any trailing colons (seen in veracode data)
        version_str = version_str.rstrip(':')
        return parse_version(version_str)
    except (InvalidVersion, AttributeError, TypeError):
        return None

def normalize_veracode_versions(versions: List[str]) -> Set[Version]:
    """Normalize Veracode version format."""
    normalized = set()
    for v in versions:
        parsed = parse_version_safe(v)
        if parsed:
            normalized.add(parsed)
    return normalized

def normalize_snyk_versions(version_range: str) -> Tuple[Optional[Version], Optional[Version]]:
    """Normalize Snyk version range format (e.g., '>=2.0.1,<2.0.4')."""
    try:
        spec = SpecifierSet(version_range)
        min_ver = max_ver = None
        for s in spec:
            if s.operator in ('>=', '>'):
                ver = parse_version_safe(s.version)
                if ver:
                    min_ver = ver if not min_ver else max(min_ver, ver)
            elif s.operator in ('<=', '<'):
                ver = parse_version_safe(s.version)
                if ver:
                    max_ver = ver if not max_ver else min(max_ver, ver)
        return min_ver, max_ver
    except:
        return None, None

def normalize_github_versions(version_info: List[Dict]) -> Tuple[Optional[Version], Optional[Version]]:
    """Normalize GitHub version format."""
    min_ver = max_ver = None
    for info in version_info:
        if 'introduced' in info:
            ver = parse_version_safe(info['introduced'])
            if ver:
                min_ver = ver if not min_ver else max(min_ver, ver)
        if 'fixed' in info:
            ver = parse_version_safe(info['fixed'])
            if ver:
                max_ver = ver if not max_ver else min(max_ver, ver)
    return min_ver, max_ver

def normalize_gitlab_versions(version_range: str) -> Tuple[Optional[Version], Optional[Version]]:
    """Normalize GitLab version range format."""
    return normalize_snyk_versions(version_range)  # GitLab uses same format as Snyk

def normalize_cve_versions(version_info: List[Dict]) -> Tuple[Optional[Version], Optional[Version]]:
    """Normalize CVE version format."""
    min_ver = max_ver = None
    for info in version_info:
        if 'versionStartIncluding' in info:
            ver = parse_version_safe(info['versionStartIncluding'])
            if ver:
                min_ver = ver if not min_ver else max(min_ver, ver)
        if 'versionEndExcluding' in info:
            ver = parse_version_safe(info['versionEndExcluding'])
            if ver:
                max_ver = ver if not max_ver else min(max_ver, ver)
    return min_ver, max_ver

def normalize_osv_versions(versions: List[str]) -> Set[Version]:
    """Normalize OSV version format."""
    normalized = set()
    for v in versions:
        parsed = parse_version_safe(v)
        if parsed:
            normalized.add(parsed)
    return normalized

def compare_version_ranges(range1: Tuple[Version, Version], range2: Tuple[Version, Version]) -> str:
    """Compare two version ranges and determine their relationship."""
    min1, max1 = range1
    min2, max2 = range2
    
    if not all([min1, max1, min2, max2]):
        return "Unknown"  # Cannot determine relationship if any bound is missing
        
    # Equal ranges
    if min1 == min2 and max1 == max2:
        return "Equal"
        
    # Disjoint ranges
    if max1 <= min2 or max2 <= min1:
        return "Disjoint"
        
    # Containment relationships
    if min1 <= min2 and max1 >= max2:
        return "Contain"
    if min2 <= min1 and max2 >= max1:
        return "Contained"
        
    # Overlapping ranges
    return "Overlap"

def normalize_versions(db_name: str, versions: any) -> Tuple[Optional[Version], Optional[Version]]:
    """Normalize versions based on database type."""
    try:
        if db_name == "veracode":
            vers = normalize_veracode_versions(versions)
            if vers:
                return min(vers), max(vers)
        elif db_name == "snyk":
            if isinstance(versions, list) and versions:
                return normalize_snyk_versions(versions[0])
        elif db_name == "github":
            return normalize_github_versions(versions)
        elif db_name == "gitlab":
            if isinstance(versions, list) and versions:
                return normalize_gitlab_versions(versions[0])
        elif db_name == "cve":
            return normalize_cve_versions(versions)
        elif db_name == "osv":
            vers = normalize_osv_versions(versions)
            if vers:
                return min(vers), max(vers)
    except Exception as e:
        print(f"Error normalizing versions for {db_name}: {str(e)}")
    return None, None

def analyze_version_inconsistencies(input_file: str, output_file: str):
    """Analyze version inconsistencies between vulnerability databases."""
    try:
        print(f"Reading input file: {input_file}")
        with open(input_file, 'r') as f:
            data = json.load(f)
        
        print(f"Processing {len(data)} CVEs...")
        result = {}
        for cve_id in tqdm(data.keys()):
            result[cve_id] = []
            for pair in data[cve_id]:
                try:
                    new_pair = pair.copy()
                    db1, db2 = list(pair.keys())
                    
                    # Normalize versions for both databases
                    range1 = normalize_versions(db1, pair[db1])
                    range2 = normalize_versions(db2, pair[db2])
                    
                    # Compare version ranges and determine inconsistency type
                    if range1[0] and range1[1] and range2[0] and range2[1]:
                        inconsistency = compare_version_ranges(range1, range2)
                    else:
                        inconsistency = "Unknown"
                    
                    new_pair["inconsistency"] = inconsistency
                    result[cve_id].append(new_pair)
                except Exception as e:
                    print(f"Error processing pair for {cve_id}: {str(e)}")
                    continue
        
        print(f"Saving results to: {output_file}")
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=4)
        
        print("Analysis complete!")
        
        # Print summary statistics
        total_pairs = sum(len(pairs) for pairs in result.values())
        inconsistency_counts = {
            "Equal": 0,
            "Disjoint": 0,
            "Contain": 0,
            "Contained": 0,
            "Overlap": 0,
            "Unknown": 0
        }
        
        for pairs in result.values():
            for pair in pairs:
                if "inconsistency" in pair:
                    inconsistency_counts[pair["inconsistency"]] += 1
        
        print("\nInconsistency Statistics:")
        print("-" * 40)
        for inc_type, count in inconsistency_counts.items():
            percentage = (count / total_pairs) * 100 if total_pairs > 0 else 0
            print(f"{inc_type:<10}: {count:>7} ({percentage:>6.2f}%)")
        print("-" * 40)
        
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    input_file = "pair_wise_versions.json"
    output_file = "RQ2.json"
    analyze_version_inconsistencies(input_file, output_file) 