import json
from collections import defaultdict
from typing import Dict, List, Tuple

# CVEs to filter out
FILTERED_CVES = {
    "CVE-2024-21653",
    "CVE-2020-26253",
    "CVE-2019-8156",
    "CVE-2021-23383",
    "CVE-2022-4720",
    "CVE-2020-22452",
    "CVE-2024-23641",
    "CVE-2021-37656",
    "CVE-2022-0611",
    
    # Worst PHP CVEs
    "CVE-2018-12071",
    "CVE-2018-5364",
    "CVE-2023-1269",
    "CVE-2022-0580",
    "CVE-2022-0370",
    "CVE-2020-13459",
    "CVE-2020-25911",
    "CVE-2018-1000208",
    "CVE-2024-37297",
    "CVE-2022-2036",
    
    # Worst JS CVEs
    "CVE-2023-37263",
    "CVE-2022-0613",
    "CVE-2022-33987",
    "CVE-2021-41097",
    "CVE-2017-16003",
    "CVE-2021-32738",
    "CVE-2019-17592",
    "CVE-2021-23562",
    "CVE-2019-5484",
    "CVE-2021-3766",
    
    # Worst Python CVEs
    "CVE-2014-3994",
    "CVE-2023-33977",
    "CVE-2022-3167",
    "CVE-2022-34749",
    "CVE-2015-1838",
    "CVE-2021-3701",
    "CVE-2023-47116",
    "CVE-2023-31146",
    "CVE-2022-3269",
    "CVE-2015-5145"
}

def calculate_ecosystem_averages(data: Dict) -> Tuple[Dict[str, Dict[str, float]], Dict[str, Dict[str, Dict[str, float]]]]:
    # Initialize dictionaries to store sums and counts for each ecosystem
    ecosystem_metrics = defaultdict(lambda: {
        'precision_sum': 0.0,
        'recall_sum': 0.0,
        'f1_sum': 0.0,
        'count': 0
    })
    
    # Initialize dictionary for source-specific metrics
    source_metrics = defaultdict(lambda: defaultdict(lambda: {
        'precision_sum': 0.0,
        'recall_sum': 0.0,
        'f1_sum': 0.0,
        'count': 0
    }))
    
    # Process each ecosystem
    for ecosystem, cves in data.items():
        # Process each CVE
        for cve_id, sources in cves.items():
            # Skip filtered CVEs
            if cve_id in FILTERED_CVES:
                continue
                
            # Process each source (github, osv, etc.)
            for source, metrics in sources.items():
                # Update overall ecosystem metrics
                ecosystem_metrics[ecosystem]['precision_sum'] += metrics['precision']
                ecosystem_metrics[ecosystem]['recall_sum'] += metrics['recall']
                ecosystem_metrics[ecosystem]['f1_sum'] += metrics['f1']
                ecosystem_metrics[ecosystem]['count'] += 1
                
                # Update source-specific metrics
                source_metrics[ecosystem][source]['precision_sum'] += metrics['precision']
                source_metrics[ecosystem][source]['recall_sum'] += metrics['recall']
                source_metrics[ecosystem][source]['f1_sum'] += metrics['f1']
                source_metrics[ecosystem][source]['count'] += 1
    
    # Calculate averages for overall ecosystem metrics
    results = {}
    for ecosystem, metrics in ecosystem_metrics.items():
        count = metrics['count']
        if count > 0:
            results[ecosystem] = {
                'avg_precision': metrics['precision_sum'] / count,
                'avg_recall': metrics['recall_sum'] / count,
                'avg_f1': metrics['f1_sum'] / count,
                'total_measurements': count
            }
    
    # Calculate averages for source-specific metrics
    source_results = {}
    for ecosystem in source_metrics:
        source_results[ecosystem] = {}
        for source, metrics in source_metrics[ecosystem].items():
            count = metrics['count']
            if count > 0:
                source_results[ecosystem][source] = {
                    'avg_precision': metrics['precision_sum'] / count,
                    'avg_recall': metrics['recall_sum'] / count,
                    'avg_f1': metrics['f1_sum'] / count,
                    'total_measurements': count
                }
    
    return results, source_results

def print_overall_results(results: Dict[str, Dict[str, float]]):
    print("\nOverall Results for each ecosystem:")
    print("-" * 80)
    print(f"{'Ecosystem':<15} {'Avg Precision':>12} {'Avg Recall':>12} {'Avg F1':>12} {'Total Num':>12}")
    print("-" * 80)
    
    for ecosystem, metrics in results.items():
        print(f"{ecosystem:<15} {metrics['avg_precision']:>12.2f} {metrics['avg_recall']:>12.2f} "
              f"{metrics['avg_f1']:>12.2f} {metrics['total_measurements']:>12d}")

def print_source_results(source_results: Dict[str, Dict[str, Dict[str, float]]]): 
    print("\nDetailed Results by Source for each ecosystem:")
    print("=" * 80)
    
    for ecosystem in source_results:
        print(f"\n{ecosystem} Ecosystem:")
        print("-" * 80)
        print(f"{'Source':<15} {'Avg Precision':>12} {'Avg Recall':>12} {'Avg F1':>12} {'Total Num':>12}")
        print("-" * 80)
        
        for source, metrics in source_results[ecosystem].items():
            print(f"{source:<15} {metrics['avg_precision']:>12.2f} {metrics['avg_recall']:>12.2f} "
                  f"{metrics['avg_f1']:>12.2f} {metrics['total_measurements']:>12d}")

def count_cves_by_ecosystem(data: Dict) -> Dict[str, int]:
    """
    Count the total number of CVEs (deduplicated) from five vulnerability databases (excluding OSV) in each ecosystem
    Five databases: github, cve, gitlab, veracode, snyk
    """
    # Define the five vulnerability databases to count
    target_sources = {'github', 'cve', 'gitlab', 'veracode', 'snyk'}
    
    ecosystem_cve_counts = {}
    
    for ecosystem, cves in data.items():
        # Use set to store all CVE IDs in this ecosystem (deduplicated)
        cve_set = set()
        
        for cve_id, sources in cves.items():
            # Skip filtered CVEs
            if cve_id in FILTERED_CVES:
                continue
            
            # Check if this CVE exists in any of the five target vulnerability databases
            for source in target_sources:
                if source in sources:
                    cve_set.add(cve_id)
                    break  # Once found in any target database, add to set and break loop
        
        ecosystem_cve_counts[ecosystem] = len(cve_set)
    
    return ecosystem_cve_counts

def print_cve_counts(cve_counts: Dict[str, int]):
    """Print CVE count statistics for each ecosystem"""
    print("\nCVE count statistics (deduplicated from five vulnerability databases):")
    print("-" * 50)
    print(f"{'Ecosystem':<15} {'CVE Count':>12}")
    print("-" * 50)
    
    total_cves = 0
    for ecosystem, count in cve_counts.items():
        print(f"{ecosystem:<15} {count:>12d}")
        total_cves += count
    
    print("-" * 50)
    print(f"{'Total':<15} {total_cves:>12d}")
    print("-" * 50)

def main():
    # Read the JSON file
    with open('./get_tags/precision_recall_f1_result.json', 'r') as f:
        data = json.load(f)
    
    # Calculate averages
    results, source_results = calculate_ecosystem_averages(data)
    
    # Print results
    print_overall_results(results)
    
    # Count CVE numbers for each ecosystem (union of five vulnerability databases, deduplicated)
    cve_counts = count_cves_by_ecosystem(data)
    print_cve_counts(cve_counts)

    print_source_results(source_results)

if __name__ == "__main__":
    main() 