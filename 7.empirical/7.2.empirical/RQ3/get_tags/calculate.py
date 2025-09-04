import re
from packaging.version import Version, InvalidVersion
import os
import json
from collections import Counter

def normalize_semver(v):
    """
    Clean and normalize version numbers for precise alignment.
    - Remove prefix 'v'
    - Convert to packaging.version.Version format
    - Auto-complete '1.2' -> '1.2.0'
    """
    if not isinstance(v, str):
        v = str(v)
    v = v.replace("releases/", "")
    v = v.replace("alpha/", "")
    v = v.replace("beta/", "")
    v = v.replace("version/", "")
    v = v.replace("release-", "")
    v = v.replace("clearsilver-", "")
    v = v.replace("v", "")
    v = v.replace("rc/", "")
    v = v.strip().lower()
    v = re.sub(r'^v', '', v)

    # Keep pre-release strings (like -beta), but ignore +metadata
    v = v.split("+")[0]

    try:
        return str(Version(v))
    except InvalidVersion:
        return v  # Fallback to string matching (final comparison may fail)

def calculate_precision_recall_f1(cve, y_true, y_pred):
    """
    F1 calculation using semantic version alignment, compatible with '1.2' and '1.2.0' cases
    """
    if cve == "CVE-2011-4357":
        print(y_true, y_pred)
    true_norm = [normalize_semver(v) for v in y_true]
    pred_norm = [normalize_semver(v) for v in y_pred]
    if cve == "CVE-2011-4357":
        print(true_norm, pred_norm)
    true_counter = Counter(true_norm)
    pred_counter = Counter(pred_norm)

    tp = sum((true_counter & pred_counter).values())
    fp = sum((pred_counter - true_counter).values())
    fn = sum((true_counter - pred_counter).values())

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return precision, recall, f1



def average_metric(stats_dict):
    """
    Calculate average values (with count)
    """
    result = {}
    for key, values in stats_dict.items():
        count = values["count"]
        if count:
            result[key] = {
                "precision": values["precision"] / count,
                "recall": values["recall"] / count,
                "f1": values["f1"] / count,
                "count": count
            }
        else:
            result[key] = {
                "precision": 0.0, "recall": 0.0, "f1": 0.0, "count": 0
            }
    return result

def main():
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    pred_path = os.path.join(BASE_DIR, "vuldb_affected_versions.json")
    true_path = os.path.join(BASE_DIR, "target_versions.json")
    output_path = os.path.join(BASE_DIR, "precision_recall_f1_result.json")

    with open(pred_path, "r", encoding="utf-8") as f:
        pred_data = json.load(f)
    with open(true_path, "r", encoding="utf-8") as f:
        true_data = json.load(f)

    repos = ["github", "osv", "veracode", "cve", "gitlab", "snyk"]
    result = {}
    overall_stats = {repo: {"precision": 0.0, "recall": 0.0, "f1": 0.0, "count": 0} for repo in repos}
    eco_stats = {}

    for eco, eco_cves in true_data.items():
        result[eco] = {}
        eco_stats[eco] = {repo: {"precision": 0.0, "recall": 0.0, "f1": 0.0, "count": 0} for repo in repos}
        for cve, cve_truth in eco_cves.items():
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
            if cve in cve_ban:
                continue
            result[eco][cve] = {}
            for repo in repos:
                # Process true values
                if isinstance(cve_truth, list):
                    y_true = cve_truth
                else:
                    y_true = cve_truth.get(repo, [])
                # Process predicted values
                y_pred = pred_data.get(eco, {}).get(cve, {}).get(repo, [])

                if not y_pred:
                    continue
                
                precision, recall, f1 = calculate_precision_recall_f1(cve, y_true, y_pred)
                if cve == "CVE-2011-4357":
                    print(repo, precision, recall, f1)
                result[eco][cve][repo] = {"precision": precision, "recall": recall, "f1": f1}

                overall_stats[repo]["precision"] += precision
                overall_stats[repo]["recall"] += recall
                overall_stats[repo]["f1"] += f1
                overall_stats[repo]["count"] += 1

                eco_stats[eco][repo]["precision"] += precision
                eco_stats[eco][repo]["recall"] += recall
                eco_stats[eco][repo]["f1"] += f1
                eco_stats[eco][repo]["count"] += 1

    # Write results to file
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"Results output to {output_path}")

    # Output overall average
    print("\nOverall average metrics for each vulnerability database (only counting CVEs with non-empty predictions):")
    for repo, avg in average_metric(overall_stats).items():
        print(f"{repo:8} | count: {avg['count']:3d} | precision: {avg['precision']:.4f} | recall: {avg['recall']:.4f} | f1: {avg['f1']:.4f}")

    # Output ecosystem average
    print("\nAverage metrics for vulnerability databases under each ecosystem (eco):")
    for eco in eco_stats:
        print(f"\n[eco: {eco}]")
        for repo, avg in average_metric(eco_stats[eco]).items():
            print(f"  {repo:8} | count: {avg['count']:3d} | precision: {avg['precision']:.4f} | recall: {avg['recall']:.4f} | f1: {avg['f1']:.4f}")

if __name__ == "__main__":
    main()
