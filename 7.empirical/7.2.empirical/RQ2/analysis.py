import json
import os

with open("version_analysis.json", "r") as f:
    data = json.load(f)

name_map = {
    "cve": "VDA",
    "github": "VDB",
    "gitlab": "VDC",
    "veracode": "VDD",
    "snyk": "VDE"
}
types = ["equal", "disjoint", "contain", "contained", "overlap"]

# Define database pairs in alphabetical order
alphabetical_pairs = [
    "VDA, VDB",
    "VDA, VDC", 
    "VDA, VDD",
    "VDA, VDE",
    "VDB, VDC",
    "VDB, VDD",
    "VDB, VDE",
    "VDC, VDD",
    "VDC, VDE",
    "VDD, VDE"
]

inconsistency_results = {}
for pair in alphabetical_pairs:
    inconsistency_results[pair] = {
        "equal": 0,
        "disjoint": 0,
        "contain": 0,
        "contained": 0,
        "overlap": 0
    }

error_count = 0
cve_count = 0
for cve, pairs in data.items():
    cve_count += 1
    for pair in pairs:
        db1, db2, _ = pair.keys()
        db_names = [name_map[db1], name_map[db2]]
        
        # Check if it's reverse order (non-alphabetical order)
        is_reverse_order = db_names[0] > db_names[1]
        
        # Sort in alphabetical order to ensure consistent key
        db_names_sorted = sorted(db_names)
        key = ", ".join(db_names_sorted)
        
        inconsistency = pair["inconsistency"].lower()
        
        # Handle inconsistency types
        if inconsistency == "equal":
            inconsistency_results[key]["equal"] += 1
        elif inconsistency == "disjoint":
            inconsistency_results[key]["disjoint"] += 1
        elif inconsistency == "overlap":
            inconsistency_results[key]["overlap"] += 1
        elif inconsistency == "contain":
            if is_reverse_order:
                # When reverse order, contain becomes contained
                inconsistency_results[key]["contained"] += 1
            else:
                inconsistency_results[key]["contain"] += 1
        elif inconsistency == "contained":
            if is_reverse_order:
                # When reverse order, contained becomes contain
                inconsistency_results[key]["contain"] += 1
            else:
                inconsistency_results[key]["contained"] += 1
        else:
            inconsistency_results[key]["equal"] += 1
            pass
            # if "contained" in inconsistency:
            #     if is_reverse_order:
            #         inconsistency_results[key]["contain"] += 1
            #     else:
            #         inconsistency_results[key]["contained"] += 1
            # else:
            #     error_count += 1
            #     print(cve, pair["inconsistency"])

print(f"Error count: {error_count}")
print(f"CVE count: {cve_count}")

with open("inconsistency_results.json", "w", encoding="utf-8") as f:
    json.dump(inconsistency_results, f, ensure_ascii=False, indent=4)





