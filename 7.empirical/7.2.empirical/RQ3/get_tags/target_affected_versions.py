import os
import json
import pandas as pd
from openai import OpenAI
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# Load version ranges from Excel
excel_path = "php python js version annotation.xlsx"
sheets = ["PHP", "JS", "Python"]
cve_version_range = {"PHP": {}, "JS": {}, "Python": {}}

for sheet in sheets:
    df = pd.read_excel(excel_path, sheet_name=sheet)
    if 'CVEID' in df.columns and '影响版本("-"为左闭右闭区间[])' in df.columns:
        for idx, row in df.iterrows():
            cveid = str(row['CVEID']).strip()
            version_range = str(row['影响版本("-"为左闭右闭区间[])']).strip()
            if cveid and version_range and cveid != 'nan' and version_range != 'nan':
                cve_version_range[sheet][cveid] = version_range

# Initialize final result dictionary (thread-shared resource, needs locking)
final_result = {"PHP": {}, "JS": {}, "Python": {}}
result_lock = Lock()

# Read version number library
with open("cve_repo_tags.json", "r", encoding="utf-8") as f:
    repo_tags = json.load(f)

# Initialize OpenAI client
client = OpenAI(
    base_url="https://ark.cn-beijing.volces.com/api/v3",
    api_key="28b0278f-187d-4322-b6e3-c4681659e195",
)

# Define task processing function
def process_cve(sheet, cve_id, version_range):
    version_list = repo_tags.get(sheet, {}).get(cve_id, [])
    Ask = f"""Please extract all relevant version numbers based on the following version range:
    Relevant version range: {version_range}
    Full version numbers: {version_list}
    "x-x" in affected versions represents left-closed right-closed interval
    Please extract all relevant version numbers based on the version range and return a list containing only version numbers, no other content.
    Output content is strictly limited to a list containing only version numbers.
    """

    try:
        print(f"[START] Query {sheet}:{cve_id}")
        completion = client.chat.completions.create(
            model="deepseek-v3-250324",
            messages=[
                {"role": "system", "content": "You are a security expert"},
                {"role": "user", "content": Ask},
            ],
        )
        result_content = completion.choices[0].message.content
        print(f"[DONE] {sheet}:{cve_id} result: {result_content}")

        with result_lock:
            final_result[sheet][cve_id] = result_content

    except Exception as e:
        print(f"[ERROR] {sheet}:{cve_id} exception: {e}")

# Use thread pool for concurrent processing
tasks = []
with ThreadPoolExecutor(max_workers=20) as executor:  # Can adjust thread count based on performance
    for sheet in sheets:
        for cve_id, version_range in cve_version_range[sheet].items():
            tasks.append(executor.submit(process_cve, sheet, cve_id, version_range))

    for future in as_completed(tasks):
        pass  # Continue only when all tasks are completed

# Save results
with open("target_versions.json", "w", encoding="utf-8") as f:
    json.dump(final_result, f, ensure_ascii=False, indent=2)
print("Written to target_versions.json")