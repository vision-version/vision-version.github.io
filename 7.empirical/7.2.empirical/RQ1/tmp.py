import json
with open("pair_wise_versions.json", "r") as f:
    data = json.load(f)

for key, value in data.items():
    print(key)
    print(value)
    break