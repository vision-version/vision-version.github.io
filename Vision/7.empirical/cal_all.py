import json

from tqdm import tqdm
from datetime import datetime
from github import Auth, Github

auth = Auth.Token("")
g = Github(auth=auth)

with open("maven_github_map.json") as f:
    maven_github_map = json.load(f)
with open("maven_tags_map.json") as f:
    maven_tags_map = json.load(f)
with open("github_tags_map.json") as f:
    github_tags_map = json.load(f)

new_github = 0
new_github_same = 0
for ga, v in tqdm(maven_tags_map.items()):
    v_set = set(v)
    tag_set = set(github_tags_map[maven_github_map[ga]])
    if v_set == tag_set:
        print("same")
    repo = g.get_repo(maven_github_map[ga])
    commit_date = repo.get_branch("master").commit.commit.committer.date
    if commit_date >= datetime(2021, 7, 1, tzinfo=commit_date.tzinfo):
        new_github += 1
        if v_set == tag_set:
            new_github_same += 1
print(f"maven total: {len(maven_tags_map)}")
print(f"github total: {len(github_tags_map)}")
print(f"new github: {new_github}")
print(f"new github same: {new_github_same}")

github_maven_map = {v: k for k, v in maven_github_map.items()}
with open("github_maven_map.json", "w") as f:
    json.dump(github_maven_map, f, indent=4)
