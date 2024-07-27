import json

from datetime import datetime
from github import Auth, Github

auth = Auth.Token("")
g = Github(auth=auth)

data_path = "trueresult original.json"
info_path = "versions.json"

with open(data_path) as f:
    data = json.load(f)
with open(info_path) as f:
    info = json.load(f)

github_repos = set()
for cveid, cve_data in data.items():
    owner = info[cveid]["UsrName"]
    repo = info[cveid]["PjName"]
    github_repos.add(f"{owner}/{repo}")

time_dict = {}
new_repo = set()
for github_repo in github_repos:
    repo = g.get_repo(github_repo)
    commit_date = repo.get_branch("master").commit.commit.committer.date
    if commit_date >= datetime(2024, 7, 1, tzinfo=commit_date.tzinfo):
        new_repo.add(github_repo)
    time_dict[github_repo] = commit_date.isoformat()

popular_repo = set()
for repo in new_repo:
    star = g.get_repo(repo).stargazers_count
    if star >= 100:
        popular_repo.add(repo)

print(f"total: {len(github_repos)}, new: {len(new_repo)}, popular: {len(popular_repo)}")
with open("commit_date", "w") as f:
    json.dump(time_dict, f, indent=4)
