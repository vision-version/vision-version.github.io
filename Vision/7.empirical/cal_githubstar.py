import json
from datetime import datetime

from github import Auth, Github

auth = Auth.Token("")
g = Github(auth=auth)

with open("versions_20240725.json") as f:
    versions = json.load(f)

github_repo_stars = {}
for cveid, meta in versions.items():
    owner = versions[cveid]["UsrName"]
    repo = versions[cveid]["PjName"]
    github_repo = f"{owner}/{repo}"
    star = g.get_repo(github_repo).stargazers_count
    github_repo_stars[github_repo] = star

with open("repo_star.json", "w") as f:
    json.dump(github_repo_stars, f, indent=4)
