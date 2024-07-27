import json
from datetime import datetime
from tqdm import tqdm

from github import Auth, Github

auth = Auth.Token("")
g = Github(auth=auth)

with open("github_tags_map.json") as f:
    github_tags_map = json.load(f)

github_repo_stars = {}
for repo in tqdm(github_tags_map):
    star = g.get_repo(repo).stargazers_count
    github_repo_stars[repo] = star

with open("repo_star_all.json", "w") as f:
    json.dump(github_repo_stars, f, indent=4)
