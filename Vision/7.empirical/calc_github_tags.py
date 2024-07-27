import json

import cpu_heater
from github import Auth, Github
from tqdm import tqdm
import random


TOKEN_LIST = [
]


def github_pool():
    pool = []
    for token in TOKEN_LIST:
        auth = Auth.Token(token)
        pool.append(Github(auth=auth))
    return pool


github_pool: list = github_pool()

with open("sim_patch.json") as f:
    data: dict[str, dict] = json.load(f)

cve_github_map = {}
for cveid, patch_urls in data.items():
    github_commit_url: str = list(patch_urls.keys())[0]
    owner = github_commit_url.split("/")[3]
    repo = github_commit_url.split("/")[4]
    cve_github_map[cveid] = f"{owner}/{repo}"
with open("cve_github_map.json", "w") as f:
    json.dump(cve_github_map, f, indent=4)


def tag_worker(cveid: str, github_repo: str):
    # random github in pool
    g = random.choice(github_pool)
    repo = g.get_repo(github_repo)
    tags = [tag.name for tag in repo.get_tags()]
    return cveid, tags


cve_tags = {}
tag_worker_args = []
for cveid, github_repo in cve_github_map.items():
    tag_worker_args.append((cveid, github_repo))
results = cpu_heater.multithreads(tag_worker_args, tag_worker, 5, True)
for cveid, tags in results:
    cve_tags[cveid] = tags

with open("cve_tags.json", "w") as f:
    json.dump(cve_tags, f, indent=4)
