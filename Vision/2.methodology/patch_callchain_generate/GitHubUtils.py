import os
import json
from git import Repo
from multiprocessing import Pool
from DescNodeReg.reportFaksNode import text2sourceevidence


class RepoDataLoader():
    '''
    1. clone repo
    2. update repo
    '''
    def __init__(self, metainfo_path):
        self.cve_metainto_path = metainfo_path
        self.local_repo_path = "GithubCache"

    def repo_clone(self):
        '''
        clone repo from github, record repo path and patch path
        '''
        meta_info = {}
        with open(self.cve_metainto_path, "r") as fr:
            patch_file = json.load(fr)
        
        owners = []
        repos = []
        urls = []
        for cve, patch_dict in patch_file.items():
            patch = patch_dict['patch']
            owner, repo = patch.split("/")[3:5]
            owners.append(owner)
            repos.append(repo)
            # ssh
            # urls.append(f"git@github.com:{owner}/{repo}.git")
            # http
            urls.append(f"https://github.com/{owner}/{repo}.git")

            # urls.append(f"https://gitclone.com/github.com/{owner}/{repo}.git")
            meta_info[cve] = {
                "patch": patch,
                "local_repo": os.path.join(self.local_repo_path, owner + "__split__" + repo)
            }

        oru = list(zip(owners, repos, urls))

        with Pool(10) as pool:
 
            pool.starmap(self.clone_or_update_repo, oru)
        return meta_info

    def clone_or_update_repo(self, owner, repo, repo_url):
        repo_folder = owner + "__split__" + repo
        local_clone_place = os.path.join(self.local_repo_path, repo_folder)
        if not os.path.exists(local_clone_place):
            print(f"{repo_url} to {local_clone_place}...")
            Repo.clone_from(repo_url, local_clone_place)

        else:
            pass

def get_commit_message(local_repo_path, commit_hash):
    repo = Repo(local_repo_path)
    commit = repo.commit(commit_hash)
    return commit.message



if __name__ == '__main__':
    repoDataLoader = RepoDataLoader(os.path.join(os.getcwd(), "cves_metainfo.json"))
    cve_patchs = repoDataLoader.repo_clone()
    
    with open("cves_metainfo.json", 'r') as f:
        cve_meta = json.load(f)
    commit_msg = get_commit_message(cve_meta['CVE-2022-29599']['local_repo'], 'f751e614c09df8de1a080dc1153931f3f68991c9')
    print(text2sourceevidence(commit_msg))

