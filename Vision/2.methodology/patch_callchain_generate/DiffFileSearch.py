from github import Github
import os
import git
from icecream import ic
from formatCode import methodNorm

def process_commit_changes(cve: str, repo_path, commit_hash: str, overwrite: bool):

    access_token = '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'
    g = Github(access_token)
    repo = git.Repo(repo_path)


    commit = repo.commit(commit_hash)
    commit_parent = commit.parents[0]
    diff = commit_parent.diff(commit)


    os.makedirs(f"./github_diff/{cve}", exist_ok=True)
    old_folder = os.path.join(f'./github_diff/{cve}/oldfiles')
    new_folder = os.path.join(f'./github_diff/{cve}/newfiles')
    os.makedirs(old_folder, exist_ok=True)
    os.makedirs(new_folder, exist_ok=True)

    os.system(f"rm -r ./github_diff/{cve}/oldfiles/*")
    os.system(f"rm -r ./github_diff/{cve}/newfiles/*")
    
    old_file_lst = []
    new_file_lst = []
    ic(os.getcwd())
    for change in diff:
        if (change.change_type == "D" or change.change_type == "M") and change.a_path.endswith(".java") and "test" not in change.a_path.lower():
            old_file_lst.append(change.a_path) 
            blob = commit_parent.tree / change.a_path
            normed_old_file_content = blob.data_stream.read().decode('utf-8')

            normed_old_file_content = methodNorm(normed_old_file_content)

            old_fp = f"./github_diff/{cve}/oldfiles/" + change.a_path.split("/")[-1]

            if not os.path.exists(old_fp) or overwrite:
                with open(old_fp, 'w') as file_old:
                    file_old.write(normed_old_file_content)
    

        if (change.change_type == "A"  or change.change_type == "M") and change.b_path.endswith(".java") and "test" not in change.b_path.lower():
            new_file_lst.append(change.b_path)  
            blob = commit.tree / change.b_path
            normed_new_file_content = blob.data_stream.read().decode('utf-8')

            normed_new_file_content = methodNorm(normed_new_file_content)

            new_fp = f"./github_diff/{cve}/newfiles/" + change.a_path.split("/")[-1]

            if not os.path.exists(new_fp) or overwrite:
                with open(new_fp, 'w') as file_old:
                    file_old.write(normed_new_file_content)
                    
        if change.change_type == "R" or change.change_type == "T" or change.change_type == "C":
            raise "Rename or Type change or Copy are not consider"
    return old_file_lst, new_file_lst


if __name__ == "__main__":
    repository_path = 'GithubCache/itext__split__itext7'
    commit_hash = '88c9cb7ec7befa096d83206419506ec5c7664912'
    process_commit_changes(repository_path, commit_hash)