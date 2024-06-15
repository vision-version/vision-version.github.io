from github import Github
import os
import git

GITDIFF_PATH = os.path.join(os.path.dirname(os.path.dirname(os.getcwd())), "patch_callchain_generate/github_diff")
print("Git diff path: ", GITDIFF_PATH)


def processCommitChanges(repo_path, commit_hash, branch):

    # DISCARD START
    access_token = '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'
    g = Github(access_token)
    repo = git.Repo(repo_path)

  
    commit = repo.commit(commit_hash)
    commit_parent = commit.parents[0]
    diff = commit_parent.diff(commit)


    old_folder = os.path.join(f'./{branch}PrePatchFile')
    new_folder = os.path.join(f'./{branch}PostPatchFile')

    os.makedirs(old_folder, exist_ok=True)
    os.makedirs(new_folder, exist_ok=True)

    old_file_lst = []
    new_file_lst = []

    for change in diff:
        if (change.change_type == "D" or change.change_type == "M") and change.a_path.endswith(".java") and "test" not in change.a_path.lower():
            old_file_lst.append(change.a_path)  
            blob = commit_parent.tree / change.a_path
            with open(f"./{old_folder}/" + change.a_path.split("/")[-1], 'wb') as file_old:
                file_old.write(blob.data_stream.read())

        if (change.change_type == "A"  or change.change_type == "M") and change.b_path.endswith(".java") and "test" not in change.b_path.lower():
            new_file_lst.append(change.b_path)
            blob = commit.tree / change.b_path
            with open(f"./{new_folder}/" + change.b_path.split("/")[-1], 'wb') as file_new:
                file_new.write(blob.data_stream.read())

        if change.change_type == "R" or change.change_type == "T" or change.change_type == "C":
            raise "Rename or Type change or Copy are not consider"
    return old_file_lst, new_file_lst

def commitRollback(self, localRepoPath, commitid):
    os.chdir(localRepoPath)
    os.system(f"git checkout {commitid}")
    
def sourtarCompare(cve: str, fileName: str):
    info = {
        "add": [],
        "delete": []
    }
    os.makedirs("diff_temp", exist_ok=True)
    os.system(
        "git diff " 
        + "--no-index "
        + f"{os.path.join(GITDIFF_PATH, f'{cve}/oldfiles/')}"
        + fileName
        + " "
        + f"{os.path.join(GITDIFF_PATH, f'{cve}/newfiles/')}"
        + fileName
        + " > "
        + "diff_temp/"
        + fileName
        + "__split__"
        + fileName
        + ".txt"
    )
    add_line = 0
    delete_line = 0
    commits = open(
        "diff_temp/" + fileName + "__split__" + fileName + ".txt", "r"
    )
    lines = commits.readlines()

    for line in lines:
        if line.startswith("@@"):
            # print(line)
            delete_line = int(line.split("-")[1].split(",")[0]) - 1
            add_line = int(line.split("+")[1].split(",")[0]) - 1
        elif line.startswith("+") and not line.startswith("+++"):
            add_line += 1
            info["add"].append(add_line)
        elif line.startswith("-") and not line.startswith("---"):
            delete_line += 1
            info["delete"].append(delete_line)
        else:
            add_line += 1
            delete_line += 1
    return info

def sourtarContextMap(cve, fileName, modifiedLines):
    with open(os.path.join(GITDIFF_PATH, f"{cve}/oldfiles/{fileName}"), 'r', encoding='utf-8') as file:
        targetLines = file.readlines()
        targetLinesNum = len(targetLines)
        i = 0 
        targetMap = {}
        for targetLine in range(1, targetLinesNum + 1):
            if targetLine not in modifiedLines["add"]:
                i += 1
                targetMap[targetLine] = i
    
    sourcetMap = {}
    with open(os.path.join(GITDIFF_PATH, f"{cve}/newfiles/{fileName}"), 'r', encoding='utf-8') as file:
        sourceLines = file.readlines()
        targetLinesNum = len(targetLines)
        j = 0
        for sourceLine in range(1, targetLinesNum + 1):
            if sourceLine not in modifiedLines["delete"]:
                j += 1
                sourcetMap[sourceLine] =  j
    return sourcetMap, targetMap


def sourtarDiffMap(sourceOldFileMap, targetOldFileMap, modifiedLines):
    delLinesGroup = group_consecutive_ints(modifiedLines["delete"])
    addLinesGroup = group_consecutive_ints(modifiedLines["add"])
    return delLinesGroup, addLinesGroup


def group_consecutive_ints(nums):
    if not nums:
        return []

    nums.sort() 

    result = [[nums[0]]]  

    for num in nums[1:]:
        if num == result[-1][-1] + 1:
            result[-1].append(num) 
        else:
            result.append([num])

    return result
if __name__ == "__main__":
    
 
    repository_path = 'GithubCache/Component_GithubCache/itext__split__itext7'
    commit_hash = '88c9cb7ec7befa096d83206419506ec5c7664912'
    processCommitChanges(repository_path, commit_hash)