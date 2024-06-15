import re

from git import Commit as GitCommit
from git import Diff, Repo


class Commit:
    def __init__(self, repo_path: str, commit_id: str):
        self.repo_path = repo_path
        self.repo = Repo(self.repo_path)
        self.commit_id = commit_id
        self.commit: GitCommit = self.repo.commit(self.commit_id)
        self.diff = self.commit.parents[0].diff(self.commit, create_patch=True)
        self.blobs: list[Blob] = [
            Blob(blob) for blob in self.diff
            if (blob.a_path is not None and blob.a_path.endswith(".java")) or
            (blob.b_path is not None and blob.b_path.endswith(".java"))
        ]


class Hunk:
    def __init__(self, hunk_content: str):
        first_lf = hunk_content.find("\n")
        self.hunk_header = hunk_content[:first_lf + 1]
        self.hunk_content = hunk_content[first_lf + 1:]
        self.a_start_line = 0
        self.a_num_lines = 0
        self.b_start_line = 0
        self.b_num_lines = 0
        self.added_lines: dict[int, str] = {}
        self.deleted_lines: dict[int, str] = {}

        lineinfo = re.match(
            r"@@ -(\d+),(\d+) \+(\d+),(\d+) @@", hunk_content).groups()
        for num in lineinfo:
            self.a_start_line = int(lineinfo[0])
            self.a_num_lines = int(lineinfo[1])
            self.b_start_line = int(lineinfo[2])
            self.b_num_lines = int(lineinfo[3])

        hunk_content_lines = self.hunk_content.split("\n")
        index = 0
        for i, line in enumerate(hunk_content_lines):
            if line.startswith("-"):
                self.deleted_lines[self.a_start_line + index] = line[1:]
            if not line.startswith("+"):
                index += 1
        index = 0
        for i, line in enumerate(hunk_content_lines):
            if line.startswith("+"):
                self.added_lines[self.b_start_line + index] = line[1:]
            if not line.startswith("-"):
                index += 1

    @staticmethod
    def parse_hunks(diff: str):
        hunks_content: list[str] = []
        iter = re.finditer(r"@@.*?@@", diff)
        indices = [m.start(0) for m in iter]
        for i, v in enumerate(indices):
            if i == len(indices) - 1:
                hunks_content.append(diff[v:])
            else:
                hunks_content.append(diff[v:indices[i + 1]])
        hunks: list[Hunk] = []
        for hc in hunks_content:
            hunk = Hunk(hc)
            hunks.append(hunk)
        return hunks


class Blob:
    def __init__(self, blob: Diff):
        self.a_path = blob.a_path
        self.b_path = blob.b_path
        self.change_type = blob.change_type
        self.a_blob_content: str = blob.a_blob.data_stream.read().decode("utf-8") if self.a_path is not None else None
        self.b_blob_content: str = blob.b_blob.data_stream.read().decode("utf-8") if self.b_path is not None else None
        self.hunks: list[Hunk] = []

        if blob.a_path is not None and not blob.a_path.endswith(".java"):
            return None
        if blob.b_path is not None and not blob.b_path.endswith(".java"):
            return None

        if blob.a_path is None and blob.b_path is not None:
            self.change_type = "A"
        elif blob.a_path is not None and blob.b_path is None:
            self.change_type = "D"
        elif blob.a_path is not None and blob.b_path is not None and blob.a_path == blob.b_path:
            self.change_type = "C"
        elif blob.a_path is not None and blob.b_path is not None and blob.a_path != blob.b_path:
            self.change_type = "M"
        else:
            self.change_type = "U"

        if self.change_type == "M" or self.change_type == "C":
            self.hunks = Hunk.parse_hunks(blob.diff.decode("utf-8"))
