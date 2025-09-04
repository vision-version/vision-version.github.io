import subprocess
import tempfile
from dataclasses import dataclass

from common import HunkType


def gitdiff(code1: str, code2: str, remove_diff_header: bool = False) -> str:
    tf1 = tempfile.NamedTemporaryFile()
    tf2 = tempfile.NamedTemporaryFile()
    tf1.write(code1.encode())
    tf2.write(code2.encode())
    tf1.flush()
    tf2.flush()
    diff = subprocess.run(
        ["git", "--no-pager", "diff", "--no-index", "-w", "-b", tf1.name, tf2.name],
        stdout=subprocess.PIPE,
    ).stdout.decode()
    if remove_diff_header:
        diff_lines = diff.splitlines()[4:]
        diff = "\n".join(diff_lines)
    return diff


@dataclass
class Hunk:
    type: HunkType


@dataclass
class ModHunk(Hunk):
    a_startline: int
    a_endline: int
    b_startline: int
    b_endline: int
    a_code: str
    b_code: str


@dataclass
class AddHunk(Hunk):
    b_startline: int
    b_endline: int
    b_code: str
    insert_line: int


@dataclass
class DelHunk(Hunk):
    a_startline: int
    a_endline: int
    a_code: str


def parse_gitdiff(diff: str) -> dict[str, list[int]]:
    info = {"add": [], "delete": []}
    add_line = 0
    delete_line = 0
    lines = diff.split("\n")

    for line in lines:
        if line.startswith("@@"):
            delete_line = int(line.split("-")[1].split(",")[0].split(" ")[0]) - 1
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


def sourtarContextMap(code_a: str, code_b: str, modifiedLines) -> tuple[dict, dict]:
    targetLines = code_b.split("\n")
    targetLinesNum = len(targetLines)
    i = 0
    targetMap = {}
    for targetLine in range(1, targetLinesNum + 1):
        if targetLine not in modifiedLines["add"]:
            i += 1
            targetMap[targetLine] = i

    sourcetMap = {}

    sourceLines = code_a.split("\n")
    sourceLinesNum = len(sourceLines)
    j = 0
    for sourceLine in range(1, sourceLinesNum + 1):
        if sourceLine not in modifiedLines["delete"]:
            j += 1
            sourcetMap[sourceLine] = j
    return sourcetMap, targetMap


def sourtarDiffMap(modifiedLines) -> tuple[list[list], list[list]]:
    def group_consecutive_ints(nums: list[int]):
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

    delLinesGroup = group_consecutive_ints(modifiedLines["delete"])
    addLinesGroup = group_consecutive_ints(modifiedLines["add"])
    return delLinesGroup, addLinesGroup


def method_linemap(mapA, mapB) -> dict[int, int]:
    map_result = {}
    for line, pivot in mapA.items():
        for k, v in mapB.items():
            if pivot == v:
                map_result[line] = k
    return map_result


def method_hunkmap(
    delLinesGroup: list[list[int]],
    addLinesGroup: list[list[int]],
    line_map: dict[int, int],
):
    hunk_map: dict[tuple[int, int], tuple[int, int]] = {}
    line_map[0] = 0
    for delLines in delLinesGroup:
        del_head = delLines[0] - 1
        del_tail = delLines[-1] + 1
        for addLines in addLinesGroup:
            add_head = addLines[0] - 1
            add_tail = addLines[-1] + 1
            if (
                del_head in line_map
                and del_tail in line_map
                and line_map[del_head] == add_head
                and line_map[del_tail] == add_tail
            ):
                hunk_map[(del_head + 1, del_tail - 1)] = (add_head + 1, add_tail - 1)
                continue
    return hunk_map


def get_patch_hunks(code1: str, code2: str) -> list[Hunk]:
    code1_lines = code1.split("\n")
    code2_lines = code2.split("\n")
    diff = gitdiff(code1, code2)
    modifiedLines = parse_gitdiff(diff)
    sourceOldFileMap, targetOldFileMap = sourtarContextMap(code1, code2, modifiedLines)
    delLinesGroup, addLinesGroup = sourtarDiffMap(modifiedLines)
    line_map = method_linemap(sourceOldFileMap, targetOldFileMap)
    modify_hunks_map = method_hunkmap(delLinesGroup, addLinesGroup, line_map)
    r_line_map = {v: k for k, v in line_map.items()}
    hunk_list: list[Hunk] = []
    for a_hunk, b_hunk in modify_hunks_map.items():
        hunk = ModHunk(
            HunkType.MOD,
            a_hunk[0],
            a_hunk[1],
            b_hunk[0],
            b_hunk[1],
            "\n".join(code1_lines[a_hunk[0] - 1 : a_hunk[1]]),
            "\n".join(code2_lines[b_hunk[0] - 1 : b_hunk[1]]),
        )
        hunk_list.append(hunk)
    for add_hunk in addLinesGroup:
        first_line, last_line = add_hunk[0], add_hunk[-1]
        if (first_line, last_line) not in modify_hunks_map.values():
            insert_line = r_line_map[first_line - 1]
            hunk_list.append(
                AddHunk(
                    HunkType.ADD,
                    first_line,
                    last_line,
                    "\n".join(code2_lines[first_line - 1 : last_line]),
                    insert_line,
                )
            )
    for del_hunk in delLinesGroup:
        first_line, last_line = del_hunk[0], del_hunk[-1]
        if (first_line, last_line) not in modify_hunks_map.keys():
            hunk_list.append(
                DelHunk(
                    HunkType.DEL,
                    first_line,
                    last_line,
                    "\n".join(code1_lines[first_line - 1 : last_line]),
                )
            )
    return hunk_list
