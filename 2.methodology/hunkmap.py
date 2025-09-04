import logging

import Levenshtein
import utils

import difftools
from project import Method


def sourtarDiffMap(modifiedLines) -> tuple[list[list], list[list]]:
    delLinesGroup = utils.group_consecutive_ints(modifiedLines["delete"])
    addLinesGroup = utils.group_consecutive_ints(modifiedLines["add"])
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


def method_map(a_method: Method, b_method: Method, sim_thres: float | None = None):
    diff = difftools.git_diff_code(a_method.code, b_method.code)
    modifiedLines = difftools.parse_diff(diff)
    sourceOldFileMap, targetOldFileMap = difftools.sourtarContextMap(
        a_method.code, b_method.code, modifiedLines
    )
    delLinesGroup, addLinesGroup = sourtarDiffMap(modifiedLines)
    line_map = method_linemap(sourceOldFileMap, targetOldFileMap)
    hunk_map = method_hunkmap(delLinesGroup, addLinesGroup, line_map)

    diff_add_lines: set[int] = set()
    for add_line in modifiedLines["add"]:
        for hunk_start, hunk_end in hunk_map.keys():
            if hunk_start <= add_line <= hunk_end:
                break
        else:
            diff_add_lines.add(add_line)

    diff_del_lines: set[int] = set()
    for del_line in modifiedLines["delete"]:
        for hunk_start, hunk_end in hunk_map.values():
            if hunk_start <= del_line <= hunk_end:
                break
        else:
            diff_del_lines.add(del_line)

    if sim_thres is not None:
        for a_hunk, b_hunk in hunk_map.items():
            tmp_map_set = set()
            for a_line in range(a_hunk[0], a_hunk[1] + 1):
                a_code = a_method.rel_lines[a_line].strip()
                similarity = 0
                sim_line = 0
                for b_line in range(b_hunk[0], b_hunk[1] + 1):
                    if b_line in tmp_map_set:
                        continue
                    b_code = b_method.rel_lines[b_line].strip()
                    ratio = Levenshtein.ratio(a_code, b_code)
                    if ratio > similarity:
                        similarity = ratio
                        sim_line = b_line
                if similarity >= sim_thres:
                    line_map[a_line] = sim_line
                    tmp_map_set.add(sim_line)
    return line_map, hunk_map, diff_add_lines, diff_del_lines


def code_map(a_code: str, b_code: str):
    diff = difftools.git_diff_code(a_code, b_code)
    modifiedLines = difftools.parse_diff(diff)
    sourceOldFileMap, targetOldFileMap = difftools.sourtarContextMap(
        a_code, b_code, modifiedLines
    )
    delLinesGroup, addLinesGroup = sourtarDiffMap(modifiedLines)
    line_map = method_linemap(sourceOldFileMap, targetOldFileMap)
    hunk_map = method_hunkmap(delLinesGroup, addLinesGroup, line_map)

    diff_add_lines: set[int] = set()
    for add_line in modifiedLines["add"]:
        for hunk_start, hunk_end in hunk_map.keys():
            if hunk_start <= add_line <= hunk_end:
                break
        else:
            diff_add_lines.add(add_line)

    diff_del_lines: set[int] = set()
    for del_line in modifiedLines["delete"]:
        for hunk_start, hunk_end in hunk_map.values():
            if hunk_start <= del_line <= hunk_end:
                break
        else:
            diff_del_lines.add(del_line)
    return line_map, hunk_map, diff_add_lines, diff_del_lines
