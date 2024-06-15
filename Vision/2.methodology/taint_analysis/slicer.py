import logging
import sys
from collections import deque
from difflib import SequenceMatcher

from ast_parser import ASTParser
from joern import PDG, PDGNode
from project import Method
from tree_sitter import Node


def backward_slice(criteria_lines: set[int], criteria_nodes: list[PDGNode], criteria_identifier: set[str], all_nodes: dict[int, list[PDGNode]], level: int = 2) -> tuple[set[int], list[PDGNode]]:
    result_lines = criteria_lines.copy()
    result_nodes = criteria_nodes.copy()

    # CFG slice
    for slice_line in criteria_lines:
        for node in all_nodes[slice_line]:
            if node.type == "METHOD_RETURN":
                continue
            for pred_node in node.pred_cfg_nodes:
                if pred_node.line_number is None or int(pred_node.line_number) == sys.maxsize:
                    continue
                result_lines.add(int(pred_node.line_number))
                result_nodes.append(pred_node)

    # DDG slice
    for sline in criteria_lines:
        for node in all_nodes[sline]:
            if node.type in ["METHOD_RETURN"]:
                continue
            visited = set()
            queue = deque([(node, 0)])
            while queue:
                node, depth = queue.popleft()
                if node not in visited:
                    visited.add(node)
                    if node not in result_nodes:
                        result_nodes.append(node)
                    if node.line_number is not None:
                        result_lines.add(node.line_number)
                    if depth < level:
                        for pred_node, edge in node.pred_ddg:
                            if pred_node.line_number is None or int(pred_node.line_number) == sys.maxsize:
                                continue
                            if edge not in node.code or edge not in criteria_identifier:
                                continue
                            queue.append((pred_node, depth + 1))  # type: ignore

    return result_lines, result_nodes


def forward_slice(criteria_lines: set[int], criteria_nodes: list[PDGNode], criteria_identifier: set[str],
                  all_nodes: dict[int, list[PDGNode]], level: int = 2) -> tuple[set[int], list[PDGNode]]:
    result_lines = criteria_lines.copy()
    result_nodes = criteria_nodes.copy()

    # CFG slice
    for slice_line in criteria_lines:
        for node in all_nodes[slice_line]:
            if node.type == "METHOD_RETURN":
                continue
            if node.line_number is None:
                continue
            for succ_node in node.succ_cfg_nodes:
                if succ_node.line_number is None or int(succ_node.line_number) == sys.maxsize:
                    continue
                if succ_node.line_number < node.line_number:
                    continue  # Prevent cyclic dependencies
                result_lines.add(int(succ_node.line_number))
                result_nodes.append(succ_node)

    # DDG slice
    for sline in criteria_lines:
        for node in all_nodes[sline]:
            if node.type in ["METHOD", "PARAM"]:
                continue
            visited = set()
            queue = deque([(node, 0)])
            while queue:
                node, depth = queue.popleft()
                if node not in visited:
                    visited.add(node)
                    if node not in result_nodes:
                        result_nodes.append(node)
                    if node.line_number is not None:
                        result_lines.add(node.line_number)
                    if depth < level:
                        for succ_node, edge in node.succ_ddg:
                            if edge not in node.code or edge not in criteria_identifier:
                                continue
                            queue.append((succ_node, depth + 1))  # type: ignore

    return result_lines, result_nodes


def method_slice(method: Method, pdg: PDG, level: int = 4):
    backward_slice_level = level
    forward_slice_level = 1
    logging.info(f"Slice Method: {method.signature}")
    logging.info(f"Slice depth backward: {backward_slice_level}, forward: {forward_slice_level}")

    all_lines = set(method.lines.keys())
    all_nodes: dict[int, list[PDGNode]] = {
        line: pdg.get_nodes_by_line_number(line) for line in all_lines
    }
    criteria_lines = set(method.deleted_lines | method.added_lines)
    logging.info(f"Slice benchmark line: {sorted(criteria_lines)}")
    criteria_nodes: list[PDGNode] = []
    for line in criteria_lines:
        for node in pdg.get_nodes_by_line_number(line):
            node.is_patch_node = True
            node.add_attr("color", "red")
            criteria_nodes.append(node)

    slice_result_lines = set(criteria_lines)
    slice_result_lines |= method.header_lines
    slice_result_lines.add(method.end_line)

    # Calculate criteria_identifier
    assert method.counterpart is not None
    criteria_identifier_a = set(method.identifier_by_lines(criteria_lines))