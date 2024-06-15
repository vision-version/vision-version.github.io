import argparse
import difflib
import json
import logging
import os
import subprocess
import time
from weight_locate import modified_line_map
import format
import hunkmap
import joern
import networkx as nx
import pandas as pd
import ppathf
import slicer

def slice(method: Method, pdg: PDG, role: str, method_dir: str, slice_level: int = 4):
    slice_result = slicer(method, pdg, level=slice_level)
    if slice_result is None:
        return
    pre_lines, rel_pre_lines, slice_nodes = slice_result
    g = nx.subgraph(pdg.g, [node.node_id for node in slice_nodes])
    os.makedirs(method_dir, exist_ok=True)
    nx.nx_agraph.write_dot(pdg.g, os.path.join(method_dir, f"{role}.dot"))
    nx.nx_agraph.write_dot(g, os.path.join(method_dir, f"{role}#{slice_level}.dot"))
    return pre_lines, rel_pre_lines

if __name__ == "__main__":
    slice()