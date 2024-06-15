def _find_cycle(graph):
    visited = set()
    recursion_stack = set()
    cycle_nodes = set()

    def dfs(node):
        nonlocal cycle_nodes
        visited.add(node)
        recursion_stack.add(node)

        for neighbor in graph.get(node, []):
            if neighbor not in visited:
                if dfs(neighbor):
                    return True
            elif neighbor in recursion_stack:
                # If the neighbor is already in the recursion stack, a cycle is detected
                cycle_nodes.add((node, neighbor))
                return True

        recursion_stack.remove(node)
        return False

    # Loop through all nodes in the graph to check for cycles
    for node in graph:
        if node not in visited:

            if dfs(node):
                return cycle_nodes

    # If no cycle is detected
    return set()

def cleanCycle(nods_edges_cycle):

    if_edge = False
    for nodes, nodes_depenent in nods_edges_cycle.items():
        if any(nodes_depenent): if_edge = True
    if not if_edge: return nods_edges_cycle

    while(True):
        nods_edges_cycle = dict(sorted(nods_edges_cycle.items(), key=lambda x: x[0], reverse=False))
        cycle_nodes = _find_cycle(nods_edges_cycle)
        if cycle_nodes:
            max_cycle_line = list(cycle_nodes)[-1][0]
            back_cycle_line = list(cycle_nodes)[-1][1]
            nods_edges_cycle[max_cycle_line].remove(back_cycle_line)
        else:
            break
    keys_to_remove = [key for key, value in nods_edges_cycle.items() if not value]
    for key in keys_to_remove:
        del nods_edges_cycle[key]
    return nods_edges_cycle

def cleanHead(pdgMap, startLine, modifiedLines, localFilePath):

    for modifiedLine in modifiedLines:
        if str(startLine) in list(modifiedLine.keys()):
            return pdgMap

    if list(pdgMap.keys()) == [startLine]:
        return {_:{} for _ in list(pdgMap[startLine])}
    # if startline in pdgmap's key or value, delete it
    pdgMapNocycleNohead = pdgMap.copy()
    pdgMapNocycleNohead.pop(startLine, None)
    for key, value in pdgMapNocycleNohead.items():
        if startLine in value:
            value.remove(startLine)
            

    if extractLineContent(localFilePath, startLine).startswith("@") and list(pdgMapNocycleNohead.keys()) != [startLine + 1]:
        pdgMapNocycleNohead.pop(startLine + 1, None)
        for key, value in pdgMapNocycleNohead.items():
            if startLine + 1 in value:
                value.remove(startLine + 1)        
    return pdgMapNocycleNohead

def extractLineContent(localFilePath, lineNumber):

    with open(localFilePath, 'r') as file:
        lines = file.readlines()
        line_content = lines[int(lineNumber) - 1].strip()
    return line_content

if __name__ == "__main__":
    nods_edges = {563: {529}, 531: {552, 532}, 532: {529, 556, 551}, 535: {536, 529, 538}, 536: set(), 538: {529, 545}, 539: {544, 529, 540}, 540: {529}, 543: {544, 529}, 544: {552, 546, 547}, 545: {529, 546, 547}, 550: {529, 551}, 556: {529, 563, 557}, 557: {529}, 551: {552, 529, 556}, 552: set(), 546: {547}, 547: {552, 546}, 529: {544, 545, 546, 547, 550, 551, 552, 556, 557, 563, 535, 536, 538, 539, 540, 543}}
    nods_edges_nocycle = cleanCycle(nods_edges)