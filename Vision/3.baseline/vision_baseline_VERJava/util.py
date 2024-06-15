import tree_sitter_java as tsjava
from tree_sitter import Language, Node, Parser

parser = Parser(Language(tsjava.language()))


def children_by_type_name(node: Node, type: str) -> list[Node]:
    node_list = []
    for child in node.named_children:
        if child.type == type:
            node_list.append(child)
    return node_list


def child_by_type_name(node: Node, type: str) -> Node | None:
    for child in node.named_children:
        if child.type == type:
            return child
    return None
