from typing import Generator


import common
import tree_sitter_c as tsc
import tree_sitter_cpp as tscpp
import tree_sitter_java as tsjava
from tree_sitter import Language, Node, Parser

TS_JAVA_PACKAGE = "(package_declaration (scoped_identifier) @package)(package_declaration (identifier) @package)"
TS_JAVA_IMPORT = "(import_declaration (scoped_identifier) @import)"
TS_JAVA_CLASS = "(class_declaration) @class"
TS_JAVA_FIELD = "(field_declaration) @field"
TS_C_INCLUDE = "(preproc_include (system_lib_string)@string_content)(preproc_include (string_literal)@string_content)"
TS_C_METHOD = "(function_definition)@method"
TS_COND_STAT = "(if_statement)@name (while_statement)@name (for_statement)@name"
TS_ASSIGN_STAT = "(assignment_expression)@name"
TS_JAVA_METHOD = "(method_declaration) @method (constructor_declaration) @method"
TS_METHODNAME = "(method_declaration 	(identifier)@id)(constructor_declaration 	(identifier)@id)"
TS_FPARAM = "(formal_parameters)@name"
CPP_CALL = '''
(call_expression (identifier)@name)(call_expression (field_expression)@name)
'''
CPP_INCLUDE = '''
(preproc_include
  path: (string_literal
    (string_content)@incude
  )
)
'''

class ASTParser:
    def __init__(self, code: str | bytes, language: common.Language | int):
        if language == common.Language.C:
            self.LANGUAGE = Language(tsc.language())
        elif language == common.Language.CPP:
            self.LANGUAGE = Language(tscpp.language())
        elif language == common.Language.JAVA:
            self.LANGUAGE = Language(tsjava.language())
        else:
            self.LANGUAGE = Language(tsc.language())
        self.parser = Parser(self.LANGUAGE)
        if isinstance(code, str):
            self.tree = self.parser.parse(bytes(code, "utf-8"))
        elif isinstance(code, bytes):
            self.tree = self.parser.parse(code)
        else:
            print(code)
        self.root = self.tree.root_node

    @staticmethod
    def children_by_type_name(node: Node, type: str) -> list[Node]:
        node_list = []
        for child in node.named_children:
            if child.type == type:
                node_list.append(child)
        return node_list

    @staticmethod
    def child_by_type_name(node: Node, type: str) -> Node | None:
        for child in node.named_children:
            if child.type == type:
                return child
        return None

    def traverse_tree(self) -> Generator[Node, None, None]:
        cursor = self.tree.walk()
        visited_children = False
        while True:
            if not visited_children:
                assert cursor.node is not None
                yield cursor.node
                if not cursor.goto_first_child():
                    visited_children = True
            elif cursor.goto_next_sibling():
                visited_children = False
            elif not cursor.goto_parent():
                break

    def query(self, query_str: str, *, node: Node | None = None) -> dict[str, list[Node]]:
        query = self.LANGUAGE.query(query_str)
        if node is not None:
            captures = query.captures(node)
        else:
            captures = query.captures(self.root)
        return captures

    def query_oneshot(self, query_str: str, *, node: Node | None = None) -> Node | None:
        captures = self.query(query_str, node=node)
        for nodes in captures.values():
            return nodes[0]
        return None

    def query_all(self, query_str: str, *, node: Node | None = None) -> list[Node]:
        captures = self.query(query_str, node=node)
        results = []
        for nodes in captures.values():
            results.extend(nodes)
        return results

    def query_by_capture_name(self, query_str: str, capture_name: str, *, node: Node | None = None) -> list[Node]:
        captures = self.query(query_str, node=node)
        return captures.get(capture_name, [])

    def get_error_nodes(self, *, node: Node | None = None) -> list[Node]:
        query_str = """
        (ERROR)@error
        """
        return self.query_by_capture_name(query_str, "error", node=node)

    def get_all_identifier_node(self) -> list[Node]:
        query_str = """
        (identifier)@id
        """
        return self.query_by_capture_name(query_str, "id")

    def get_all_conditional_node(self) -> list[Node]:
        query_str = TS_COND_STAT
        return self.query_by_capture_name(query_str, "name")

    def get_all_assign_node(self) -> list[Node]:
        query_str = """
        (assignment_expression)@name (declaration)@name
        """
        return self.query_by_capture_name(query_str, "name")

    def get_all_return_node(self) -> list[Node]:
        query_str = """
        (return_statement)@name
        """
        return self.query_by_capture_name(query_str, "name")

    def get_all_call_node(self) -> list[Node]:
        query_str = """
        (call_expression)@name
        """
        return self.query_by_capture_name(query_str, "name")

    def get_all_includes(self) -> list[Node]:
        if self.LANGUAGE == Language(tscpp.language()) or self.LANGUAGE == Language(tsc.language()):
            query_str = """
            (preproc_include)@name
            """
        else:
            query_str = """
            (import_declaration)@name
            """
        return self.query_by_capture_name(query_str, "name")
    

    
    def get_all_flow_control_goto(self) -> list[Node]:
        query_str = """
        (goto_statement)@label
            """
        return self.query_by_capture_name(query_str, "label")

    def get_all_flow_control_break(self) -> list[Node]:
        query_str = """
        ( break_statement)@name
            """
        return self.query_by_capture_name(query_str, "name")

    def get_all_flow_control(self) -> list[Node]:
        query_str = """
        ( continue_statement)@name
            """
        return self.query_by_capture_name(query_str, "name")


    def get_root(self):
        print(self.root.children)
        return self.root

if __name__ == "__main__":
    code = """
if (sbi->flags & NTFS_FLAGS_LOG_REPLAYG) {
return 123;
goto e;
}
if (1) {
return 1;
}
return 123;
"""

    ast = ASTParser(code, common.Language.C)
    root = ast.root

    query_str = """
    (if_statement
  consequence: (compound_statement
    [(goto_statement)
    (return_statement)]@jump.a
  )
)@if
    """
    res = ast.query_by_capture_name(query_str, "jump.a")
    if res is not None:
        print(res)
    else:
        print("None")
