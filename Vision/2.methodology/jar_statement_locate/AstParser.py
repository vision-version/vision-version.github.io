from tree_sitter import Language, Parser, Node

Language.build_library(
    # Store the library in the `build` directory
    "build/languages.so",
    # Include one or more languages
    [
        # "../../5.tool/tree-sitter-java",
        "/5.tool/tree-sitter-java", 
    ],
)

TS_QUERY_PACKAGE = "(package_declaration (scoped_identifier) @package)(package_declaration (identifier) @package)"
TS_IMPORT = "(import_declaration (scoped_identifier) @import)"
TS_CLASS = "(class_declaration) @class"
TS_FIELD = "(field_declaration) @field"
TS_METHOD = "(method_declaration) @method (constructor_declaration) @method"

class ASTParser:
    def __init__(self, code: str):
        self.JAVA_LANGUAGE = Language("build/languages.so", "java")
        self.parser = Parser()
        self.parser.set_language(self.JAVA_LANGUAGE)
        self.root = self.parser.parse(bytes(code, "utf-8")).root_node

    @staticmethod
    def children_by_type_name(node: Node, target_type: str):
        node_list = []
        for child in node.named_children:
            if child.type == target_type:
                node_list.append(child)
        return node_list

    @staticmethod
    def child_by_type_name(node: Node, type: str):
        for child in node.named_children:
            if child.type == type:
                return child
        return None

    def query_oneshot(self, query_str: str):
        query = self.JAVA_LANGUAGE.query(query_str)
        captures = query.captures(self.root)
        result = None
        for capture in captures:
            result = capture[0]
            break
        return result

    def query(self, query_str: str):
        query = self.JAVA_LANGUAGE.query(query_str)
        captures = query.captures(self.root)
        return captures


if __name__ == "__main__":
    code = """
    package Tika;

import java.io.File;
import java.io.IOException;
import java.net.URL;

import org.apache.tika.exception.TikaException;
    """

    query_str = """
    (package_declaration (scoped_identifier) @package)
    (package_declaration (identifier) @package)
    """

    res = ASTParser(code).query_oneshot(query_str)
    if res is not None:
        print(res.text.decode())
    else:
        print("None")