import AstParser
from tree_sitter import Node
from AstParser import ASTParser
import os

class JarProject:
    def __init__(self, project_root_path: str):
        self.files: list[File] = []
        self.files_list: set[str] = set()
        self.classes_list: set[str] = set()
        self.methods_list: set[str] = set()
        self.fields_list: set[str] = set()
        self.class_methods_lines: dict[tuple] = {}
        
        java_files = []
        for root, dirs, files in os.walk(project_root_path):
            for file in files:
                if file.endswith('.java'):
                    java_files.append(os.path.join(root, file))
        
        for java_file in java_files:
            file = File(java_file, open(java_file, 'r').read(), self)
            # try:
            #     file = File(java_file, open(java_file, 'r').read(), self)
            # except Exception as e:
            #     continue
            self.files.append(file)
            self.files_list.add(java_file)
            self.classes_list.update([clazz.fullname for clazz in file.classes])
            self.methods_list.update([method.signature for clazz in file.classes for method in clazz.methods])
            rel_filepath = os.path.relpath(java_file, project_root_path)
            for clazz in file.classes:
                for method in clazz.methods:
                    self.class_methods_lines.update({
                        rel_filepath + "__split__" + clazz.name + "__split__" + method.name + "__split__" + method.signature: (method.start_line, method.end_line)
                    })

            self.fields_list.update([field.signature for clazz in file.classes for field in clazz.fields])
        print(f"✅Jar{project_root_path}")

class File:
    def __init__(self, path: str, content: str, project: JarProject):
        parser = ASTParser(content)
        self.project = project
        self.parser = parser
        self.path = path
        self.code = content
        package = parser.query_oneshot(AstParser.TS_QUERY_PACKAGE)
        self.package = package.text.decode() if package is not None else "<NONE>"
        self.imports = [import_node[0].text.decode() for import_node in parser.query(AstParser.TS_IMPORT)]
        self.classes = [Class(class_node[0], self) for class_node in parser.query(AstParser.TS_CLASS)]
        self.methods = [method for clazz in self.classes for method in clazz.methods]
        self.fields = [field for clazz in self.classes for field in clazz.fields]

class Class:
    def __init__(self, node: Node, file: File):
        self.code = node.text.decode()
        parser = file.parser
        self.name = node.child_by_field_name("name").text.decode()
        self.fullname = f"{file.package}.{self.name}"
        self.file = file
        self.fields = [Field(field_node[0], self, file)
                       for field_node in parser.query(AstParser.TS_FIELD) if
                       field_node[0].parent.type == "class_body" and
                       field_node[0].parent.parent.child_by_field_name("name") is not None and
                       field_node[0].parent.parent.child_by_field_name("name").text.decode() == self.name]
        self.methods = [Method(method_node[0], self, file)
                        for method_node in parser.query(AstParser.TS_METHOD) if
                        method_node[0].parent.type == "class_body" and
                        method_node[0].parent.parent.child_by_field_name("name") is not None and
                        method_node[0].parent.parent.child_by_field_name("name").text.decode() == self.name]

class Field:
    def __init__(self, node: Node, clazz: Class, file: File):
        # nodes = node.child_by_field_name("declarator")
        # nodes_name = nodes.child_by_field_name("name")
        self.name = node.child_by_field_name("declarator").child_by_field_name("name").text.decode()
        self.clazz = clazz
        self.file = file
        self.code = node.text.decode()
        self.signature = f"{self.clazz.fullname}.{self.name}"

class Method:
    def __init__(self, node: Node, clazz: Class, file: File):
        self.name = node.child_by_field_name("name").text.decode()
        self.fullname = f"{clazz.fullname}.{self.name}"
        self.clazz = clazz
        self.file = file
        self.code = node.text.decode()
        self.node = node

        parameters = ASTParser.children_by_type_name(node.child_by_field_name("parameters"), "formal_parameter")
        parameter_signature = ",".join([param.child_by_field_name("type").text.decode() for param in parameters])
        parameter_name = ",".join([param.child_by_field_name("name").text.decode() for param in parameters])
        self.signature = f"{self.clazz.fullname}.{self.name}({parameter_name})"
        self.start_line = node.start_point[0] + 1
        self.end_line = node.end_point[0] + 1
        self.lines: dict[int, str] = {i + self.start_line: line for i, line in enumerate(self.code.split("\n"))}

        if node.child_by_field_name("body") is None:
            self.body_start_line = self.start_line
            self.body_end_line = self.end_line
        else:
            self.body_start_line = node.child_by_field_name("body").start_point[0] + 1
            self.body_end_line = node.child_by_field_name("body").end_point[0] + 1


if __name__ == "__main__":
    jarproject = JarProject("/2.methodology/jar_statement_locate/../../4.jar/jarDecompile/io.netty-netty-codec-http/netty-codec-http-4.1.102.Final")
    print(jarproject.class_methods_lines)