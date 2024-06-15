from util import Node, child_by_type_name, children_by_type_name, parser


class Package:
    def __init__(self, source_code: str):
        self.source_code = source_code
        self.tree = parser.parse(self.source_code.encode())
        self.name = child_by_type_name(child_by_type_name(
            self.tree.root_node, "package_declaration"), "scoped_identifier").text.decode()
        class_declarations = children_by_type_name(self.tree.root_node, "class_declaration")
        self.classes: list[Class] = [Class(class_declaration, self)
                                     for class_declaration in class_declarations]


class Class:
    def __init__(self, class_declaration: Node, package: Package):
        self.name: str = class_declaration.child_by_field_name("name").text.decode()
        self.qualified_name: str = package.name + "." + self.name
        self.package: Package = package
        self.start_line: int = class_declaration.start_point[0] + 1
        self.end_line: int = class_declaration.end_point[0] + 1
        self.source_code: str = class_declaration.text.decode()

        class_body = class_declaration.child_by_field_name("body")
        self.body_start_line: int = class_body.start_point[0] + 1
        self.body_end_line: int = class_body.end_point[0] + 1

        method_declarations = children_by_type_name(class_body, "method_declaration")
        self.methods: list[Method] = [Method(method_declaration, self)
                                      for method_declaration in method_declarations]


class Method:
    def __init__(self, method_declaration: Node, clazz: Class):
        self.name: str = method_declaration.child_by_field_name("name").text.decode()
        self.clazz: Class = clazz
        self.package: Package = clazz.package
        self.source_code: str = method_declaration.text.decode()
        self.start_line: int = method_declaration.start_point[0] + 1
        self.end_line: int = method_declaration.end_point[0] + 1

        parameters = children_by_type_name(
            method_declaration.child_by_field_name("parameters"), "formal_parameter")
        parameters_type_list = [parameter.child_by_field_name(
            "type").text.decode() for parameter in parameters]
        self.signature: str = clazz.qualified_name + "." + \
            self.name + "(" + ",".join(parameters_type_list) + ")"

        body = method_declaration.child_by_field_name("body")
        if body == None:
            self.body_source_code: str = ""
            self.body_start_line: int = 0
            self.body_end_line: int = 0
            return
        self.body_source_code: str = body.text.decode()
        self.body_start_line: int = body.start_point[0] + 1
        self.body_end_line: int = body.end_point[0] + 1
