import os
import re
import subprocess
import tempfile

import cpu_heater
from tree_sitter import Node

import ast_parser
from ast_parser import ASTParser
from common import Language
from format_code import format_and_del_comment_c_cpp

includeFiles = []
analysizedFiles = []
targetRepoMacros = "targetrepo_macros_cache/"
encoding_format = "ISO-8859-1"
CTAGS_PATH = ""


def operator_extraction(st, code: str, language: Language):
    arithmetic_operator = {"-=", "+=", "*=", "/=", "%=", "&=", "^=", ">>=", "<<=", "|="}
    binary_operator = {">=", "<="}
    Uniary_operator = {"!"}
    code_bytes = code.encode()
    query = (
        "(binary_expression)@name (unary_expression) @name (assignment_expression)@name"
    )
    while 1:
        parser = ASTParser(code_bytes.decode(), language)
        nodes = parser.query_all(query)
        finished = True
        if len(nodes) >= 10000:
            break
        for node in nodes:
            op = node.child(1).text.decode()
            if op in arithmetic_operator:
                left = node.child(0).text.decode()
                right = node.child(2).text.decode()
                op1 = op.replace("=", "")
                if len(node.child(2).children) != 0:
                    new_express = f"{left}={left}{op1}({right})"
                else:
                    new_express = f"{left}={left}{op1}{right}"
                start_byte = node.start_byte
                end_byte = node.end_byte
                code_bytes = (
                    code_bytes[:start_byte]
                    + new_express.encode()
                    + code_bytes[end_byte:]
                )
                finished = False
                break
            elif op in binary_operator:
                left = node.child(0).text.decode()
                right = node.child(2).text.decode()
                op1 = op.replace("=", "")
                if len(node.child(2).children) != 0:
                    new_express = f"{left}{op1}({right}) || {left}==({right})"
                else:
                    new_express = f"{left}{op1}{right} || {left}=={right}"
                start_byte = node.start_byte
                end_byte = node.end_byte
                code_bytes = (
                    code_bytes[:start_byte]
                    + new_express.encode()
                    + code_bytes[end_byte:]
                )
                finished = False
                break
            else:
                op = node.child(0).text.decode()
                right = node.child(1).text.decode()
                if op in Uniary_operator:
                    new_express = f"{right}==0"
                    start_byte = node.start_byte
                    end_byte = node.end_byte
                    code_bytes = (
                        code_bytes[:start_byte]
                        + new_express.encode()
                        + code_bytes[end_byte:]
                    )
                    finished = False
                    break
        if finished:
            break

    return st, code_bytes.decode(), language


def del_DeadCode(st, code: str, language: Language):
    code_bytes = code.encode()

    while True:
        parser = ASTParser(code_bytes.decode(), language)
        nodes = parser.query_all(
            "(while_statement) @name (if_statement) @name (for_statement) @name"
        )
        finished = True
        for node in nodes:
            condition = node.child_by_field_name("condition")
            if condition is None:
                continue
            if (
                condition
                and condition.text.decode() == "(0)"
                or condition.text.decode() == "0"
            ):
                start_byte = node.start_byte
                end_byte = node.end_byte
                code_bytes = code_bytes[:start_byte] + code_bytes[end_byte:]
                finished = False
                break

        if finished:
            break

    return st, code_bytes.decode(), language


def while_for_transformation(st, code: str, language: Language):
    code_bytes = code.encode()
    do_while_replace = []

    while True:
        parser = ASTParser(code_bytes.decode(), language)
        nodes = parser.query_all("(for_statement) @name")
        finished = True
        if len(nodes) >= 1000:
            break
        for node in nodes:
            if node.type == "for_statement":
                init = node.child_by_field_name("initializer")
                condition = node.child_by_field_name("condition")
                increment = node.child_by_field_name("update")
                body = node.child_by_field_name("body")
                init_code = init.text.decode() if init is not None else ""
                condition_code = condition.text.decode() if condition is not None else 1
                increment_code = (
                    increment.text.decode() if increment is not None else ""
                )
                while_loop = f"{init_code}\nwhile ({condition_code}){{\n "
                while_loop += body.text.decode()[1:-1]
                while_loop += f"\n{increment_code};\n}}\n"
                start_byte = node.start_byte
                end_byte = node.end_byte
                code_bytes = (
                    code_bytes[:start_byte]
                    + while_loop.encode()
                    + code_bytes[end_byte:]
                )
                finished = False
                break
            else:
                continue

        if finished:
            break
    parser = ASTParser(code_bytes.decode(), language)
    nodes = parser.query_all("(do_statement) @name")
    finished = True
    if len(nodes) >= 1000:
        return st, code_bytes.decode(), language
    for node in nodes:
        condition = node.child_by_field_name("condition")
        body = node.child_by_field_name("body")
        if condition.text.decode() == "(0)":
            do_while_replace.append((body.text.decode()[1:-1], node.text.decode()))

    codes = code_bytes.decode()
    for target_body, origin_body in do_while_replace:
        codes = codes.replace(origin_body, target_body)

    return st, codes, language


def astyle(code: str) -> str:
    code = (
        subprocess.run(
            [
                "astyle",
                "--style=java",
                "--squeeze-ws",
                "--keep-one-line-statements",
                "--delete-empty-lines",
                "--max-code-length=200",
                "--delete-empty-lines",
            ],
            input=code.encode(),
            stdout=subprocess.PIPE,
        )
        .stdout.decode()
        .strip()
    )
    return code


def move_definition(st, code: str, language: Language):
    code_bytes = code.encode()
    query = "(compound_statement)@name"
    vis = set()
    while True:
        parser = ASTParser(code_bytes.decode(), language)
        nodes = parser.query_all(query)
        finished = True
        for node in nodes:
            start_byte = node.start_byte
            end_byte = node.end_byte
            if (start_byte, end_byte) in vis:
                continue
            vis.add((start_byte, end_byte))
            finished = False
            reconstruct_codes = rearrange_variables(node, code_bytes)

            code_bytes = (
                code_bytes[:start_byte] + reconstruct_codes + code_bytes[end_byte:]
            )
            break
        if finished:
            break

    return st, code_bytes.decode(), language


def rearrange_variables(node, code_bytes):
    declarations = []
    statements = []
    result = "".encode()
    for child in node.children:
        if child.type == "declaration" or child.type == "{":
            declarations.append(child)
        else:
            statements.append(child)

    new_children = declarations + statements
    for child in new_children:
        result += code_bytes[child.start_byte : child.end_byte] + "\n".encode()
    return result


def split_define_assign(st, code: str, language: Language):
    code_bytes = code.encode()
    query = "(declaration)@name"
    while True:
        parser = ASTParser(code_bytes.decode(), language)
        nodes = parser.query_all(query)
        finished = True
        for node in nodes:
            start_byte = node.start_byte
            end_byte = node.end_byte
            declarators = node.children_by_field_name("declarator")
            type_name = node.child_by_field_name("type").text.decode()
            identifiers_declaration = f"{type_name} "
            assignments = ""
            has_init = False
            for declarator in declarators:
                if declarator.type != "init_declarator":
                    identifiers_declaration += f"{declarator.text.decode()}, "
                    continue
                identifier = parser.query_all("(identifier)@name", node=declarator)[
                    0
                ].text.decode()
                left = declarator.child(0).text.decode()
                op = declarator.child(1).text.decode()
                right = declarator.child(2).text.decode()
                identifiers_declaration += f"{left}, "
                assignments += f"{identifier} {op} {right};\n"
                has_init = True
            if has_init:
                new_code = identifiers_declaration.strip()[:-1] + ";\n" + assignments
                code_bytes = (
                    code_bytes[:start_byte] + new_code.encode() + code_bytes[end_byte:]
                )
                finished = False
                break
        if finished:
            break

    return st, astyle(code_bytes.decode()), language


def code_transformation(codes: str, language: Language):
    parser = ASTParser(codes, language)
    nodes = parser.query_all(ast_parser.TS_C_METHOD)
    line_interval = []
    for node in nodes:
        line_interval.append((node.start_point[0], node.end_point[0]))

    length = len(codes.split("\n"))
    codes_interval = codes.split("\n")
    codes_split = []
    st_before, ed_before = 1, 1
    line_interval = sorted(line_interval)
    for st, ed in line_interval:
        if st_before != 1 and ed_before + 1 != st:
            codes_split.append(
                (ed_before + 1, "\n".join(codes_interval[ed_before + 1 : st]), language)
            )
        elif ed_before + 1 != st:
            codes_split.append(
                (ed_before - 1, "\n".join(codes_interval[ed_before - 1 : st]), language)
            )

        codes_split.append((st, "\n".join(codes_interval[st : ed + 1]), language))
        st_before = st
        ed_before = ed
    if ed_before < len(codes_interval):
        codes_split.append((ed_before, "\n".join(codes_interval[ed_before:]), language))
    results = cpu_heater.multithreads(
        del_DeadCode, codes_split, max_workers=1024, show_progress=False
    )
    results = cpu_heater.multithreads(
        while_for_transformation, results, max_workers=1024, show_progress=False
    )
    results = cpu_heater.multithreads(
        operator_extraction, results, max_workers=1024, show_progress=False
    )
    results = cpu_heater.multithreads(
        operator_extraction, results, max_workers=1024, show_progress=False
    )
    results = cpu_heater.multithreads(
        move_definition, results, max_workers=8192, show_progress=True
    )
    codes = ""
    results = sorted(results)
    for st, res, language in results:
        if res == "":
            continue
        codes += res + "\n"
    codes = astyle(codes)
    return codes


def abstract(code: str, language: Language):
    TS_LVAR = "(parameter_declaration)@name"
    TS_FPARAM = "(declaration)@name"
    TS_FUNCCALL = "(call_expression (identifier)@name)"
    TS_DTYPE = "(type_identifier)@name"
    TS_PRIMITIVE = "(primitive_type)@name"
    TS_STRING = "(string_literal)@name"
    lvars = {}
    fparams = {}
    fcalls = set()
    dtypes = set()
    parser = ASTParser(code, language)
    nodes = parser.query_all(TS_LVAR)
    strings = set()
    for node in nodes:
        type_names = parser.query_all(TS_PRIMITIVE, node=node)
        if len(type_names) == 1:
            type_name = type_names[0].text.decode()
        else:
            type_name = ""
        try:
            lv = parser.query_all("(identifier)@name", node=node)[0].text.decode()
        except:
            continue

        if type_name != "":
            k = node.text.decode().replace("const", "").replace(" ", "").rfind(lv)
            lvars[lv] = node.text.decode().replace("const", "").replace(" ", "")[:k]
        else:
            lvars[lv] = ""

    nodes = parser.query_all(TS_FPARAM)
    for node in nodes:
        type_names = parser.query_all(TS_PRIMITIVE, node=node)
        if len(type_names) == 1:
            type_name = type_names[0].text.decode()
        else:
            type_name = ""
        fp = parser.query_all("(identifier)@name", node=node)[0].text.decode()

        if type_name != "":
            k = node.text.decode().replace("const", "").replace(" ", "").rfind(fp)
            fparams[fp] = node.text.decode().replace("const", "").replace(" ", "")[:k]
        else:
            fparams[fp] = ""

    nodes = parser.query_all(TS_DTYPE)
    for node in nodes:
        dtypes.add(node.text.decode())

    nodes = parser.query_all(TS_FUNCCALL)
    for node in nodes:
        fcalls.add(node.text.decode())

    nodes = parser.query_all(TS_STRING)
    for node in nodes:
        strings.add(node.text.decode())

    cnt = 0
    abstractBody = code
    for param in fparams:
        if len(param) == 0:
            continue
        try:
            paramPattern = re.compile("(^|\W)" + param + "(\W)")
            if fparams[param] != "":
                abstractBody = paramPattern.sub(
                    f"\g<1>{fparams[param]}_FPARAM_{cnt}\g<2>", abstractBody
                )
            else:
                abstractBody = paramPattern.sub(f"\g<1>FPARAM_{cnt}\g<2>", abstractBody)
            cnt += 1
        except:
            pass

    cnt = 0
    for dtype in dtypes:
        if len(dtype) == 0:
            continue
        try:
            dtypePattern = re.compile("(^|\W)" + dtype + "(\W)")
            abstractBody = dtypePattern.sub(f"\g<1>DTYPE_{cnt}\g<2>", abstractBody)
            cnt += 1
        except:
            pass

    cnt = 0
    for lvar in lvars:
        if len(lvar) == 0:
            continue
        try:
            lvarPattern = re.compile("(^|\W)" + lvar + "(\W)")
            if lvars[lvar] != "":
                abstractBody = lvarPattern.sub(
                    f"\g<1>{lvars[lvar]}_LVAR_{cnt}\g<2>", abstractBody
                )
            else:
                abstractBody = lvarPattern.sub(f"\g<1>LVAR_{cnt}\g<2>", abstractBody)
            cnt += 1
        except:
            pass

    cnt = 0
    for fcall in fcalls:
        if len(fcall) == 0:
            continue
        try:
            fcallPattern = re.compile("(^|\W)" + fcall + "(\W)")
            abstractBody = fcallPattern.sub(f"\g<1>FUNCCALL_{cnt}\g<2>", abstractBody)
            cnt += 1
        except:
            pass

    cnt = 0
    for string in strings:
        if len(string) == 0:
            continue
        try:
            replace_str = "STRING"
            fmt_pattern = r"%[\\.]*[0-9]*[.\-*#]*[0-9]*[hljztL]*[diuoxXfFeEgGaAcCsSpnm]"
            fmt_list = re.findall(fmt_pattern, string)
            if len(fmt_list) != 0:
                write_code = "".join(fmt_list)
                write_code = '"' + write_code + '"'
                replace_str = write_code
                fstrPattern = re.compile(r"(^|\W)" + re.escape(string) + r"(\W)")
                abstractBody = fstrPattern.sub(
                    r"\g<1>" + f"{replace_str}_{cnt}" + r"\g<2>", abstractBody
                )
            else:
                replace_str = "STRING"
                fstrPattern = re.compile(r"(^|\W)" + re.escape(string) + r"(\W)")
                abstractBody = fstrPattern.sub(
                    r"\g<1>" + f"{replace_str}_{cnt}" + r"\g<2>", abstractBody
                )
                cnt += 1
        except:
            pass

    removedMTags = [
        "__FILE__",
        "__LINE__",
        "__DATE__",
        "__TIME__",
        "__STDC__",
        "__STDC_VERSION__",
        "__cplusplus",
        "__GNUC__",
        "__GNUC_MINOR__",
        "__GNUC_PATCHLEVEL__",
        "__BASE_FILE__",
        "__FILE_NAME__",
        "__INCLUDE_LEVEL__",
        "__VERSION__",
        "__CHAR_UNSIGNED__",
        "__WCHAR_UNSIGNED__",
        "__REGISTER_PREFIX__",
        "__USER_LABEL_PREFIX__",
        "const",
        "static",
        "extern",
    ]

    for removed in removedMTags:
        abstractBody = abstractBody.replace(removed, "")

    return abstractBody


def extraction_marcos_and_format(codes: str, repoName: str, fileName: str):
    removedMacros = [
        "__FILE__",
        "__LINE__",
        "__DATE__",
        "__TIME__",
        "__STDC__",
        "__STDC_VERSION__",
        "__cplusplus",
        "__GNUC__",
        "__GNUC_MINOR__",
        "__GNUC_PATCHLEVEL__",
        "__BASE_FILE__",
        "__FILE_NAME__",
        "__INCLUDE_LEVEL__",
        "__VERSION__",
        "__CHAR_UNSIGNED__",
        "__WCHAR_UNSIGNED__",
        "__REGISTER_PREFIX__",
        "__USER_LABEL_PREFIX__",
        "__attribute__((noreturn))",
    ]
    file_contents = codes.split("\n")
    i = 0
    while i < len(file_contents):
        file_pure_contents = file_contents[i].strip().replace(" ", "")
        if file_pure_contents.startswith("#include") and "/" in file_pure_contents:
            file_contents[i] = "\n"
            continue
        if file_pure_contents.startswith("#if0"):
            j = i
            while j < len(file_contents):
                file_pure_contents_in = file_contents[j].strip().replace(" ", "")
                if file_pure_contents_in.startswith(
                    "#else"
                ) or file_pure_contents_in.startswith("#endif"):
                    break
                else:
                    file_contents[j] = "\n"
                j += 1
            i = j
        if (
            file_pure_contents.startswith("#if")
            or file_pure_contents.startswith("#elif")
            or file_pure_contents.startswith("#else")
            or file_pure_contents.startswith("#ifdef")
            or file_pure_contents.startswith("#ifndef")
            or file_pure_contents.startswith("#endif")
        ):
            if file_contents[i].strip().replace(" ", "").endswith("\\"):
                file_contents[i] = "\n"
                j = i + 1
                while j < len(file_contents):
                    if file_contents[j].strip().replace(" ", "").endswith("\\"):
                        file_contents[j] = "\n"
                    else:
                        file_contents[j] = "\n"
                        break
                    j += 1
                i = j
            else:
                file_contents[i] = "\n"

        for macro in removedMacros:
            file_contents[i] = file_contents[i].replace(macro, '"{0}"'.format(macro))
        if file_contents[i].lstrip().replace(" ", "").startswith("#error"):
            file_contents[i] = "\n"
        if (
            file_contents[i].strip().startswith("#define")
            and len(file_contents[i].strip().replace("\t", " ").split(" ")) <= 2
            and not file_contents[i].strip().endswith("\\")
        ):
            file_contents[i] = "\n"
        i += 1

    with tempfile.NamedTemporaryFile(delete=False, suffix=".c") as temp_source_file:
        temp_source_file_name = temp_source_file.name
        temp_source_file.write("\n".join(file_contents).encode())
        temp_source_file.flush()
        temp_source_file.close()
    with open(temp_source_file_name, "rb") as f:
        file_contents = f.readlines()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".c") as temp_output_file:
        temp_output_file_name = temp_output_file.name
    relines = []

    with open(
        targetRepoMacros + "/{0}/macro_{1}.h".format(repoName, fileName), "r"
    ) as f:
        lines = f.readlines()
        i = 0
        while i < len(lines):
            if (
                lines[i].strip().startswith("#define")
                and not lines[i].strip().replace(" ", "").endswith("\\")
                and len(lines[i].lstrip().replace("\t", " ").split(" ")) <= 2
            ):
                lines[i] = "\n"
            relines.append(lines[i])
            i += 1
    with open(
        targetRepoMacros + "/{0}/macro_{1}.h".format(repoName, fileName), "w"
    ) as f:
        f.writelines(relines)
    gcc_finish = False
    preMsg = ""
    first_try = False
    pure_fileName = fileName
    while not gcc_finish:
        try:
            cmd = (
                'gcc -E -w -include "'
                + targetRepoMacros
                + '/{0}/macro_{1}.h" "{2}" -o "{3}"'.format(
                    repoName,
                    pure_fileName,
                    temp_source_file_name,
                    temp_output_file_name,
                )
            )
            subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True).decode(
                errors="replace"
            )
            gcc_finish = True
        except subprocess.CalledProcessError as e:
            err_msg = e.output.decode()
            if preMsg == err_msg:
                if first_try:
                    return format_and_del_comment_c_cpp(codes)
                else:
                    with open(
                        f"{targetRepoMacros}{repoName}/macro_{pure_fileName}.h",
                        "r",
                        encoding=encoding_format,
                    ) as f:
                        file_contents = f.readlines()
                        i = 0
                        while i < len(file_contents):
                            if (
                                file_contents[i]
                                .strip()
                                .replace(" ", "")
                                .startswith("#include")
                            ):
                                file_contents[i] = "\n"
                            i += 1
                    fp = open(
                        f"{targetRepoMacros}{repoName}/macro_{pure_fileName}.h", "w"
                    )
                    fp.writelines(file_contents)
                    fp.close()
                    with open(
                        temp_source_file_name, "r", encoding=encoding_format
                    ) as f:
                        file_contents = f.readlines()
                        i = 0
                        while i < len(file_contents):
                            if (
                                file_contents[i]
                                .strip()
                                .replace(" ", "")
                                .startswith("#include")
                            ):
                                file_contents[i] = "\n"
                            i += 1
                        fp = open(temp_source_file_name, "w")
                        fp.writelines(file_contents)
                        fp.close()
                    first_try = True
            else:
                preMsg = err_msg
            msgs = err_msg.split("\n")
            i = 0
            while i < len(msgs):
                msg = msgs[i]
                pattern1 = r"requires (\d+) arguments, but only (\d+) given"
                pattern2 = r"fatal error: ([^:]+): No such file or directory"
                pattern3 = r"passed (\d+) arguments, but takes just (\d+)"
                pattern4 = r'error: missing binary operator before token "\("'
                pattern5 = r"error: #endif without #if"
                pattern6 = r"error: #else without #if"
                pattern7 = r"error: "
                match = re.search(pattern1, msg)
                match2 = re.search(pattern2, msg)
                match3 = re.search(pattern3, msg)
                match4 = re.search(pattern4, msg)
                match5 = re.search(pattern5, msg)
                match6 = re.search(pattern6, msg)
                match7 = re.search(pattern7, msg)
                if match:
                    if len(msgs[i + 4].split(":")) > 1:
                        info = msgs[i + 4]
                        i += 6
                    else:
                        info = msg
                        i += 1
                    fileName = info.split(":")[0].strip()
                    if not (
                        targetRepoMacros not in fileName
                        or pure_fileName not in fileName
                    ) or fileName.startswith("/"):
                        i += 1
                        continue
                    lineNumber = info.split(":")[1].strip()
                    f = open(fileName, "r", encoding="utf-8", errors="replace")
                    lines = f.readlines()
                    f.close()

                    lines[int(lineNumber) - 1] = "\n"
                    fp = open(fileName, "w", encoding="utf-8", errors="replace")
                    fp.writelines(lines)
                    fp.close()
                elif match2:
                    info = msg
                    fileName = info.split(":")[0].strip()
                    if not (
                        targetRepoMacros not in fileName
                        or pure_fileName not in fileName
                    ) or fileName.startswith("/"):
                        i += 1
                        continue
                    lineNumber = info.split(":")[1].strip()
                    f = open(fileName, "r", encoding="utf-8", errors="replace")
                    lines = f.readlines()
                    f.close()

                    lines[int(lineNumber) - 1] = "\n"
                    fp = open(fileName, "w", encoding="utf-8", errors="replace")
                    fp.writelines(lines)
                    fp.close()
                    i += 1
                elif match3:
                    if len(msgs[i + 4].split(":")) > 1:
                        info = msgs[i + 4]
                        i += 6
                    else:
                        info = msg
                        i += 1
                    fileName = info.split(":")[0].strip()
                    if not (
                        targetRepoMacros not in fileName
                        or pure_fileName not in fileName
                    ) or fileName.startswith("/"):
                        i += 1
                        continue
                    lineNumber = info.split(":")[1].strip()
                    errMsg = info.split(":")[-1].strip()
                    matches = re.findall(r'"([^"]*)"', errMsg)

                    f = open(fileName, "r", encoding="utf-8", errors="replace")
                    lines = f.readlines()
                    f.close()
                    for match in matches:
                        if match in lines[int(lineNumber) - 1]:
                            lines[int(lineNumber) - 1] = "\n"
                    fp = open(fileName, "w", encoding="utf-8", errors="replace")
                    fp.writelines(lines)
                    fp.close()
                elif match4 or match5 or match6 or match7:
                    info = msg
                    fileName = info.split(":")[0].strip()
                    if not (
                        targetRepoMacros not in fileName
                        or pure_fileName not in fileName
                    ) or fileName.startswith("/"):
                        i += 1
                        continue
                    lineNumber = info.split(":")[1].strip()
                    f = open(fileName, "r", encoding="utf-8", errors="replace")
                    lines = f.readlines()
                    f.close()

                    lines[int(lineNumber) - 1] = "\n"

                    fp = open(fileName, "w", encoding="utf-8", errors="replace")
                    fp.writelines(lines)

                    fp.close()
                    i += 1
                else:
                    i += 1
    with open(temp_output_file_name, "r", encoding=encoding_format) as f:
        lines = f.readlines()
        i = 0
        while i < len(lines):
            if lines[i].endswith("\\\n"):
                temp = i
                while lines[i].endswith("\\\n"):
                    i += 1
                lines[temp] = lines[temp][:-2]
                for k in range(temp + 1, i + 1):
                    if k == len(lines):
                        break
                    lines[temp] += " "
                    lines[temp] += lines[k][:-2].strip()
                    lines[k] = "\n"
            else:
                i += 1
    with open(temp_source_file_name, "w", encoding=encoding_format) as f:
        f.writelines(lines)
    with open(temp_source_file_name, "r", encoding=encoding_format) as f:
        lines = f.readlines()
        i = 0
        while i < len(lines):
            if lines[i].startswith("# "):
                while temp_source_file_name not in lines[i]:
                    lines[i] = "\n"
                    i += 1
                lines[i] = "\n"
            i += 1
    with open(temp_source_file_name, "w", encoding=encoding_format) as f:
        f.writelines(lines)
    with open(temp_source_file_name, "r", encoding=encoding_format) as f:
        lines = f.readlines()
        i = 0
        preTemp = 0
        while i < len(lines):
            if (
                lines[i].strip() == "\n"
                or lines[i].strip() == "\r\n"
                or lines[i].strip() == ""
            ):
                i += 1
            elif lines[i].strip() == ";":
                if lines[preTemp].strip().endswith("{"):
                    lines[preTemp] = lines[preTemp][:-2] + ";\n"
                    lines[i] = "\n"
                    j = i
                    while j < len(lines) and not lines[j].strip() == "}":
                        j += 1
                    lines[j] = "\n"
                    i = j + 1
                else:
                    lines[preTemp] = lines[preTemp].strip() + ";\n"
                    lines[i] = "\n"
            elif (
                lines[i].strip().startswith("||")
                or lines[i].strip().startswith("&&")
                or lines[i].strip().startswith(">>")
                or lines[i].strip().startswith(")")
                or (
                    lines[i].strip().startswith("(")
                    and not lines[preTemp].strip().endswith("{")
                    and not (
                        lines[preTemp].strip().endswith(";")
                        and not lines[preTemp].strip().startswith("for")
                    )
                )
            ):
                lines[preTemp] = lines[preTemp].strip() + lines[i].lstrip()
                lines[i] = "\n"
                i = preTemp
            elif (
                lines[i].lstrip().startswith("else")
                and lines[preTemp].strip().replace(" ", "") == "}"
            ):
                lines[preTemp] = lines[preTemp].strip() + lines[i].lstrip()
                lines[i] = "\n"
                i = preTemp
            else:
                temp = i
                preTemp = i
                while (
                    i < len(lines)
                    and not lines[i].strip().endswith(";")
                    and not lines[i].strip().endswith("{")
                    and not (
                        lines[i].strip().endswith(")")
                        and (
                            lines[i].strip().startswith("if")
                            or lines[temp].strip().startswith("if")
                        )
                    )
                    and not lines[i].strip().endswith("}")
                    and not lines[i].strip().startswith("#")
                ):
                    i += 1
                if temp != i:
                    lines[temp] = lines[temp][:-1]
                for j in range(temp + 1, i + 1):
                    if j == len(lines):
                        break
                    lines[temp] += " "
                    lines[temp] += lines[j][:-1].strip()
                    lines[j] = "\n"
                if temp == i:
                    i += 1
        i = 0
        while i < len(lines):
            lines[i] = lines[i].replace("_U_", "")
            lines[i] = lines[i].replace("IN ", "")
            lines[i] = lines[i].replace("EFIAPI", "")
            lines[i] = lines[i].replace("UNUSED_PARAM", "")
            lines[i] = lines[i].replace("NULL", "((void *)0)")
            lines[i] = lines[i].replace("(((void *)0))", "((void *)0)")
            lines[i] = lines[i].replace("false", "0").replace("true", "1")
            lines[i] = lines[i].replace("__declspec(dllexport) mrb_value", "")
            lines[i] = lines[i].replace('extern "C"', "")
            lines[i] = lines[i].replace("__attribute__((noreturn))", "")
            lines[i] = lines[i].replace("!!", "")
            if temp_source_file_name in lines[i]:
                j = lines[i].replace(" ", "").find(temp_source_file_name)
                if (
                    lines[i].replace(" ", "")[j + len(temp_source_file_name) + 1] == ","
                    and lines[i]
                    .replace(" ", "")[j + len(temp_source_file_name) + 2]
                    .isdigit()
                ):
                    k = (
                        lines[i]
                        .replace(" ", "")[j + len(temp_source_file_name) + 2 :]
                        .find(",")
                    )
                    if k != -1:
                        digit = lines[i].replace(" ", "")[
                            j + len(temp_source_file_name) + 2 : j
                            + len(temp_source_file_name)
                            + 2
                            + k
                        ]
                    else:
                        k = (
                            lines[i]
                            .replace(" ", "")[j + len(temp_source_file_name) + 2 :]
                            .find(")")
                        )
                        digit = lines[i].replace(" ", "")[
                            j + len(temp_source_file_name) + 2 : j
                            + len(temp_source_file_name)
                            + 2
                            + k
                        ]
                    lines[i] = (
                        lines[i]
                        .replace(temp_source_file_name + ",", "")
                        .replace(digit + ",", "")
                        .replace(temp_source_file_name, "")
                        .replace(digit, "")
                    )

            if "&(*" in lines[i] or "*(&" in lines[i]:
                k = lines[i].find("&(*")
                if k == -1:
                    k = lines[i].find("*(&")
                if k == -1:
                    i += 1
                    continue
                bracket_count = 1
                for j in range(k + 3, len(lines[i])):
                    if lines[i][j] == "(":
                        bracket_count += 1
                    elif lines[i][j] == ")":
                        if bracket_count == 1:
                            lines[i] = lines[i][0:j] + lines[i][j + 1 :]
                            break
                        bracket_count -= 1
                lines[i] = lines[i].replace("&(*", "").replace("*(&", "")
            i += 1
    with open(temp_source_file_name, "w", encoding=encoding_format) as f:
        f.writelines(lines)
    os.remove(temp_source_file_name)
    os.remove(temp_output_file_name)
    return "".join(lines)


def removeComment(string):
    c_regex = re.compile(
        r'(?P<comment>//.*?$|[{}]+)|(?P<multilinecomment>/\*.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"]*)',
        re.DOTALL | re.MULTILINE,
    )
    return "".join(
        [
            c.group("noncomment")
            for c in c_regex.finditer(string)
            if c.group("noncomment")
        ]
    )


def getsMacros(repoPath, repoName, fileName, all_blob={}):
    removedMacros = [
        "__FILE__",
        "__LINE__",
        "__DATE__",
        "__TIME__",
        "__STDC__",
        "__STDC_VERSION__",
        "__cplusplus",
        "__GNUC__",
        "__GNUC_MINOR__",
        "__GNUC_PATCHLEVEL__",
        "__BASE_FILE__",
        "__FILE_NAME__",
        "__INCLUDE_LEVEL__",
        "__VERSION__",
        "__CHAR_UNSIGNED__",
        "__WCHAR_UNSIGNED__",
        "__REGISTER_PREFIX__",
        "__USER_LABEL_PREFIX__",
    ]
    fileCnt = 0
    lineCnt = 0
    allMacs = {}
    includes = set()
    macrosDict = {}
    if os.path.exists(targetRepoMacros + repoName + "/macro_" + fileName + ".h"):
        return
    if not os.path.isdir(targetRepoMacros + repoName):
        os.mkdir(targetRepoMacros + repoName)
    while includeFiles:
        if all_blob == {}:
            analysisFile, prefix, level = includeFiles.pop()
            flag = False
            for path, dir, files in os.walk(repoPath):
                if prefix not in path:
                    continue
                else:
                    prefix = path
                    flag = True
                    break
        else:
            analysisFile, prefix, level = includeFiles.pop()
            flag = True
        if flag:
            getInclude = False
            while not getInclude and prefix != "/".join(repoPath.split("/")[:-1]):
                if "extract.h" in analysisFile:
                    analysisFile = analysisFile.split("\t")[0]
                if all_blob == {}:
                    filePath = os.path.join(prefix, analysisFile)
                    if not os.path.isfile(filePath):
                        filePath = os.path.join(prefix, "deps/lua/src", analysisFile)
                        if not os.path.isfile(filePath):
                            filePath = os.path.join(prefix, "include", analysisFile)
                            if not os.path.isfile(filePath):
                                prefix = "/".join(prefix.split("/")[:-1])
                                continue
                else:
                    filePath = os.path.join(prefix, analysisFile)
                    if filePath not in all_blob:
                        filePath = os.path.join(prefix, "deps/lua/src", analysisFile)
                        if filePath not in all_blob:
                            filePath = os.path.join(prefix, "include", analysisFile)
                            if filePath not in all_blob:
                                prefix = "/".join(prefix.split("/")[:-1])
                                continue
                if filePath in analysizedFiles:
                    break
                else:
                    analysizedFiles.append(filePath)
                getIncludeFiles(filePath, prefix, level + 1)
                try:
                    if repoPath not in filePath:
                        with tempfile.NamedTemporaryFile(
                            delete=False, suffix=".c"
                        ) as temp_source_file:
                            temp_source_file_name = temp_source_file.name
                            temp_source_file.write(
                                "\n".join(all_blob[filePath]).encode()
                            )
                            temp_source_file.flush()
                            temp_source_file.close()
                    else:
                        temp_source_file_name = filePath
                    functionList = subprocess.check_output(
                        CTAGS_PATH
                        + ' -f - --kinds-C=* --fields=neKSt "'
                        + temp_source_file_name
                        + '"',
                        stderr=subprocess.STDOUT,
                        shell=True,
                    ).decode(errors="replace")
                    f = open(filePath, "r", encoding="UTF-8", errors="replace")
                    lines = f.readlines()
                    allFuncs = str(functionList).split("\n")
                    macro = "macro"
                    number = re.compile(r"(\d+)")
                    tmpString = ""
                    lineCnt += len(lines)
                    fileCnt += 1
                    macros = ""
                    for i in allFuncs:
                        elemList = re.sub(r"[\t\s ]{2,}", "", i)
                        elemList = elemList.split("\t")
                        if i != "" and macro in elemList:
                            j = elemList.index(macro)
                            strStartLine = -1
                            strEndLine = -1
                            while j < len(elemList):
                                elem = elemList[j]
                                if "line:" in elem:
                                    strStartLine = int(number.search(elem).group(0))
                                elif "end:" in elem:
                                    strEndLine = int(number.search(elem).group(0))
                                if strStartLine >= 0 and strEndLine >= 0:
                                    break
                                j += 1
                            if strStartLine == -1 or strEndLine == -1:
                                continue
                            tmpString = ""
                            tmpString = tmpString.join(
                                lines[strStartLine - 1 : strEndLine]
                            )
                            rawBody = tmpString
                            macros += rawBody
                            macrosName = elemList[0]
                            if filePath.replace("/", "@@") not in allMacs:
                                allMacs[filePath.replace("/", "@@")] = []
                            if macrosName not in macrosDict.keys():
                                allMacs[filePath.replace("/", "@@")].append(rawBody)
                                macrosDict[macrosName] = level
                            elif macrosDict[macrosName] > level:
                                allMacs[filePath.replace("/", "@@")].append(rawBody)
                                macrosDict[macrosName] = level
                except subprocess.CalledProcessError as e:
                    print("Parser Error:")
                    print(e)
                    continue
                except Exception as e:
                    print("Subprocess failed")
                    print(e)
                    continue
                getInclude = True
                break
            if not getInclude:
                includes.add(analysisFile)

    f = open(
        targetRepoMacros + repoName + "/macro_" + fileName + ".h", "w", encoding="UTF-8"
    )
    for include in includes:
        f.write("#include<{0}>\n".format(include))
    for fp in allMacs:
        for eachVal in allMacs[fp]:
            val = eachVal
            for macro in removedMacros:
                val = val.replace(macro, '"{0}"'.format(macro))
            if "/* nothing */" in val:
                continue
            val = removeComment(val)
            if (
                val.strip().startswith("#define")
                and len(val.strip().replace("\t", " ").split(" ")) <= 2
                and not val.strip().endswith("\\")
            ):
                continue
            if "__trace_if" in val:
                continue
            f.write(val)
    f.close()


def getIncludeFiles(fileName, prefix, level, all_blobs={}):
    if all_blobs == {}:
        with open(fileName, "r", encoding=encoding_format) as f:
            lines = f.readlines()
            for line in lines:
                if line.lstrip().startswith("#include"):
                    file = (
                        line.replace("#include", "")
                        .replace('"', "")
                        .replace("<", "")
                        .replace(">", " ")
                        .strip()
                        .split(" ")[0]
                    )
                    includeFiles.append((file, prefix, level))
    else:
        lines = all_blobs[fileName].split("\n")
        for line in lines:
            if line.lstrip().startswith("#include"):
                file = (
                    line.replace("#include", "")
                    .replace('"', "")
                    .replace("<", "")
                    .replace(">", " ")
                    .strip()
                    .split(" ")[0]
                )
                includeFiles.append((file, prefix, level))


def extraction_macros(
    code: str, repo_path: str, fileName: str, commit: str = "", all_blobs={}
):
    repoName = repo_path.split("/")[-1]
    if not os.path.exists(
        targetRepoMacros
        + "/{0}/macro_{1}.h".format(repoName, fileName.replace("/", "_") + "_" + commit)
    ):
        analysizedFiles.clear()
        includeFiles.append(("", fileName, 0))
        prefix = "/".join(fileName.split("/")[:-1])
        getIncludeFiles(fileName, prefix, 1, all_blobs)
        getsMacros(repo_path, repoName, fileName.replace("/", "_") + "_" + commit)
    return extraction_marcos_and_format(
        code, repoName, fileName.replace("/", "_") + "_" + commit
    )


def abstraction(code: str, language: Language):
    codes = code_transformation(code, Language.CPP)
    return abstract(codes, Language.CPP)


if __name__ == "__main__":
    pass
