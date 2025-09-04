import os
import re
import subprocess
import tempfile

import ast_parser
import config
from ast_parser import ASTParser
from common import Language

encoding_format = "ISO-8859-1"


def del_comment(file_contents):
    c_regex = re.compile(
        r'(?P<comment>//.*?$)|(?P<multilinecomment>/\*.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"]*)',
        re.DOTALL | re.MULTILINE,
    )
    file_contents = "".join(
        [
            c.group("noncomment")
            for c in c_regex.finditer(file_contents)
            if c.group("noncomment")
        ]
    )
    return file_contents


def get_comment(code):
    c_regex = re.compile(
        r'(?P<comment>//.*?$)|(?P<multilinecomment>/\*.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"]*)',
        re.DOTALL | re.MULTILINE,
    )
    comment = [c.group("comment") for c in c_regex.finditer(code) if c.group("comment")]
    multilinecomment = [
        c.group("multilinecomment")
        for c in c_regex.finditer(code)
        if c.group("multilinecomment")
    ]
    all_comment = set()
    for comma in comment:
        all_comment.add(comma)
    for comma in multilinecomment:
        all_comment.add(comma)
    return all_comment


def add_bracket(code: str, language: Language):
    code_bytes = code.encode()
    parser = ASTParser(code, language)
    nodes = parser.query_all(ast_parser.TS_COND_STAT)
    nodes = [node for node in nodes]
    need_modified_bytes = []
    for node in nodes:
        consequence_node = node.child_by_field_name("consequence")
        if consequence_node is None:
            continue
        if consequence_node.type != "compound_statement":
            if (
                consequence_node.start_byte,
                consequence_node.end_byte,
            ) not in need_modified_bytes:
                need_modified_bytes.append(
                    (consequence_node.start_byte, consequence_node.end_byte)
                )
        alternative_node = node.child_by_field_name("alternative")
        if alternative_node is None:
            continue
        alternative_node = alternative_node.named_child(0)
        if (
            alternative_node is not None
            and alternative_node.type != "compound_statement"
            and alternative_node.type != "if_statement"
        ):
            if (
                alternative_node.start_byte,
                alternative_node.end_byte,
            ) not in need_modified_bytes:
                st = alternative_node.start_byte
                ed = alternative_node.end_byte
                need_modified_bytes.append(
                    (alternative_node.start_byte, alternative_node.end_byte)
                )
    need_modified_bytes = sorted(need_modified_bytes)
    i = 0
    while i < len(need_modified_bytes):
        st, ed = need_modified_bytes[i]
        if ed - st <= 1:
            i += 1
            continue
        code_bytes = (
            code_bytes[:st]
            + b"{\n"
            + code_bytes[st : ed + 1]
            + b"}\n"
            + code_bytes[ed + 1 :]
        )
        j = i + 1
        while j < len(need_modified_bytes):
            st_next, ed_next = need_modified_bytes[j]
            if st_next >= st and st_next <= ed:
                st_next += 2
            else:
                st_next += 4
            if ed_next >= st and ed_next <= ed:
                ed_next += 2
            else:
                ed_next += 4
            need_modified_bytes[j] = (st_next, ed_next)
            j += 1
        i += 1
    return code_bytes.decode()


def del_lineBreak_C(code):
    comments = get_comment(code)
    comment_map = {}
    cnt = 0
    for comment in comments:
        repl = f"__COMMENT__{cnt};"
        code = code.replace(comment, repl)
        comment_map[repl] = comment
        cnt += 1
    lines = code.split("\n")
    i = 0
    while i < len(lines):
        if lines[i].endswith("\\"):
            temp = i
            while lines[i].endswith("\\"):
                i += 1
            lines[temp] = lines[temp].strip()
            for k in range(temp + 1, i + 1):
                if k == len(lines):
                    break
                lines[temp] += " "
                lines[temp] += lines[k].strip()
                lines[k] = "\n"
        else:
            i += 1
    i = 0
    while i < len(lines):
        if lines[i].strip() == "" or lines[i].strip().startswith("#"):
            i += 1
        else:
            temp = i
            while (
                i < len(lines)
                and not lines[i].strip().endswith(";")
                and not lines[i].strip().endswith("{")
                and not lines[i].strip().endswith(")")
                and not lines[i].strip().endswith("}")
                and not lines[i].strip().endswith(":")
                and not lines[i].strip().startswith("#")
            ):
                i += 1
            while i < len(lines) - 1 and (
                lines[i + 1].strip().startswith("?")
                or lines[i + 1].strip().startswith("||")
                or lines[i + 1].strip().startswith("&&")
            ):
                i += 1
            if i < len(lines) and lines[i].strip().startswith("#"):
                i -= 1
            if temp != i:
                lines[temp] = lines[temp]
            for j in range(temp + 1, i + 1):
                if j == len(lines):
                    break
                lines[temp] += " "
                lines[temp] += lines[j].strip()
                lines[j] = ""
            if temp == i:
                i += 1
    code = "\n".join(lines)
    for repl in comment_map.keys():
        code = code.replace(repl, comment_map[repl])
    return code


def del_macros(code):
    lines = code.split("\n")
    removed_macros = {
        "R_API",
        "INLINE",
        "TRIO_PRIVATE_STRING",
        "GF_EXPORT",
        "LOCAL",
        "IN",
        "OUT",
        "_U_",
        "EFIAPI",
        "UNUSED_PARAM",
        "__declspec(dllexport) mrb_value",
        'extern "C"',
        "__rte_always_inline",
        "__init",
        "__user",
        "UNUSED",
        "noinline",
        "static",
        "__attribute__(())",
        "checkreturn",
    }
    i = 0
    while i < len(lines):
        if lines[i].endswith("\\"):
            temp = i
            while lines[i].endswith("\\"):
                i += 1
            lines[temp] = lines[temp][:-1]
            for k in range(temp + 1, i + 1):
                if k == len(lines):
                    break
                lines[temp] += " "
                if k != i:
                    lines[temp] += lines[k][:-1].strip()
                else:
                    lines[temp] += lines[k].strip()
                lines[k] = "\n"
        else:
            i += 1
    i = 0
    while i < len(lines):
        if lines[i].strip().startswith("#") and not lines[i].strip().startswith(
            "#include"
        ):
            lines[i] = ""
        for rmv_macro in removed_macros:
            lines[i] = lines[i].replace(rmv_macro, "")
        lines[i] = (
            lines[i]
            .replace("METHODDEF(void)", "void")
            .replace("METHODDEF(JDIMENSION)", "int")
        )
        i += 1
    return "\n".join(lines)


def format_and_del_comment_c_cpp(code, del_macro=True, del_comments=True):
    code = (
        subprocess.run(
            [
                "astyle",
                "--style=java",
                "--squeeze-ws",
                "--keep-one-line-statements",
                "--max-code-length=200",
                "--delete-empty-lines",
            ],
            input=code.encode(),
            stdout=subprocess.PIPE,
        )
        .stdout.decode()
        .strip()
    )
    if del_comments:
        code = del_comment(code)
    if del_macro:
        code = del_macros(code)
    code = del_lineBreak_C(code)
    code = remove_empty_lines(code)
    code = (
        subprocess.run(
            [
                "astyle",
                "--style=java",
                "--squeeze-ws",
                "--keep-one-line-statements",
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


def rewrite_macros(repoName, hash, filename):
    relines = []
    with open(
        "./macros_test/{0}/macro_{1}_{2}.h".format(
            repoName, hash, filename.split("/")[-1]
        )
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
        "./macros_test/{0}/macro_{1}_{2}.h".format(
            repoName, hash, filename.split("/")[-1]
        ),
        "w",
    ) as f:
        f.writelines(relines)


def format_and_del_comment_c_cpp_with_gcc(code, repoName, hash, fileName):
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
    file_contents = code.split("\n")
    i = 0
    while i < len(file_contents):
        file_pure_contents = file_contents[i].strip().replace(" ", "")
        if file_pure_contents.startswith("#include") and "/" in file_pure_contents:
            file_contents[i] = ""
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
                    file_contents[j] = ""
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
                file_contents[i] = ""
                j = i + 1
                while j < len(file_contents):
                    if file_contents[j].strip().replace(" ", "").endswith("\\"):
                        file_contents[j] = ""
                    else:
                        file_contents[j] = ""
                        break
                    j += 1
                i = j
            else:
                file_contents[i] = ""

        for macro in removedMacros:
            file_contents[i] = file_contents[i].replace(macro, '"{0}"'.format(macro))
        if file_contents[i].lstrip().replace(" ", "").startswith("#error"):
            file_contents[i] = " "
        if (
            file_contents[i].strip().startswith("#define")
            and len(file_contents[i].strip().replace("\t", " ").split(" ")) <= 2
            and not file_contents[i].strip().endswith("\\")
        ):
            file_contents[i] = " "
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
    rewrite_macros(repoName, hash, fileName)
    gcc_finish = False
    preMsg = ""
    first_try = False
    pure_fileName = fileName
    while not gcc_finish:
        try:
            cmd = "gcc -E -w -include ./macros_test/{0}/macro_{1}_{2}.h {3} -o {4}".format(
                repoName,
                hash,
                pure_fileName,
                temp_source_file_name,
                temp_output_file_name,
            )
            print(cmd)
            subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True).decode(
                errors="replace"
            )
            gcc_finish = True
            print(temp_output_file_name)
            with open(temp_output_file_name, "rb") as f:
                file_contents = f.readlines()
                print(file_contents)
        except subprocess.CalledProcessError as e:
            err_msg = e.output.decode()
            print(err_msg)
            if preMsg == err_msg:
                if first_try:
                    format_and_del_comment_c_cpp(code)
                    return
                else:
                    if not os.path.exists("./macros_test"):
                        os.makedirs("./macros_test")
                    with open(
                        "./macros_test/{0}/macro_{1}_{2}.h".format(
                            repoName, hash, pure_fileName
                        ),
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
                            "./macros_test/{0}/macro_{1}_{2}.h".format(
                                repoName, hash, pure_fileName
                            ),
                            "w",
                        )
                        fp.writelines(file_contents)
                    with open(
                        temp_source_file_name, "r", encoding=encoding_format
                    ) as f:
                        file_contents = f.readlines()
                        print(file_contents)
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
            print(msgs)
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
                    info = msgs[i + 4]
                    fileName = info.split(":")[0].strip()
                    if not (
                        (fileName.startswith("/home") or fileName.startswith("/nas"))
                        and (
                            fileName.endswith(".h")
                            or fileName.endswith(".c")
                            or fileName.endswith(".cpp")
                            or fileName.endswith(".cc")
                        )
                    ):
                        i += 1
                        continue
                    lineNumber = info.split(":")[1].strip()
                    f = open(fileName, "r", encoding="utf-8", errors="replace")
                    lines = f.readlines()
                    lines[int(lineNumber) - 1] = "\n"
                    f.close()
                    fp = open(fileName, "w", encoding="utf-8", errors="replace")
                    fp.writelines(lines)
                    fp.close()
                    i += 6
                elif match2:
                    info = msg
                    fileName = info.split(":")[0].strip()
                    if not (
                        (fileName.startswith("/home") or fileName.startswith("/nas"))
                        and (
                            fileName.endswith(".h")
                            or fileName.endswith(".c")
                            or fileName.endswith(".cpp")
                            or fileName.endswith(".cc")
                        )
                    ):
                        i += 1
                        continue
                    lineNumber = info.split(":")[1].strip()
                    f = open(fileName, "r", encoding="utf-8", errors="replace")
                    lines = f.readlines()
                    lines[int(lineNumber) - 1] = "\n"
                    f.close()
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
                        (fileName.startswith("/home") or fileName.startswith("/nas"))
                        and (
                            fileName.endswith(".h")
                            or fileName.endswith(".c")
                            or fileName.endswith(".cpp")
                            or fileName.endswith(".cc")
                        )
                    ):
                        i += 1
                        continue
                    lineNumber = info.split(":")[1].strip()
                    f = open(fileName, "r", encoding="utf-8", errors="replace")
                    lines = f.readlines()
                    lines[int(lineNumber) - 1] = "\n"
                    f.close()
                    fp = open(fileName, "w", encoding="utf-8", errors="replace")
                    fp.writelines(lines)
                    fp.close()
                elif match4 or match5 or match6 or match7:
                    info = msg
                    fileName = info.split(":")[0].strip()
                    if not (
                        (fileName.startswith("/home") or fileName.startswith("/nas"))
                        and (
                            fileName.endswith(".h")
                            or fileName.endswith(".c")
                            or fileName.endswith(".cpp")
                            or fileName.endswith(".cc")
                        )
                    ):
                        i += 1
                        continue
                    lineNumber = info.split(":")[1].strip()
                    f = open(fileName, "r", encoding="utf-8", errors="replace")
                    lines = f.readlines()
                    lines[int(lineNumber) - 1] = "\n"
                    f.close()
                    fp = open(fileName, "w", encoding="utf-8", errors="replace")
                    fp.writelines(lines)
                    fp.close()
                    i += 1
                else:
                    i += 1
    with open(temp_output_file_name, "r", encoding=encoding_format) as f:
        lines = f.readlines()
        print(lines)
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
                print(k)
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


def remove_empty_lines(string) -> str:
    return re.sub(r"^\s*$\n", "", string, flags=re.MULTILINE)


def remove_spaces(string):
    return re.sub(r"\s+", "", string)


def normalize(code: str, del_comments: bool = True) -> str:
    if del_comments:
        code = del_comment(code)
    code = del_lineBreak_C(code)
    code = remove_spaces(code)
    return code.strip()


def del_lineBreak(src):
    f = open(src, "r")
    lines = f.readlines()
    i = 0
    relines = ""
    while i < len(lines):
        line = lines[i]
        i += 1

        while (
            not (
                line.replace(" ", "").rstrip().endswith(";")
                and line.lstrip().startswith("for ")
                and line.count(";") == 3
            )
            and not (
                line.replace(" ", "").rstrip().endswith(";")
                and not (
                    line.lstrip().startswith("try") or line.lstrip().startswith("for ")
                )
            )
            and not line.replace(" ", "").rstrip().endswith("}")
            and not (
                (
                    line.lstrip().startswith("if ")
                    or line.lstrip().startswith("for ")
                    or line.lstrip().startswith("while ")
                    or line.lstrip().startswith("switch ")
                    or line.lstrip().startswith("else if")
                )
                and line.replace(" ", "").rstrip().endswith(")")
            )
            and not (line.strip().startswith("else"))
            and not line.replace(" ", "").rstrip().endswith("{")
            and not (
                line.replace(" ", "").lstrip().startswith("@")
                and line.replace(" ", "").rstrip().endswith(")")
            )
            and not (line.strip().startswith("case") and line.rstrip().endswith(":"))
            and not line.replace(" ", "") == "\n"
            and i < len(lines)
        ):
            if line.replace(" ", "").lstrip().startswith("@"):
                tmp_lines = line.strip().split(" ")
                if len(tmp_lines) == 1:
                    break
            line = line[0:-1] + " "
            line += lines[i].lstrip()
            i += 1

        if (
            line.replace(" ", "").rstrip().endswith(")")
            and "=" in line
            and not (
                line.lstrip().startswith("if ")
                or line.lstrip().startswith("for ")
                or line.lstrip().startswith("else if ")
                or line.lstrip().startswith("@")
            )
        ):
            line = line[0:-1] + " "
            line += lines[i].lstrip()
            i += 1

        while line.lstrip().startswith("for ") and not (
            line.replace(" ", "").rstrip().endswith(")")
            or line.replace(" ", "").rstrip().endswith("{")
            or line.replace(" ", "").rstrip().endswith(";")
        ):
            line = line[0:-1] + " "
            line += lines[i].lstrip()
            i += 1

        while (
            line.replace(" ", "").lstrip().startswith("@")
            and not line.replace(" ", "").lstrip().startswith("@Override")
            and not line.replace(" ", "").lstrip().startswith("@Deprecated")
            and (
                (line.replace(" ", "").rstrip().endswith(","))
                or (
                    line.replace(" ", "").rstrip().endswith("(")
                    or (line.replace(" ", "").rstrip().endswith("{"))
                )
            )
        ):
            line = line[0:-1] + " "
            line += lines[i].lstrip()
            i += 1

        if line.replace(" ", "").lstrip().startswith("@") and (
            lines[i].replace(" ", "").rstrip().startswith(")")
            or lines[i].replace(" ", "").rstrip().startswith("}")
        ):
            line = line[0:-1] + " "
            line += lines[i].lstrip()
            i += 1

        temp_lines = line.split(" ")
        if (
            "new" in temp_lines
            and line.replace(" ", "").rstrip().endswith("{")
            and not line.lstrip().startswith("try ")
            and not lines[i].replace(" ", "").lstrip().startswith("@")
            and "->" not in temp_lines
        ) or (
            "String[]" in temp_lines
            and line.replace(" ", "").rstrip().endswith("{")
            and "public" not in temp_lines
            and not "private" in temp_lines
            and not "protected" in temp_lines
        ):
            line = line[0:-1] + " "
            line += lines[i]
            i += 1
            while (
                not line.replace(" ", "").rstrip().endswith(";")
                and not line.replace(" ", "").rstrip().endswith("}")
                and not line.replace(" ", "").rstrip().endswith(")")
                and not line.replace(" ", "").rstrip().endswith("{")
                and not line.replace(" ", "").lstrip().startswith("@")
                and not line.replace(" ", "").lstrip().startswith("else")
                and i < len(lines)
            ):
                if (
                    lines[i].strip().startswith("public")
                    or lines[i].strip().startswith("private")
                    or lines[i].strip().startswith("protected")
                    or lines[i].strip().startswith("@")
                ):
                    line += "\n"
                    break
                line = line[0:-1] + " "
                line += lines[i].lstrip()
                i += 1

            while not line.rstrip().endswith(";"):
                if (
                    lines[i].strip().startswith("public")
                    or lines[i].strip().startswith("private")
                    or lines[i].strip().startswith("protected")
                    or lines[i].strip().startswith("@")
                ):
                    line += "\n"
                    break
                line = line[0:-1] + " "
                line += lines[i].lstrip()
                i += 1

        if line.replace(" ", "").rstrip().endswith("});") and "{" not in line:
            k = line.rfind("}")
            line = line[: k + 1].rstrip() + "\n" + line[k + 1 :].lstrip()
        elif line.replace(" ", "").lstrip().startswith("}));"):
            k = line.rfind("}")
            line = line[: k + 1].rstrip() + "\n" + line[k + 1 :].lstrip()

        if (
            line.lstrip().startswith("if ")
            or line.lstrip().startswith("for ")
            or line.lstrip().startswith("while ")
            or line.lstrip().startswith("try ")
            or line.lstrip().startswith("catch ")
            or line.lstrip().startswith("else if")
            or line.lstrip().startswith("switch ")
        ):
            string_literals = re.findall(r'"(?:\\.|[^\\"])*"', line)
            tmp = line
            for j, literal in enumerate(string_literals):
                placeholder = f"__string_literal_{j}__"
                tmp = tmp.replace(literal, placeholder)
            while (
                tmp.count("(") != tmp.count(")")
                or not (
                    tmp.rstrip().endswith("{")
                    or tmp.rstrip().endswith(")")
                    or tmp.rstrip().endswith(";")
                    or tmp.rstrip().endswith("}")
                )
            ) and i < len(lines):
                tmp = tmp[0:-1] + " "
                tmp += lines[i].lstrip()
                i += 1
            for j, literal in enumerate(string_literals):
                placeholder = f"__string_literal_{j}__"
                tmp = tmp.replace(placeholder, literal)
            line = tmp

        if line.replace(" ", "").lstrip().startswith("."):
            relines = relines[0:-1] + line.lstrip()
        elif line.replace(" ", "").lstrip().startswith("{"):
            relines = relines[0:-1] + line.lstrip()
        elif (
            line.lstrip().startswith("throws")
            or line.replace(" ", "").lstrip().startswith("||")
            or line.replace(" ", "").lstrip().startswith("&&")
            or line.replace(" ", "").lstrip().startswith("+")
            or line.replace(" ", "").lstrip().startswith("-")
            or line.replace(" ", "").lstrip().startswith("*")
            or line.replace(" ", "").lstrip().startswith(")")
            or line.replace(" ", "").lstrip().startswith(">")
            or line.replace(" ", "").lstrip().startswith("<")
            or line.replace(" ", "").lstrip().startswith(":")
            or line.replace(" ", "").lstrip().startswith("==")
            or line.replace(" ", "").lstrip().startswith("?")
            or line.replace(" ", "").lstrip().startswith("!=")
        ):
            relines = relines[0:-1] + " " + line.lstrip()
        elif line.replace(" ", "").lstrip().startswith("},"):
            relines = relines + line
        elif (
            line.replace(" ", "").lstrip().startswith("}")
            and not line.replace(" ", "").rstrip().endswith("};")
            and not (
                line.replace(" ", "").lstrip().startswith("})")
                and not line.replace(" ", "").lstrip().startswith("}){")
            )
        ):
            j = line.find("}")
            relines = relines + line[0 : j + 1].rstrip() + "\n" + line[j + 1 :].lstrip()
        elif line.replace(" ", "").lstrip().startswith("})."):
            k = line.rfind("}")
            relines = relines + line[: k + 1].rstrip() + "\n" + line[k + 1 :].lstrip()
        elif (
            line.replace(" ", "").lstrip().startswith("@Override")
            and not line.replace(" ", "").rstrip().endswith("@Override")
            and not line.replace(" ", "").rstrip().startswith("@OverrideMustInvoke")
        ):
            k = line.find("@Override")
            relines = (
                relines
                + line[: k + len("@Override")]
                + "\n"
                + line[k + len("@Override") :]
            )
        elif line.replace(" ", "").lstrip().startswith(
            "@Deprecated"
        ) and not line.replace(" ", "").rstrip().endswith("@Deprecated"):
            k = line.find("@Deprecated")
            relines = (
                relines
                + line[: k + len("@Deprecated")]
                + "\n"
                + line[k + len("@Deprecated") :]
            )
        elif line.replace(" ", "") != "\n":
            relines += line
    f.close()
    outputf = open(src, "w")
    outputf.write(relines)
    outputf.close()


def addBracket(src):
    f = open(src, "r")
    lines = f.readlines()
    i = 0
    relines = ""
    while i < len(lines):
        line = lines[i]
        i += 1
        if line.replace(" ", "").endswith(";\n"):
            relines += line
        elif (
            line.lstrip().startswith("if ")
            or line.lstrip().startswith("for ")
            or (
                line.strip().startswith("else")
                and not line.lstrip().startswith("else if")
            )
            or line.lstrip().startswith("while ")
            or line.lstrip().startswith("try ")
            or line.lstrip().startswith("catch ")
            or line.lstrip().startswith("else if")
            or line.lstrip().startswith("switch ")
        ) and line.replace(" ", "").rstrip().endswith("}"):
            k = line.find("{")
            temp = line[0 : k + 1] + "\n"
            line = line[k + 1 :]
            st = 0
            left = 1
            while left > 0 and st < len(line):
                if line[st] == "{":
                    left += 1
                    temp += line[0 : st + 1] + "\n"
                    line = line[st + 1 :]
                    st = -1
                elif line[st] == "}":
                    left -= 1
                    temp += line[0:st] + "\n}\n"
                    line = line[st + 1 :]
                    st = -1
                st += 1
            if not (left <= 0 and st >= len(line)):
                relines += temp + line
            else:
                relines += temp
        elif (
            (
                line.lstrip().startswith("if ")
                or line.lstrip().startswith("for ")
                or (
                    line.strip().startswith("else")
                    and not line.lstrip().startswith("else if")
                )
                or line.lstrip().startswith("while ")
                or line.lstrip().startswith("try ")
                or line.lstrip().startswith("catch ")
                or line.lstrip().startswith("else if")
                or line.lstrip().startswith("switch")
            )
            and not line.replace(" ", "").rstrip().endswith("{")
            and not line.replace(" ", "").rstrip().endswith(";")
        ):
            first = True
            temp = ""
            left = 1
            before = ""
            while (
                (
                    line.lstrip().startswith("if ")
                    or line.lstrip().startswith("for ")
                    or (
                        line.strip().startswith("else")
                        and not line.lstrip().startswith("else if")
                    )
                    or line.lstrip().startswith("while ")
                    or line.lstrip().startswith("try ")
                    or line.lstrip().startswith("catch ")
                    or line.lstrip().startswith("else if")
                    or line.lstrip().startswith("switch")
                )
                and not line.replace(" ", "").rstrip().endswith("{")
                and not line.replace(" ", "").rstrip().endswith(";")
            ):
                if first:
                    temp = line[0:-1] + "{\n"
                else:
                    j = i - 1
                    while j >= 0 and lines[j].replace(" ", "") == "\n":
                        j -= 1
                    i += 1
                    if (
                        line.strip().startswith("else")
                        and not line.lstrip().startswith("else if")
                        and before == "else"
                    ):
                        temp += "}\n" + line[0:-1] + "{\n"
                    elif before == "else" and left != 0:
                        temp += "}\n" + line[0:-1] + "{\n"
                    elif lines[j].replace(" ", "").strip() == "}":
                        temp += "}\n" + line[0:-1] + "{\n"
                    else:
                        temp += line[0:-1] + "{\n"
                        left += 1
                if line.lstrip().startswith("if "):
                    before = "if"
                elif line.lstrip().startswith("for "):
                    before = "for"
                elif line.strip().startswith("else") and not line.lstrip().startswith(
                    "else if"
                ):
                    before = "else"
                elif line.lstrip().startswith("while "):
                    before = "while"
                elif line.lstrip().startswith("try "):
                    before = "try"
                elif line.lstrip().startswith("catch "):
                    before = "catch"
                elif line.lstrip().startswith("else if"):
                    before = "else if"
                elif line.lstrip().startswith("switch"):
                    before = "switch"
                while (
                    lines[i].lstrip().startswith("if ")
                    or lines[i].lstrip().startswith("if(")
                    or lines[i].lstrip().startswith("for ")
                    or (
                        lines[i].strip().startswith("else")
                        and not lines[i].lstrip().startswith("else if")
                    )
                    or lines[i].lstrip().startswith("while ")
                    or lines[i].lstrip().startswith("try ")
                    or lines[i].lstrip().startswith("catch ")
                    or lines[i].lstrip().startswith("else if")
                    or lines[i].lstrip().startswith("switch ")
                ) and not (
                    lines[i].replace(" ", "").rstrip().endswith("{")
                    or lines[i].replace(" ", "").rstrip().endswith(";")
                ):
                    if lines[i].strip().startswith("else") and (
                        before == "for" or before == "while"
                    ):
                        temp += "}\n" + lines[i][:-1] + "{\n"
                        i += 1
                        before = "else"
                    elif lines[i].replace(" ", "").rstrip().endswith("}"):
                        k = lines[i].find("{")
                        temp1 = lines[i][0 : k + 1] + "\n"
                        lines[i] = lines[i][k + 1 :]
                        st = 0
                        left1 = 1
                        while left1 > 0 and st < len(lines[i]):
                            if lines[i][st] == "{":
                                left1 += 1
                                temp1 += lines[i][0 : st + 1] + "\n"
                                lines[i] = lines[i][st + 1 :]
                                st = -1
                            elif lines[i][st] == "}":
                                left1 -= 1
                                temp1 += lines[i][0:st] + "\n}\n"
                                lines[i] = lines[i][st + 1 :]
                                st = -1
                            st += 1
                        if not (left1 <= 0 and st >= len(lines[i])):
                            temp += temp1 + lines[i]
                        else:
                            temp += temp1
                    else:
                        temp += lines[i][:-1] + "{\n"
                        left += 1
                        if line.lstrip().startswith("if "):
                            before = "if"
                        elif line.lstrip().startswith("for "):
                            before = "for"
                        elif line.strip().startswith(
                            "else"
                        ) and not line.lstrip().startswith("else if"):
                            before = "else"
                        elif line.lstrip().startswith("while "):
                            before = "while"
                        elif line.lstrip().startswith("try "):
                            before = "try"
                        elif line.lstrip().startswith("catch "):
                            before = "catch"
                        elif line.lstrip().startswith("else if"):
                            before = "else if"
                        elif line.lstrip().startswith("switch"):
                            before = "switch"
                        i += 1
                fl = True
                if (
                    lines[i].lstrip().startswith("if ")
                    or lines[i].lstrip().startswith("if(")
                    or lines[i].lstrip().startswith("for ")
                    or (
                        lines[i].strip().startswith("else")
                        and not lines[i].lstrip().startswith("else if")
                    )
                    or lines[i].lstrip().startswith("while ")
                    or lines[i].lstrip().startswith("try ")
                    or lines[i].lstrip().startswith("catch ")
                    or lines[i].lstrip().startswith("else if")
                    or lines[i].lstrip().startswith("switch ")
                ) and lines[i].replace(" ", "").rstrip().endswith("{"):
                    while (
                        lines[i].lstrip().startswith("if ")
                        or lines[i].lstrip().startswith("if(")
                        or lines[i].lstrip().startswith("for ")
                        or (
                            lines[i].strip().startswith("else")
                            and not lines[i].lstrip().startswith("else if")
                        )
                        or lines[i].lstrip().startswith("while ")
                        or lines[i].lstrip().startswith("try ")
                        or lines[i].lstrip().startswith("catch ")
                        or lines[i].lstrip().startswith("else if")
                        or lines[i].lstrip().startswith("switch ")
                    ) and lines[i].replace(" ", "").rstrip().endswith("{"):
                        temp += lines[i]
                        i += 1
                        left1 = 1
                        be = False
                        while left1 > 0 and i < len(lines):
                            if "{" in lines[i]:
                                k = lines[i].find("{")
                                temp1 = lines[i][0 : k + 1] + "\n"
                                lines[i] = lines[i][k + 1 :]
                                st = 0
                                left1 += 1
                                while left1 > 0 and st < len(lines[i]):
                                    if lines[i][st] == "{":
                                        left1 += 1
                                        temp1 += lines[i][0 : st + 1] + "\n"
                                        lines[i] = lines[i][st + 1 :]
                                        st = -1
                                    elif lines[i][st] == "}":
                                        left1 -= 1
                                        temp1 += lines[i][0:st] + "\n}\n"
                                        lines[i] = lines[i][st + 1 :]
                                        st = -1
                                    st += 1
                                if not (left1 <= 0 and st >= len(lines[i])):
                                    temp += temp1 + lines[i]
                                else:
                                    temp += temp1
                                i += 1
                            elif lines[i].replace(" ", "").rstrip().endswith("}"):
                                left1 -= 1
                                temp += lines[i]
                                i += 1
                            elif (
                                lines[i].lstrip().startswith("if ")
                                or lines[i].lstrip().startswith("if(")
                                or lines[i].lstrip().startswith("for ")
                                or (
                                    lines[i].strip().startswith("else")
                                    and not lines[i].lstrip().startswith("else if")
                                )
                                or lines[i].lstrip().startswith("while ")
                                or lines[i].lstrip().startswith("try ")
                                or lines[i].lstrip().startswith("catch ")
                                or lines[i].lstrip().startswith("else if")
                                or lines[i].lstrip().startswith("switch ")
                            ) and not lines[i].replace(" ", "").rstrip().endswith("{"):
                                temp += lines[i][:-1] + "{\n"
                                left1 += 1
                                i += 1
                                be = True
                            elif be and not (
                                lines[i].lstrip().startswith("if ")
                                or lines[i].lstrip().startswith("if(")
                                or lines[i].lstrip().startswith("for ")
                                or (
                                    lines[i].strip().startswith("else")
                                    and not lines[i].lstrip().startswith("else if")
                                )
                                or lines[i].lstrip().startswith("while ")
                                or lines[i].lstrip().startswith("try ")
                                or lines[i].lstrip().startswith("catch ")
                                or lines[i].lstrip().startswith("else if")
                                or lines[i].lstrip().startswith("switch ")
                            ):
                                temp += lines[i] + "}\n"
                                be = False
                                i += 1
                                left1 -= 1
                            else:
                                temp += lines[i]
                                i += 1
                        while lines[i].replace(" ", "") == "\n":
                            temp += lines[i]
                            i += 1
                        while left1 != 0:
                            temp += "}\n"
                            left1 -= 1
                elif lines[i].rstrip().endswith("{"):
                    tmp = i
                    while i < len(lines) and not lines[i].rstrip().endswith("};"):
                        temp += lines[i]
                        i += 1
                    temp += lines[i]
                    i += 1
                elif not (
                    lines[i].lstrip().startswith("if ")
                    or lines[i].lstrip().startswith("if(")
                    or lines[i].lstrip().startswith("for ")
                    or (
                        lines[i].strip().startswith("else")
                        and not lines[i].lstrip().startswith("else if")
                    )
                    or lines[i].lstrip().startswith("while ")
                    or lines[i].lstrip().startswith("try ")
                    or lines[i].lstrip().startswith("catch ")
                    or lines[i].lstrip().startswith("else if")
                    or lines[i].lstrip().startswith("switch ")
                ):
                    temp += lines[i] + "}\n"
                    left -= 1
                    i += 1
                    fl = False
                line = lines[i]
                if line.lstrip().startswith("else") and left != 0 and fl:
                    temp += "}\n"
                    left -= 1
                first = False
            if left > 0:
                temp += "}\n"
                left -= 1

            if (
                not (
                    (
                        lines[i].lstrip().startswith("if ")
                        or lines[i].lstrip().startswith("if(")
                        or lines[i].lstrip().startswith("for ")
                        or (
                            lines[i].strip().startswith("else")
                            and not lines[i].lstrip().startswith("else if")
                        )
                        or lines[i].lstrip().startswith("while ")
                        or lines[i].lstrip().startswith("try ")
                        or lines[i].lstrip().startswith("catch ")
                        or lines[i].lstrip().startswith("else if")
                        or lines[i].lstrip().startswith("switch ")
                    )
                    and not (
                        lines[i].replace(" ", "").rstrip().endswith("{")
                        or lines[i].replace(" ", "").rstrip().endswith(";")
                    )
                )
                and left > 0
            ):
                temp += lines[i] + "}\n"
                i += 1
                left -= 1
            while left != 0:
                temp += "}\n"
                left -= 1
            relines += temp
        else:
            relines += line
    f.close()
    assertLoc = []
    lines = relines.split("\n")
    empty_line = []
    newContent = ""
    annotaionLines = 0
    for i in range(len(lines)):
        line = lines[i]
        if lines[i].strip() in ["{", "}", ""]:
            empty_line.append(i + 1 - annotaionLines)
        lineContent = line.strip().split(" ")
        if (
            len(lineContent) <= 1
            and line.strip().startswith("@")
            and not line.strip().endswith("{")
            and (
                lines[i + 1].strip().startswith("public")
                or lines[i + 1].strip().startswith("private")
                or lines[i + 1].strip().startswith("protected")
                or lines[i + 1].strip().startswith("@")
            )
        ):
            annotaionLines += 1
            continue
        elif line.strip() == "PendingIntent.getService }":
            newContent += "}\n"
            continue
        newContent += line + "\n"
    outputf = open(src, "w")
    outputf.write(newContent)
    outputf.close()
    return empty_line


def format_and_del_comment_java(src):
    fp = open(src)
    code = fp.read()
    fp.close()
    del_comment(code)
    del_lineBreak(src)


if __name__ == "__main__":
    pass
