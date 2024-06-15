import json
import os
import hashlib
import re
import sys
from queue import Queue
from xml.dom.minidom import parse
import xml.dom.minidom


def del_comment(src):
    with open(src, "r", errors="ignore") as f:
        file_contents = f.read()
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
    with open(src, "w") as f:
        f.write(file_contents)


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
            and not (
                line.strip().startswith("else")
                and not line.lstrip().startswith("else if")
            )
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
            line = line[: k + 1] + "\n" + line[k + 1 :]
        elif line.replace(" ", "").lstrip().startswith("}));"):
            k = line.rfind("}")
            line = line[: k + 1] + "\n" + line[k + 1 :]

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
            while (tmp.count("(") != tmp.count(")") or not (
                tmp.rstrip().endswith("{")
                or tmp.rstrip().endswith(")")
                or tmp.rstrip().endswith(";")
                or tmp.rstrip().endswith("}")
            )) and i < len(lines):
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
            relines = relines + line[0 : j + 1] + "\n" + line[0:j] + line[j + 1 :]
        elif line.replace(" ", "").lstrip().startswith("})."):
            k = line.rfind("}")
            relines = relines + line[: k + 1] + "\n" + line[k + 1 :]
        elif line.replace(" ", "").lstrip().startswith(
            "@Override"
        ) and not line.replace(" ", "").rstrip().endswith("@Override") and not line.replace(" ", "").rstrip().startswith("@OverrideMustInvoke"):
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
    