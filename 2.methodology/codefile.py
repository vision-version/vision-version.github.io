import os

import format_code


class CodeFile:
    def __init__(
        self, file_path: str, code: str, isformat: bool = True, rel_path: str = ""
    ):
        self.file_path = file_path
        self.code = code
        if rel_path != "":
            self.rel_path = rel_path
        else:
            self.rel_path = file_path
        if isformat:
            self.formated_code = format_code.format_and_del_comment_c_cpp(code)
        else:
            self.formated_code = code


def create_code_tree(
    code_files: list[CodeFile], dir: str, overwrite: bool = False
) -> str:
    code_dir = os.path.join(dir, "code")
    if os.path.exists(code_dir) and not overwrite:
        return code_dir
    os.makedirs(code_dir, exist_ok=True)

    for file in code_files:
        code = file.formated_code
        path = file.rel_path
        assert path is not None
        os.makedirs(os.path.dirname(os.path.join(code_dir, path)), exist_ok=True)
        with open(os.path.join(code_dir, path), "w") as f:
            f.write(code)
    return code_dir
