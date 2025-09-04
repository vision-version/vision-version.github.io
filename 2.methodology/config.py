import platform

version = "3.1.0"
pf = platform.platform()
if "Windows" in pf:
    gitBinary = r"D:\Program Files\Git\bin\git.exe"
    diffBinary = r"D:\Program Files\Git\usr\bin\diff.exe"
else:
    gitBinary = "git"
    diffBinary = "diff"
    javaBinary = "java"

CTAGS_PATH = "/path/to/ctags"
joern_path = "/path/to/joern-cli"
