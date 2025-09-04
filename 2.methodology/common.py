from enum import Enum


class Language(Enum):
    JAVA = "javasrc"
    C = "newc"
    CPP = "newc"


class HunkType(Enum):
    ADD = "add"
    DEL = "del"
    MOD = "mod"
