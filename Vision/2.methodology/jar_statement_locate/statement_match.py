import os
import json
from  icecream import ic
class StatementMatch():
    def __init__(self, cveid, PrePostMethods):
        self.oldMethods = PrePostMethods["old"]
        self.newMethods = PrePostMethods["new"]
    
    def preStatementMatch(self):
        pass
    
    def postStatementMatch(self):
        newMethodsCp = self.newMethods
        for versions4PostMethod in newMethodsCp:
            poststatementMatchResult = newMethodsCp[versions4PostMethod]
            self.nicadstatementClone(versions4PostMethod, poststatementMatchResult)
            break
    
    def nicadstatementClone(self, version, poststatementMatchResult):
        ic(version)
        ic(poststatementMatchResult)