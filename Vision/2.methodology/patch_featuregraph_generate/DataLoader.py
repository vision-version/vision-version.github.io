import os
import json



class DataLoader():
    def __init__(self,cve_methods, cve_metainfo):
        self.cve_methods = cve_methods
        self.cve_metainfo = cve_metainfo
        self.cveMethods = self.methodsAcquire()
        self.cveMetaPath = self.metaAcquire()

    def methodsAcquire(self):
        with open(self.cve_methods, "r") as fr:
            return json.load(fr)
    
    def metaAcquire(self):
        with open(self.cve_metainfo, "r") as fr:
            return json.load(fr)        