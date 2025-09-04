import json
import os
import sys
from collections import Counter

class StatisticsBase():
    def __init__(self, gt_path, cve_gav_path):
        with open(gt_path, "r") as fr:
            self.gt = json.load(fr)
        with open(cve_gav_path, "r") as fr:
            self.cve_gav = json.load(fr)
    def cve_num(self):
        '''
        @params: gt
        @output: affected lib version, not affected lib version
        '''        
        print(f"cve num is {len(self.gt.keys())}")

    def cwe_num(self):
        '''
        @params: pending 
        @output: pending
        '''
        pass
    def jar_num(self):
        '''
        @params: cve_gav gt
        @output: jars num
        '''
        jar_lst = [ ]
        cves = list(self.gt.keys())
        for cve in cves:
            jar_lst.append(self.cve_gav[cve])

        count = Counter(jar_lst)


        sorted_by_count = count.most_common() 
        print("jar_num: ", len(count))

        sorted_count = dict(sorted(count.items()))
        with open("jar_statistic.json", "w") as fw:
            json.dump(sorted_count, fw, indent = 4)
    def version_num(self):
        '''
        @params: gt
        @output: affected lib version, not affected lib version
        '''
        version_num = 0
        for cve, results in self.gt.items():
            version_num += len(results["affected"])
            version_num += len(results["unaffected"])
        print("version_num: ", version_num)
if __name__ == "__main__":
    gt_path = "trueresult.json"
    cve_gav_path = "/1.empirical/cve_gav_all.json"
    statisticsBase = StatisticsBase(gt_path, cve_gav_path)
    statisticsBase.cve_num()
    statisticsBase.jar_num()
    statisticsBase.version_num()