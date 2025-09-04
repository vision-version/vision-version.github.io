import json
import os

def get_effective_results():
    fp = open("final_results.json","r")
    results = json.load(fp)
    fp.close()

    tp = 0
    fp = 0
    fn = 0
    tn = 0
    pv = 0
    for cve in results.keys():
        if len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['VisionPro']['affected']))) == len(results[cve]['groundtruth']['affected']) and len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['VisionPro']['unaffected']))) == len(results[cve]['groundtruth']['unaffected']):
            pv += 1
        tp += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['VisionPro']['affected'])))
        fp += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['VisionPro']['affected'])))
        fn += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['VisionPro']['unaffected'])))
        tn += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['VisionPro']['unaffected'])))

    precision = tp / (tp + fp)
    recall = tp / (tp + fn)
    f1_score = 2 * precision * recall / (precision + recall)
    print("visionpro:", tp, fp, fn, tn, precision, recall, f1_score, pv)
 
def get_effective_results_vuddy():
    fp = open("final_results.json","r")
    results = json.load(fp)
    fp.close()

    tp = 0
    fp = 0
    fn = 0
    tn = 0
    pv = 0
    for cve in results.keys():
        if len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['vuddy']['affected']))) == len(results[cve]['groundtruth']['affected']) and len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['vuddy']['unaffected']))) == len(results[cve]['groundtruth']['unaffected']):
            pv += 1
        tp += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['vuddy']['affected'])))
        fp += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['vuddy']['affected'])))
        fn += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['vuddy']['unaffected'])))
        tn += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['vuddy']['unaffected'])))

    precision = tp / (tp + fp)
    recall = tp / (tp + fn)
    f1_score = 2 * precision * recall / (precision + recall)
    print("vuddy:", tp, fp, fn, tn, precision, recall, f1_score, pv)

def get_effective_results_v0finder():
    fp = open("final_results.json","r")
    results = json.load(fp)
    fp.close()

    tp = 0
    fp = 0
    fn = 0
    tn = 0
    pv = 0
    for cve in results.keys():
        if len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['v0finder']['affected']))) == len(results[cve]['groundtruth']['affected']) and len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['v0finder']['unaffected']))) == len(results[cve]['groundtruth']['unaffected']):
            pv += 1
        tp += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['v0finder']['affected'])))
        fp += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['v0finder']['affected'])))
        fn += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['v0finder']['unaffected'])))
        tn += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['v0finder']['unaffected'])))

    precision = tp / (tp + fp)
    recall = tp / (tp + fn)
    f1_score = 2 * precision * recall / (precision + recall)
    print("v0finder:", tp, fp, fn, tn, precision, recall, f1_score, pv)

def get_effective_results_mvp():
    fp = open("final_results.json","r")
    results = json.load(fp)
    fp.close()

    tp = 0
    fp = 0
    fn = 0
    tn = 0
    pv = 0
    for cve in results.keys():
        if len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['mvp']['affected']))) == len(results[cve]['groundtruth']['affected']) and len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['mvp']['unaffected']))) == len(results[cve]['groundtruth']['unaffected']):
            pv += 1
        tp += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['mvp']['affected'])))
        fp += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['mvp']['affected'])))
        fn += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['mvp']['unaffected'])))
        tn += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['mvp']['unaffected'])))

    precision = tp / (tp + fp)
    recall = tp / (tp + fn)
    f1_score = 2 * precision * recall / (precision + recall)
    print("mvp:", tp, fp, fn, tn, precision, recall, f1_score, pv)

if __name__ == "__main__":
    get_effective_results()
    get_effective_results_vuddy()
    get_effective_results_v0finder()
    get_effective_results_mvp()
