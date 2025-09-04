import json


def get_changed_type():

    fp = open("changed_info.json","r")
    changed_info = json.load(fp)
    fp.close()


    fp = open("final_results.json","r")
    results = json.load(fp)
    fp.close()

    changed_methods_results = {}
    changed_methods_results['pure_add'] = {}
    changed_methods_results['pure_add']['VisionPro'] = {}
    changed_methods_results['pure_add']['VisionPro']['tp'] = 0
    changed_methods_results['pure_add']['VisionPro']['fp'] = 0
    changed_methods_results['pure_add']['VisionPro']['fn'] = 0
    changed_methods_results['pure_add']['VisionPro']['tn'] = 0
    changed_methods_results['pure_add']['VisionPro']['pv'] = 0

    changed_methods_results['others'] = {}
    changed_methods_results['others']['VisionPro'] = {}
    changed_methods_results['others']['VisionPro']['tp'] = 0
    changed_methods_results['others']['VisionPro']['fp'] = 0
    changed_methods_results['others']['VisionPro']['fn'] = 0
    changed_methods_results['others']['VisionPro']['tn'] = 0
    changed_methods_results['others']['VisionPro']['pv'] = 0

    changed_methods_results['pure_add']['vuddy'] = {}
    changed_methods_results['pure_add']['vuddy']['tp'] = 0
    changed_methods_results['pure_add']['vuddy']['fp'] = 0
    changed_methods_results['pure_add']['vuddy']['fn'] = 0
    changed_methods_results['pure_add']['vuddy']['tn'] = 0
    changed_methods_results['pure_add']['vuddy']['pv'] = 0

    changed_methods_results['others']['vuddy'] = {}
    changed_methods_results['others']['vuddy']['tp'] = 0
    changed_methods_results['others']['vuddy']['fp'] = 0
    changed_methods_results['others']['vuddy']['fn'] = 0
    changed_methods_results['others']['vuddy']['tn'] = 0
    changed_methods_results['others']['vuddy']['pv'] = 0

    changed_methods_results['pure_add']['v0finder'] = {}
    changed_methods_results['pure_add']['v0finder']['tp'] = 0
    changed_methods_results['pure_add']['v0finder']['fp'] = 0
    changed_methods_results['pure_add']['v0finder']['fn'] = 0
    changed_methods_results['pure_add']['v0finder']['tn'] = 0
    changed_methods_results['pure_add']['v0finder']['pv'] = 0

    changed_methods_results['others']['v0finder'] = {}
    changed_methods_results['others']['v0finder']['tp'] = 0
    changed_methods_results['others']['v0finder']['fp'] = 0
    changed_methods_results['others']['v0finder']['fn'] = 0
    changed_methods_results['others']['v0finder']['tn'] = 0
    changed_methods_results['others']['v0finder']['pv'] = 0 


    changed_methods_results['pure_add']['mvp'] = {}
    changed_methods_results['pure_add']['mvp']['tp'] = 0
    changed_methods_results['pure_add']['mvp']['fp'] = 0
    changed_methods_results['pure_add']['mvp']['fn'] = 0
    changed_methods_results['pure_add']['mvp']['tn'] = 0
    changed_methods_results['pure_add']['mvp']['pv'] = 0

    changed_methods_results['others']['mvp'] = {}
    changed_methods_results['others']['mvp']['tp'] = 0
    changed_methods_results['others']['mvp']['fp'] = 0
    changed_methods_results['others']['mvp']['fn'] = 0
    changed_methods_results['others']['mvp']['tn'] = 0
    changed_methods_results['others']['mvp']['pv'] = 0 
    


    for cve in changed_info['pure_add']:      
        if len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['VisionPro']['affected']))) == len(results[cve]['groundtruth']['affected']) and len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['VisionPro']['unaffected']))) == len(results[cve]['groundtruth']['unaffected']):
            changed_methods_results['pure_add']['VisionPro']['pv'] += 1
        changed_methods_results['pure_add']['VisionPro']['tp'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['VisionPro']['affected'])))
        changed_methods_results['pure_add']['VisionPro']['fp'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['VisionPro']['affected'])))
        changed_methods_results['pure_add']['VisionPro']['fn'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['VisionPro']['unaffected'])))
        changed_methods_results['pure_add']['VisionPro']['tn'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['VisionPro']['unaffected'])))

        if len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['vuddy']['affected']))) == len(results[cve]['groundtruth']['affected']) and len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['vuddy']['unaffected']))) == len(results[cve]['groundtruth']['unaffected']):
            changed_methods_results['pure_add']['vuddy']['pv'] += 1
        changed_methods_results['pure_add']['vuddy']['tp'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['vuddy']['affected'])))
        changed_methods_results['pure_add']['vuddy']['fp'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['vuddy']['affected'])))
        changed_methods_results['pure_add']['vuddy']['fn'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['vuddy']['unaffected'])))
        changed_methods_results['pure_add']['vuddy']['tn'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['vuddy']['unaffected'])))

        if len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['v0finder']['affected']))) == len(results[cve]['groundtruth']['affected']) and len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['v0finder']['unaffected']))) == len(results[cve]['groundtruth']['unaffected']):
            changed_methods_results['pure_add']['v0finder']['pv'] += 1
        changed_methods_results['pure_add']['v0finder']['tp'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['v0finder']['affected'])))
        changed_methods_results['pure_add']['v0finder']['fp'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['v0finder']['affected'])))
        changed_methods_results['pure_add']['v0finder']['fn'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['v0finder']['unaffected'])))
        changed_methods_results['pure_add']['v0finder']['tn'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['v0finder']['unaffected'])))

        if len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['mvp']['affected']))) == len(results[cve]['groundtruth']['affected']) and len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['mvp']['unaffected']))) == len(results[cve]['groundtruth']['unaffected']):
            changed_methods_results['pure_add']['mvp']['pv'] += 1
        changed_methods_results['pure_add']['mvp']['tp'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['mvp']['affected'])))
        changed_methods_results['pure_add']['mvp']['fp'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['mvp']['affected'])))
        changed_methods_results['pure_add']['mvp']['fn'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['mvp']['unaffected'])))
        changed_methods_results['pure_add']['mvp']['tn'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['mvp']['unaffected'])))
    for tool in changed_methods_results['pure_add']:
        changed_methods_results['pure_add'][tool]['pre'] = changed_methods_results['pure_add'][tool]['tp'] / (changed_methods_results['pure_add'][tool]['tp'] + changed_methods_results['pure_add'][tool]['fp'])
        changed_methods_results['pure_add'][tool]['rec'] = changed_methods_results['pure_add'][tool]['tp'] / (changed_methods_results['pure_add'][tool]['tp'] + changed_methods_results['pure_add'][tool]['fn'])
        changed_methods_results['pure_add'][tool]['f1'] = 2 * changed_methods_results['pure_add'][tool]['pre'] * changed_methods_results['pure_add'][tool]['rec'] / (changed_methods_results['pure_add'][tool]['pre'] + changed_methods_results['pure_add'][tool]['rec'])



    for cve in changed_info['others']:      
        if len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['VisionPro']['affected']))) == len(results[cve]['groundtruth']['affected']) and len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['VisionPro']['unaffected']))) == len(results[cve]['groundtruth']['unaffected']):
            changed_methods_results['others']['VisionPro']['pv'] += 1
        changed_methods_results['others']['VisionPro']['tp'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['VisionPro']['affected'])))
        changed_methods_results['others']['VisionPro']['fp'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['VisionPro']['affected'])))
        changed_methods_results['others']['VisionPro']['fn'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['VisionPro']['unaffected'])))
        changed_methods_results['others']['VisionPro']['tn'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['VisionPro']['unaffected'])))

        if len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['vuddy']['affected']))) == len(results[cve]['groundtruth']['affected']) and len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['vuddy']['unaffected']))) == len(results[cve]['groundtruth']['unaffected']):
            changed_methods_results['others']['vuddy']['pv'] += 1
        changed_methods_results['others']['vuddy']['tp'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['vuddy']['affected'])))
        changed_methods_results['others']['vuddy']['fp'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['vuddy']['affected'])))
        changed_methods_results['others']['vuddy']['fn'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['vuddy']['unaffected'])))
        changed_methods_results['others']['vuddy']['tn'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['vuddy']['unaffected'])))

        if len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['v0finder']['affected']))) == len(results[cve]['groundtruth']['affected']) and len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['v0finder']['unaffected']))) == len(results[cve]['groundtruth']['unaffected']):
            changed_methods_results['others']['v0finder']['pv'] += 1
        changed_methods_results['others']['v0finder']['tp'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['v0finder']['affected'])))
        changed_methods_results['others']['v0finder']['fp'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['v0finder']['affected'])))
        changed_methods_results['others']['v0finder']['fn'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['v0finder']['unaffected'])))
        changed_methods_results['others']['v0finder']['tn'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['v0finder']['unaffected'])))
        if len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['mvp']['affected']))) == len(results[cve]['groundtruth']['affected']) and len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['mvp']['unaffected']))) == len(results[cve]['groundtruth']['unaffected']):
            changed_methods_results['others']['mvp']['pv'] += 1
        changed_methods_results['others']['mvp']['tp'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['mvp']['affected'])))
        changed_methods_results['others']['mvp']['fp'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['mvp']['affected'])))
        changed_methods_results['others']['mvp']['fn'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['mvp']['unaffected'])))
        changed_methods_results['others']['mvp']['tn'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['mvp']['unaffected'])))

    
    for tool in changed_methods_results['others']:
        changed_methods_results['others'][tool]['pre'] = changed_methods_results['others'][tool]['tp'] / (changed_methods_results['others'][tool]['tp'] + changed_methods_results['others'][tool]['fp'])
        changed_methods_results['others'][tool]['rec'] = changed_methods_results['others'][tool]['tp'] / (changed_methods_results['others'][tool]['tp'] + changed_methods_results['others'][tool]['fn'])    
        changed_methods_results['others'][tool]['f1'] = 2 * changed_methods_results['others'][tool]['pre'] * changed_methods_results['others'][tool]['rec'] / (changed_methods_results['others'][tool]['pre'] + changed_methods_results['others'][tool]['rec'])
    
    fp = open("changed_type_results.json", "w")
    json.dump(changed_methods_results, fp, indent=4)
    fp.close()

if __name__ == "__main__":
    get_changed_type()