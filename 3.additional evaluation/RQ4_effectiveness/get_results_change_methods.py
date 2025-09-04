import json

def get_changed_methods_patch():
    changed_methods_results = {}
    fp = open("changed_info.json","r")
    changed_info = json.load(fp)
    fp.close()

    fp = open("final_results.json","r")
    results = json.load(fp)
    fp.close()

    changed_methods_results['cm_1'] = {}
    changed_methods_results['cm_1']['VisionPro'] = {}
    changed_methods_results['cm_1']['VisionPro']['tp'] = 0
    changed_methods_results['cm_1']['VisionPro']['fp'] = 0
    changed_methods_results['cm_1']['VisionPro']['fn'] = 0
    changed_methods_results['cm_1']['VisionPro']['tn'] = 0
    changed_methods_results['cm_1']['VisionPro']['pv'] = 0
    changed_methods_results['cm_1']['vuddy'] = {}
    changed_methods_results['cm_1']['vuddy']['tp'] = 0
    changed_methods_results['cm_1']['vuddy']['fp'] = 0
    changed_methods_results['cm_1']['vuddy']['fn'] = 0
    changed_methods_results['cm_1']['vuddy']['tn'] = 0
    changed_methods_results['cm_1']['vuddy']['pv'] = 0
    changed_methods_results['cm_1']['v0finder'] = {}
    changed_methods_results['cm_1']['v0finder']['tp'] = 0
    changed_methods_results['cm_1']['v0finder']['fp'] = 0
    changed_methods_results['cm_1']['v0finder']['fn'] = 0
    changed_methods_results['cm_1']['v0finder']['tn'] = 0
    changed_methods_results['cm_1']['v0finder']['pv'] = 0
    changed_methods_results['cm_1']['mvp'] = {}
    changed_methods_results['cm_1']['mvp']['tp'] = 0
    changed_methods_results['cm_1']['mvp']['fp'] = 0
    changed_methods_results['cm_1']['mvp']['fn'] = 0
    changed_methods_results['cm_1']['mvp']['tn'] = 0
    changed_methods_results['cm_1']['mvp']['pv'] = 0
    for cve in changed_info['cm_1']:        
        if len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['VisionPro']['affected']))) == len(results[cve]['groundtruth']['affected']) and len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['VisionPro']['unaffected']))) == len(results[cve]['groundtruth']['unaffected']):
            changed_methods_results['cm_1']['VisionPro']['pv'] += 1
        changed_methods_results['cm_1']['VisionPro']['tp'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['VisionPro']['affected'])))
        changed_methods_results['cm_1']['VisionPro']['fp'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['VisionPro']['affected'])))
        changed_methods_results['cm_1']['VisionPro']['fn'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['VisionPro']['unaffected'])))
        changed_methods_results['cm_1']['VisionPro']['tn'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['VisionPro']['unaffected'])))

        if len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['vuddy']['affected']))) == len(results[cve]['groundtruth']['affected']) and len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['vuddy']['unaffected']))) == len(results[cve]['groundtruth']['unaffected']):
            changed_methods_results['cm_1']['vuddy']['pv'] += 1
        changed_methods_results['cm_1']['vuddy']['tp'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['vuddy']['affected'])))
        changed_methods_results['cm_1']['vuddy']['fp'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['vuddy']['affected'])))
        changed_methods_results['cm_1']['vuddy']['fn'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['vuddy']['unaffected'])))
        changed_methods_results['cm_1']['vuddy']['tn'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['vuddy']['unaffected'])))

        if len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['v0finder']['affected']))) == len(results[cve]['groundtruth']['affected']) and len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['v0finder']['unaffected']))) == len(results[cve]['groundtruth']['unaffected']):
            changed_methods_results['cm_1']['v0finder']['pv'] += 1
        changed_methods_results['cm_1']['v0finder']['tp'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['v0finder']['affected'])))
        changed_methods_results['cm_1']['v0finder']['fp'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['v0finder']['affected'])))
        changed_methods_results['cm_1']['v0finder']['fn'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['v0finder']['unaffected'])))
        changed_methods_results['cm_1']['v0finder']['tn'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['v0finder']['unaffected'])))


        if len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['mvp']['affected']))) == len(results[cve]['groundtruth']['affected']) and len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['mvp']['unaffected']))) == len(results[cve]['groundtruth']['unaffected']):
            changed_methods_results['cm_1']['mvp']['pv'] += 1
        changed_methods_results['cm_1']['mvp']['tp'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['mvp']['affected'])))
        changed_methods_results['cm_1']['mvp']['fp'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['mvp']['affected'])))
        changed_methods_results['cm_1']['mvp']['fn'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['mvp']['unaffected'])))
        changed_methods_results['cm_1']['mvp']['tn'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['mvp']['unaffected'])))


    changed_methods_results['cm_1']['VisionPro']['pre'] = changed_methods_results['cm_1']['VisionPro']['tp'] / (changed_methods_results['cm_1']['VisionPro']['tp'] + changed_methods_results['cm_1']['VisionPro']['fp'])
    changed_methods_results['cm_1']['VisionPro']['rec'] = changed_methods_results['cm_1']['VisionPro']['tp'] / (changed_methods_results['cm_1']['VisionPro']['tp'] + changed_methods_results['cm_1']['VisionPro']['fn'])
    changed_methods_results['cm_1']['VisionPro']['f1'] = 2 * changed_methods_results['cm_1']['VisionPro']['pre'] * changed_methods_results['cm_1']['VisionPro']['rec'] / (changed_methods_results['cm_1']['VisionPro']['pre'] + changed_methods_results['cm_1']['VisionPro']['rec'])

    changed_methods_results['cm_1']['vuddy']['pre'] = changed_methods_results['cm_1']['vuddy']['tp'] / (changed_methods_results['cm_1']['vuddy']['tp'] + changed_methods_results['cm_1']['vuddy']['fp'])
    changed_methods_results['cm_1']['vuddy']['rec'] = changed_methods_results['cm_1']['vuddy']['tp'] / (changed_methods_results['cm_1']['vuddy']['tp'] + changed_methods_results['cm_1']['vuddy']['fn'])
    changed_methods_results['cm_1']['vuddy']['f1'] = 2 * changed_methods_results['cm_1']['vuddy']['pre'] * changed_methods_results['cm_1']['vuddy']['rec'] / (changed_methods_results['cm_1']['vuddy']['pre'] + changed_methods_results['cm_1']['vuddy']['rec'])

    changed_methods_results['cm_1']['v0finder']['pre'] = changed_methods_results['cm_1']['v0finder']['tp'] / (changed_methods_results['cm_1']['v0finder']['tp'] + changed_methods_results['cm_1']['v0finder']['fp'])
    changed_methods_results['cm_1']['v0finder']['rec'] = changed_methods_results['cm_1']['v0finder']['tp'] / (changed_methods_results['cm_1']['v0finder']['tp'] + changed_methods_results['cm_1']['v0finder']['fn'])
    changed_methods_results['cm_1']['v0finder']['f1'] = 2 * changed_methods_results['cm_1']['v0finder']['pre'] * changed_methods_results['cm_1']['v0finder']['rec'] / (changed_methods_results['cm_1']['v0finder']['pre'] + changed_methods_results['cm_1']['v0finder']['rec'])
        
    changed_methods_results['cm_1']['mvp']['pre'] = changed_methods_results['cm_1']['mvp']['tp'] / (changed_methods_results['cm_1']['mvp']['tp'] + changed_methods_results['cm_1']['mvp']['fp'])
    changed_methods_results['cm_1']['mvp']['rec'] = changed_methods_results['cm_1']['mvp']['tp'] / (changed_methods_results['cm_1']['mvp']['tp'] + changed_methods_results['cm_1']['mvp']['fn'])
    changed_methods_results['cm_1']['mvp']['f1'] = 2 * changed_methods_results['cm_1']['mvp']['pre'] * changed_methods_results['cm_1']['mvp']['rec'] / (changed_methods_results['cm_1']['mvp']['pre'] + changed_methods_results['cm_1']['mvp']['rec'])
        
    changed_methods_results['cm_25'] = {}
    changed_methods_results['cm_25']['VisionPro'] = {}
    changed_methods_results['cm_25']['VisionPro']['tp'] = 0
    changed_methods_results['cm_25']['VisionPro']['fp'] = 0
    changed_methods_results['cm_25']['VisionPro']['fn'] = 0
    changed_methods_results['cm_25']['VisionPro']['tn'] = 0
    changed_methods_results['cm_25']['VisionPro']['pv'] = 0

    changed_methods_results['cm_25']['vuddy'] = {}
    changed_methods_results['cm_25']['vuddy']['tp'] = 0
    changed_methods_results['cm_25']['vuddy']['fp'] = 0
    changed_methods_results['cm_25']['vuddy']['fn'] = 0
    changed_methods_results['cm_25']['vuddy']['tn'] = 0
    changed_methods_results['cm_25']['vuddy']['pv'] = 0

    changed_methods_results['cm_25']['v0finder'] = {}
    changed_methods_results['cm_25']['v0finder']['tp'] = 0
    changed_methods_results['cm_25']['v0finder']['fp'] = 0
    changed_methods_results['cm_25']['v0finder']['fn'] = 0
    changed_methods_results['cm_25']['v0finder']['tn'] = 0
    changed_methods_results['cm_25']['v0finder']['pv'] = 0
    changed_methods_results['cm_25']['mvp'] = {}
    changed_methods_results['cm_25']['mvp']['tp'] = 0
    changed_methods_results['cm_25']['mvp']['fp'] = 0
    changed_methods_results['cm_25']['mvp']['fn'] = 0
    changed_methods_results['cm_25']['mvp']['tn'] = 0
    changed_methods_results['cm_25']['mvp']['pv'] = 0


    for cve in changed_info['cm_25']:
        if len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['VisionPro']['affected']))) == len(results[cve]['groundtruth']['affected']) and len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['VisionPro']['unaffected']))) == len(results[cve]['groundtruth']['unaffected']):
            changed_methods_results['cm_25']['VisionPro']['pv'] += 1
        changed_methods_results['cm_25']['VisionPro']['tp'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['VisionPro']['affected'])))
        changed_methods_results['cm_25']['VisionPro']['fp'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['VisionPro']['affected'])))
        changed_methods_results['cm_25']['VisionPro']['fn'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['VisionPro']['unaffected'])))
        changed_methods_results['cm_25']['VisionPro']['tn'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['VisionPro']['unaffected'])))

        if len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['vuddy']['affected']))) == len(results[cve]['groundtruth']['affected']) and len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['vuddy']['unaffected']))) == len(results[cve]['groundtruth']['unaffected']):
            changed_methods_results['cm_25']['vuddy']['pv'] += 1
        changed_methods_results['cm_25']['vuddy']['tp'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['vuddy']['affected'])))
        changed_methods_results['cm_25']['vuddy']['fp'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['vuddy']['affected'])))
        changed_methods_results['cm_25']['vuddy']['fn'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['vuddy']['unaffected'])))
        changed_methods_results['cm_25']['vuddy']['tn'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['vuddy']['unaffected'])))

        if len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['v0finder']['affected']))) == len(results[cve]['groundtruth']['affected']) and len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['v0finder']['unaffected']))) == len(results[cve]['groundtruth']['unaffected']):
            changed_methods_results['cm_25']['v0finder']['pv'] += 1
        changed_methods_results['cm_25']['v0finder']['tp'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['v0finder']['affected'])))
        changed_methods_results['cm_25']['v0finder']['fp'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['v0finder']['affected'])))
        changed_methods_results['cm_25']['v0finder']['fn'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['v0finder']['unaffected'])))
        changed_methods_results['cm_25']['v0finder']['tn'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['v0finder']['unaffected'])))
        if len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['mvp']['affected']))) == len(results[cve]['groundtruth']['affected']) and len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['mvp']['unaffected']))) == len(results[cve]['groundtruth']['unaffected']):
            changed_methods_results['cm_25']['mvp']['pv'] += 1
        changed_methods_results['cm_25']['mvp']['tp'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['mvp']['affected'])))
        changed_methods_results['cm_25']['mvp']['fp'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['mvp']['affected'])))
        changed_methods_results['cm_25']['mvp']['fn'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['mvp']['unaffected'])))
        changed_methods_results['cm_25']['mvp']['tn'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['mvp']['unaffected'])))
    
    
    changed_methods_results['cm_25']['VisionPro']['pre'] = changed_methods_results['cm_25']['VisionPro']['tp'] / (changed_methods_results['cm_25']['VisionPro']['tp'] + changed_methods_results['cm_25']['VisionPro']['fp'])
    changed_methods_results['cm_25']['VisionPro']['rec'] = changed_methods_results['cm_25']['VisionPro']['tp'] / (changed_methods_results['cm_25']['VisionPro']['tp'] + changed_methods_results['cm_25']['VisionPro']['fn'])
    changed_methods_results['cm_25']['VisionPro']['f1'] = 2 * changed_methods_results['cm_25']['VisionPro']['pre'] * changed_methods_results['cm_25']['VisionPro']['rec'] / (changed_methods_results['cm_25']['VisionPro']['pre'] + changed_methods_results['cm_25']['VisionPro']['rec'])

    changed_methods_results['cm_25']['vuddy']['pre'] = changed_methods_results['cm_25']['vuddy']['tp'] / (changed_methods_results['cm_25']['vuddy']['tp'] + changed_methods_results['cm_25']['vuddy']['fp'])
    changed_methods_results['cm_25']['vuddy']['rec'] = changed_methods_results['cm_25']['vuddy']['tp'] / (changed_methods_results['cm_25']['vuddy']['tp'] + changed_methods_results['cm_25']['vuddy']['fn'])
    changed_methods_results['cm_25']['vuddy']['f1'] = 2 * changed_methods_results['cm_25']['vuddy']['pre'] * changed_methods_results['cm_25']['vuddy']['rec'] / (changed_methods_results['cm_25']['vuddy']['pre'] + changed_methods_results['cm_25']['vuddy']['rec'])
    
    changed_methods_results['cm_25']['v0finder']['pre'] = changed_methods_results['cm_25']['v0finder']['tp'] / (changed_methods_results['cm_25']['v0finder']['tp'] + changed_methods_results['cm_25']['v0finder']['fp'])
    changed_methods_results['cm_25']['v0finder']['rec'] = changed_methods_results['cm_25']['v0finder']['tp'] / (changed_methods_results['cm_25']['v0finder']['tp'] + changed_methods_results['cm_25']['v0finder']['fn'])
    changed_methods_results['cm_25']['v0finder']['f1'] = 2 * changed_methods_results['cm_25']['v0finder']['pre'] * changed_methods_results['cm_25']['v0finder']['rec'] / (changed_methods_results['cm_25']['v0finder']['pre'] + changed_methods_results['cm_25']['v0finder']['rec'])

    changed_methods_results['cm_25']['mvp']['pre'] = changed_methods_results['cm_25']['mvp']['tp'] / (changed_methods_results['cm_25']['mvp']['tp'] + changed_methods_results['cm_25']['mvp']['fp'])
    changed_methods_results['cm_25']['mvp']['rec'] = changed_methods_results['cm_25']['mvp']['tp'] / (changed_methods_results['cm_25']['mvp']['tp'] + changed_methods_results['cm_25']['mvp']['fn'])
    changed_methods_results['cm_25']['mvp']['f1'] = 2 * changed_methods_results['cm_25']['mvp']['pre'] * changed_methods_results['cm_25']['mvp']['rec'] / (changed_methods_results['cm_25']['mvp']['pre'] + changed_methods_results['cm_25']['mvp']['rec'])

    changed_methods_results['cm_5'] = {}
    changed_methods_results['cm_5']['VisionPro'] = {}
    changed_methods_results['cm_5']['VisionPro']['tp'] = 0  
    changed_methods_results['cm_5']['VisionPro']['fp'] = 0
    changed_methods_results['cm_5']['VisionPro']['fn'] = 0
    changed_methods_results['cm_5']['VisionPro']['tn'] = 0
    changed_methods_results['cm_5']['VisionPro']['pv'] = 0

    changed_methods_results['cm_5']['vuddy'] = {}
    changed_methods_results['cm_5']['vuddy']['tp'] = 0  
    changed_methods_results['cm_5']['vuddy']['fp'] = 0
    changed_methods_results['cm_5']['vuddy']['fn'] = 0
    changed_methods_results['cm_5']['vuddy']['tn'] = 0
    changed_methods_results['cm_5']['vuddy']['pv'] = 0

    changed_methods_results['cm_5']['v0finder'] = {}
    changed_methods_results['cm_5']['v0finder']['tp'] = 0
    changed_methods_results['cm_5']['v0finder']['fp'] = 0
    changed_methods_results['cm_5']['v0finder']['fn'] = 0
    changed_methods_results['cm_5']['v0finder']['tn'] = 0
    changed_methods_results['cm_5']['v0finder']['pv'] = 0

    changed_methods_results['cm_5']['mvp'] = {}
    changed_methods_results['cm_5']['mvp']['tp'] = 0
    changed_methods_results['cm_5']['mvp']['fp'] = 0
    changed_methods_results['cm_5']['mvp']['fn'] = 0
    changed_methods_results['cm_5']['mvp']['tn'] = 0
    changed_methods_results['cm_5']['mvp']['pv'] = 0

    for cve in changed_info['cm_5']:
        if len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['VisionPro']['affected']))) == len(results[cve]['groundtruth']['affected']) and len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['VisionPro']['unaffected']))) == len(results[cve]['groundtruth']['unaffected']):
            changed_methods_results['cm_5']['VisionPro']['pv'] += 1
        changed_methods_results['cm_5']['VisionPro']['tp'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['VisionPro']['affected'])))
        changed_methods_results['cm_5']['VisionPro']['fp'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['VisionPro']['affected'])))
        changed_methods_results['cm_5']['VisionPro']['fn'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['VisionPro']['unaffected'])))
        changed_methods_results['cm_5']['VisionPro']['tn'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['VisionPro']['unaffected'])))

        if len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['vuddy']['affected']))) == len(results[cve]['groundtruth']['affected']) and len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['vuddy']['unaffected']))) == len(results[cve]['groundtruth']['unaffected']):
            changed_methods_results['cm_5']['vuddy']['pv'] += 1
        changed_methods_results['cm_5']['vuddy']['tp'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['vuddy']['affected'])))
        changed_methods_results['cm_5']['vuddy']['fp'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['vuddy']['affected'])))
        changed_methods_results['cm_5']['vuddy']['fn'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['vuddy']['unaffected'])))
        changed_methods_results['cm_5']['vuddy']['tn'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['vuddy']['unaffected'])))

        if len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['v0finder']['affected']))) == len(results[cve]['groundtruth']['affected']) and len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['v0finder']['unaffected']))) == len(results[cve]['groundtruth']['unaffected']):
            changed_methods_results['cm_5']['v0finder']['pv'] += 1
        changed_methods_results['cm_5']['v0finder']['tp'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['v0finder']['affected'])))
        changed_methods_results['cm_5']['v0finder']['fp'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['v0finder']['affected'])))
        changed_methods_results['cm_5']['v0finder']['fn'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['v0finder']['unaffected'])))
        changed_methods_results['cm_5']['v0finder']['tn'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['v0finder']['unaffected'])))

        if len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['mvp']['affected']))) == len(results[cve]['groundtruth']['affected']) and len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['mvp']['unaffected']))) == len(results[cve]['groundtruth']['unaffected']):
            changed_methods_results['cm_5']['mvp']['pv'] += 1
        changed_methods_results['cm_5']['mvp']['tp'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['mvp']['affected'])))
        changed_methods_results['cm_5']['mvp']['fp'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['mvp']['affected'])))
        changed_methods_results['cm_5']['mvp']['fn'] += len(set(results[cve]['groundtruth']['affected']).intersection(set(results[cve]['mvp']['unaffected'])))
        changed_methods_results['cm_5']['mvp']['tn'] += len(set(results[cve]['groundtruth']['unaffected']).intersection(set(results[cve]['mvp']['unaffected'])))


    changed_methods_results['cm_5']['VisionPro']['pre'] = changed_methods_results['cm_5']['VisionPro']['tp'] / (changed_methods_results['cm_5']['VisionPro']['tp'] + changed_methods_results['cm_5']['VisionPro']['fp'])
    changed_methods_results['cm_5']['VisionPro']['rec'] = changed_methods_results['cm_5']['VisionPro']['tp'] / (changed_methods_results['cm_5']['VisionPro']['tp'] + changed_methods_results['cm_5']['VisionPro']['fn'])
    changed_methods_results['cm_5']['VisionPro']['f1'] = 2 * changed_methods_results['cm_5']['VisionPro']['pre'] * changed_methods_results['cm_5']['VisionPro']['rec'] / (changed_methods_results['cm_5']['VisionPro']['pre'] + changed_methods_results['cm_5']['VisionPro']['rec'])

    changed_methods_results['cm_5']['vuddy']['pre'] = changed_methods_results['cm_5']['vuddy']['tp'] / (changed_methods_results['cm_5']['vuddy']['tp'] + changed_methods_results['cm_5']['vuddy']['fp'])
    changed_methods_results['cm_5']['vuddy']['rec'] = changed_methods_results['cm_5']['vuddy']['tp'] / (changed_methods_results['cm_5']['vuddy']['tp'] + changed_methods_results['cm_5']['vuddy']['fn'])    
    changed_methods_results['cm_5']['vuddy']['f1'] = 2 * changed_methods_results['cm_5']['vuddy']['pre'] * changed_methods_results['cm_5']['vuddy']['rec'] / (changed_methods_results['cm_5']['vuddy']['pre'] + changed_methods_results['cm_5']['vuddy']['rec'])

    changed_methods_results['cm_5']['v0finder']['pre'] = changed_methods_results['cm_5']['v0finder']['tp'] / (changed_methods_results['cm_5']['v0finder']['tp'] + changed_methods_results['cm_5']['v0finder']['fp'])
    changed_methods_results['cm_5']['v0finder']['rec'] = changed_methods_results['cm_5']['v0finder']['tp'] / (changed_methods_results['cm_5']['v0finder']['tp'] + changed_methods_results['cm_5']['v0finder']['fn'])
    changed_methods_results['cm_5']['v0finder']['f1'] = 2 * changed_methods_results['cm_5']['v0finder']['pre'] * changed_methods_results['cm_5']['v0finder']['rec'] / (changed_methods_results['cm_5']['v0finder']['pre'] + changed_methods_results['cm_5']['v0finder']['rec'])
    changed_methods_results['cm_5']['mvp']['pre'] = changed_methods_results['cm_5']['mvp']['tp'] / (changed_methods_results['cm_5']['mvp']['tp'] + changed_methods_results['cm_5']['mvp']['fp'])
    changed_methods_results['cm_5']['mvp']['rec'] = changed_methods_results['cm_5']['mvp']['tp'] / (changed_methods_results['cm_5']['mvp']['tp'] + changed_methods_results['cm_5']['mvp']['fn'])
    changed_methods_results['cm_5']['mvp']['f1'] = 2 * changed_methods_results['cm_5']['mvp']['pre'] * changed_methods_results['cm_5']['mvp']['rec'] / (changed_methods_results['cm_5']['mvp']['pre'] + changed_methods_results['cm_5']['mvp']['rec'])

    fp = open("changed_methods_results.json","w")
    json.dump(changed_methods_results, fp, indent=4)
    fp.close()

if __name__ == "__main__":
    get_changed_methods_patch()