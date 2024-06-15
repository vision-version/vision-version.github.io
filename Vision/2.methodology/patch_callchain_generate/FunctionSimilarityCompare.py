import json
import os
import hashlib
from itertools import permutations
from icecream import ic
from tqdm import tqdm



def calculate_similarity(code1, code2):
    # print("code1: ", code1)

    hash1 = hashlib.sha256(code1.encode()).hexdigest()
    hash2 = hashlib.sha256(code2.encode()).hexdigest()



    distance = 0
    for c1, c2 in zip(hash1, hash2):
        if c1 != c2:
            distance += 1
            # progress_bar.update(1)
    # distance = sum(c1 != c2 for c1, c2 in zip(hash1, hash2))

    similarity_score = 1 - (distance / max(len(hash1), len(hash2)))

    return similarity_score


def match_deleted_lines(deleted_lines1, deleted_lines2):
    '''
    @description:
    @deleted_lines1:
    @deleted_lines2:
    @return:
    '''
    max_similarity_score = 0

    shorter_list = deleted_lines1 if len(deleted_lines1) < len(deleted_lines2) else deleted_lines2
    longer_list = deleted_lines2 if len(deleted_lines1) < len(deleted_lines2) else deleted_lines1
    

    longer_list += longer_list[: len(shorter_list)]
        

    i = 0
    j = i + len(shorter_list)
    progress_bar = tqdm(total=len(longer_list), desc='???')
    while j <= len(longer_list):
        j = i + len(shorter_list)
        similarity_score = sum(calculate_similarity(code1, code2) for code1, code2 in zip(shorter_list, longer_list[i: j])) / len(shorter_list)  
        max_similarity_score = max(max_similarity_score, similarity_score)       
        progress_bar.update(1)
        i += 1
        # break
    
    return max_similarity_score

def match_deleted_lines_simp(deleted_lines1, deleted_lines2):
    '''
    @description:
    @deleted_lines1:
    @deleted_lines2:
    @return:
    '''
    merged_deleted_lines1 = ''.join(deleted_lines1)
    merged_deleted_lines2 = ''.join(deleted_lines2)
    m = len(merged_deleted_lines1)
    n = len(merged_deleted_lines2)

 
    dp = [[0] * (n + 1) for _ in range(m + 1)]


    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j

  
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if merged_deleted_lines1[i - 1] == merged_deleted_lines2[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]
            else:
                dp[i][j] = min(dp[i - 1][j - 1], dp[i][j - 1], dp[i - 1][j]) + 1

    distance = dp[m][n]
    max_length = max(m, n)
    similarity = 1 - distance / max_length
    return similarity


def compare_functions(func1, func2):
    '''
    @description:
    @func1: Function 1
    @func2: Function 2
    @return:
    '''
    deleted_lines1 = []
    deleted_lines2 = []

    for line in func1:
        for _, code in line.items():
            deleted_lines1.append(code)
    
    for line in func2:
        for _, code in line.items():
            deleted_lines2.append(code)
    # print(f"length of code list 1: {len(deleted_lines1)}, length of code list 2: {len(deleted_lines2)}")
    # simScoreComplex = match_deleted_lines(deleted_lines1, deleted_lines2)
    simScoreSimple = match_deleted_lines_simp(deleted_lines1, deleted_lines2)
    return simScoreSimple


def functionSimComparator(deleteMethodFull: dict):
    '''
    @description:
    @functions:
    @return: dict
    '''
    score = {}
    functions = list(deleteMethodFull.keys())
    # score = {_ : [] for _ in function}
    for i in range(len(functions) - 1):
        for j in range(i + 1, len(functions)):
            method1 = functions[i]
            method2 = functions[j]
            # print(f"length of code list 1: {len(deleteMethodFull[method1]['lineNumber'])}, length of code list 2: {len(deleteMethodFull[method2]['lineNumber'])}")
            similarity_score = compare_functions(deleteMethodFull[method1]["lineNumber"], deleteMethodFull[method2]["lineNumber"])

            if similarity_score >= 0:
                score[f"{method1}__split__{method2}"] = similarity_score
            else: 
                continue
    sorted_score = sorted(score.items(), key=lambda item: item[1], reverse=True)
    return sorted_score


def compute_statistics(score_dict):
    sum = 0
    variance = 0
    max = 0
    n = len(score_dict)
    for func, score in score_dict.items():
        sum += score
        if score > max:
            max = score
    mean = sum / n
    for func, score in score_dict.items():
        variance += (score - mean) ** 2
    variance /= (n - 1)
    score_dict['mean'] = mean
    score_dict['variance'] = variance
    score_dict['max'] = max
    return score_dict


if __name__ == '__main__':
    # work_dir = os.getcwd()
    # methods_dir = "cves_methods.json"
    # results = {}
    # result_stat = {}
    
    # with open(os.path.join(work_dir, methods_dir), "r") as fr:
    #     cve_methods = json.load(fr)
    
    # for cve, methods in cve_methods.items():
    #     old_func_similarity_scores = {}
    #     new_func_similarity_scores = {}
    #     for old_file in methods["old_methods_info"]:
    #         old_func_similarity_scores.update(functionSimComparator(old_file["deleteMethodFull"]))
    #     for new_file in methods["new_methods_info"]:
    #         new_func_similarity_scores.update(functionSimComparator(new_file["addMethodFull"]))
    #     results[cve] = {
    #         'old': old_func_similarity_scores, 
    #         'new': new_func_similarity_scores
    #     }
    #     old_stats = compute_statistics(old_func_similarity_scores)
    #     new_stats = compute_statistics(new_func_similarity_scores)
    #     result_stat[cve] = {
    #         'old': old_stats,
    #         'new': new_stats
    #     }
        
    # with open("function_similarity_test.json", 'w') as fsf:
    #     json.dump(results, fsf, indent=4)
    # with open("function_similarity_stat.json", 'w') as fsf:
    #     json.dump(result_stat, fsf, indent=4)
    print(match_deleted_lines_simp(["123456123"],["456123"]))