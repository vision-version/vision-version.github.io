from icecream import ic
def analyze_sets(set1, set2):
    result = []
  
    if not set1:
        result.append("1 empty set")
    if not set2:
        result.append("2 empty set")
    
    if set1 & set2:

        if set1.issubset(set2):
            result.append("")
        elif set2.issubset(set1):
            result.append("")
        elif set1 == set2:
            result.append("")
        else:
    
            if set1.isdisjoint(set2):
                result.append("")
            else:
                result.append("")
    return result