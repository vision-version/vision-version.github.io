import json

# Original JSON data
with open("inconsistency_results.json", "r") as f:
    data = json.load(f)

# Map JSON keys to row labels in LaTeX
latex_labels = {
    "VD_A, VD_B": r"$\langle VD\_A, VD\_B\rangle$",
    "VD_A, VD_C": r"$\langle VD\_A, VD\_C\rangle$",
    "VD_A, VD_D": r"$\langle VD\_A, VD\_D\rangle$",
    "VD_A, VD_E": r"$\langle VD\_A, VD\_E\rangle$",
    "VD_B, VD_C": r"$\langle VD\_B, VD\_C\rangle$",
    "VD_B, VD_D": r"$\langle VD\_B, VD\_D\rangle$",
    "VD_B, VD_E": r"$\langle VD\_B, VD\_E\rangle$",
    "VD_C, VD_D": r"$\langle VD\_C, VD\_D\rangle$",
    "VD_C, VD_E": r"$\langle VD\_C, VD\_E\rangle$",
    "VD_D, VD_E": r"$\langle VD\_D, VD\_E\rangle$",
}

# Initialize totals
totals = {"equal": 0, "disjoint": 0, "contain": 0, "contained": 0, "overlap": 0}

# Print each row
for key, counts in data.items():
    eq = counts["equal"]
    dis = counts["disjoint"]
    con = counts["contain"]
    cdt = counts["contained"]
    ov = counts["overlap"]
    row_total = eq + dis + con + cdt + ov
    
    # Accumulate to totals
    totals["equal"]     += eq
    totals["disjoint"]  += dis
    totals["contain"]   += con
    totals["contained"] += cdt
    totals["overlap"]   += ov
    
    # Calculate percentages
    p_eq  = eq  / row_total * 100
    p_dis = dis / row_total * 100
    p_con = con / row_total * 100
    p_cdt = cdt / row_total * 100
    p_ov  = ov  / row_total * 100
    
    # Output LaTeX format
    print(f"{latex_labels[key]} & "
          f"{eq:,} ({p_eq:.1f}\\%) & "
          f"{dis:,} ({p_dis:.1f}\\%) & "
          f"{con:,} ({p_con:.1f}\\%) & "
          f"{cdt:,} ({p_cdt:.1f}\\%) & "
          f"{ov:,} ({p_ov:.1f}\\%) & "
          f"{row_total:,} \\\\")

# Print summary row
grand_total = sum(totals.values())
print(r"\hline")
print("Total & "
      f"{totals['equal']:,} & "
      f"{totals['disjoint']:,} & "
      f"{totals['contain']:,} & "
      f"{totals['contained']:,} & "
      f"{totals['overlap']:,} & "
      f"{grand_total:,} \\\\")