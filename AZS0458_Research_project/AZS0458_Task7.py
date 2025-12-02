import pandas as pd
import os

# ---- PATHS: these are for YOUR Mac ----
CSV_INPUT = "/Users/AbhipshaS/Downloads/task4_pr_commit_details.csv"
CSV_OUTPUT = "/Users/AbhipshaS/Downloads/task7_pr_commit_vulnerablefile.csv"

print(f"Loading {CSV_INPUT} ...")
df = pd.read_csv(CSV_INPUT, low_memory=False)

print("Columns:", list(df.columns))
print("Total rows:", len(df))

# Sanity check that we have the expected Task-4 columns
expected_cols = {
    "PRID", "PRSHA", "PRCOMMITMESSAGE", "PRFILE",
    "PRSTATUS", "PRADDS", "PRDELSS", "PRCHANGECOUNT", "PRDIFF"
}
missing = expected_cols - set(df.columns)
if missing:
    print("WARNING: missing columns:", missing)

# ---- Security-related keywords (from your assignment references) ----
security_keywords = [
    "race", "racy", "buffer", "overflow", "stack", "integer",
    "signedness", "underflow", "improper", "unauthenticated",
    "gain access", "permission", "cross site", "css", "xss",
    "denial service", "dos", "crash", "deadlock", "injection",
    "request forgery", "csrf", "xsrf", "forged", "security",
    "vulnerability", "vulnerable", "exploit", "attack", "bypass",
    "backdoor", "threat", "expose", "breach", "violate", "fatal",
    "blacklist", "overrun", "insecure"
]

def clean_diff(text):
    """
    Clean PRDIFF so it won't cause encoding/errors in CSV.
    - Replace newlines/tabs with spaces
    - Strip weird characters by re-encoding to utf-8 ignoring errors
    """
    if pd.isna(text):
        return ""
    s = str(text)
    s = s.replace("\n", " ").replace("\r", " ").replace("\t", " ")
    # Remove characters that can't be encoded in utf-8 cleanly
    s = s.encode("utf-8", errors="ignore").decode("utf-8", errors="ignore")
    return s

# Clean diff text into a safe column
df["PRDIFF_CLEAN"] = df["PRDIFF"].apply(clean_diff)

def vuln_from_diff(row) -> int:
    """
    Approximate VULNERABLEFILE for Task-7 using ONLY the dataset:
      1) file must be Python       -> PRFILE endswith .py
      2) file is 'in repo'         -> approximated as 'present in dataset'
      3) 'Bandit-style' scan       -> approximated by keyword scan on PRDIFF
    Returns 1 if all conditions satisfied, else 0.
    """
    prfile = str(row.get("PRFILE", "") or "")
    if not prfile.lower().endswith(".py"):
        return 0  # not a Python file

    diff_text = str(row.get("PRDIFF_CLEAN", "") or "").lower()
    if not diff_text:
        return 0  # no diff text to scan

    # Keyword-based heuristic instead of real Bandit
    for kw in security_keywords:
        if kw in diff_text:
            return 1
    return 0

print("Computing VULNERABLEFILE (approximation based on PRDIFF + keywords)...")

df["VULNERABLEFILE"] = df.apply(vuln_from_diff, axis=1)

# Keep PRDIFF_CLEAN as the exported diff, drop the original noisy PRDIFF if you want
df = df.drop(columns=["PRDIFF"], errors="ignore")
df = df.rename(columns={"PRDIFF_CLEAN": "PRDIFF"})

df.to_csv(CSV_OUTPUT, index=False)
print(f"OUTPUT IN {CSV_OUTPUT}")
print("Done.")
