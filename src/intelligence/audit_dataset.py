"""
Audit of the raw CICIDS2017 CSVs

Runs on the ORIGINAL files. Reads only; never writes to data/raw/.

Usage:
    python src/intelligence/audit_dataset.py                #It runs on full dataset
    python src/intelligence/audit_dataset.py --sample       #It runs on a sample of the dataset (60k rows per CSV)

Sections:
    1. Schema and label inventory
    2. Data quality: constants, NaN, inf, negatives
    3. Bit-identical duplicate columns
    4. TCP flag audit (the reproducibility question)
    5. Unit and semantics evidence (microseconds, payload, integer ratio)
    6. Environment-fingerprint check (initial TCP window)
"""

import argparse
import glob
import hashlib
import os

import numpy as np
import pandas as pd

RAW_GLOB = os.path.join("data", "raw", "*.csv")

FLAG_COLS = ["FIN Flag Count", "SYN Flag Count", "RST Flag Count",
             "PSH Flag Count", "ACK Flag Count"]

OTHER_FLAG_COLS = ["URG Flag Count", "CWE Flag Count", "ECE Flag Count", "Fwd PSH Flags", "Bwd PSH Flags",
                    "Fwd URG Flags", "Bwd URG Flags"]

def banner(text: str) -> None:
    print(f"\n{'=' * 78}\n{text}\n{'=' * 78}")

def load(sample: bool) -> pd.DataFrame:
    """Load the raw CSVs, normalising only column NAMES, never values."""
    files = sorted(glob.glob(RAW_GLOB))
    if not files:
        raise SystemExit(f"No CSVs found at {RAW_GLOB}. Run from the repo root.")
 
    frames = []
    for path in files:
        # latin-1: the Web Attack labels contain a non-UTF-8 dash.
        d = pd.read_csv(path, low_memory=False, encoding="latin-1")
        d.columns = d.columns.str.strip()  # names only; values untouched
        if sample:
            d = d.sample(n=min(60_000, len(d)), random_state=0)
        d["__source"] = os.path.basename(path)
        frames.append(d)
    return pd.concat(frames, ignore_index=True)
 
 
def s1_schema(df: pd.DataFrame) -> None:
    banner("1. SCHEMA AND LABELS")
    print(f"rows: {len(df):,}   columns: {df.shape[1] - 1}")
    print("\nlabel counts:")
    print(df["Label"].value_counts().to_string())
 
 
def s2_quality(df: pd.DataFrame, cols: list[str]) -> None:
    banner("2. DATA QUALITY")
 
    constants, nan_inf = [], []
    for c in cols:
        v = pd.to_numeric(df[c], errors="coerce").to_numpy(dtype=np.float64)
        finite = v[np.isfinite(v)]
        if len(finite) and finite.min() == finite.max():
            constants.append((c, finite.min()))
        n_nan, n_inf = int(np.isnan(v).sum()), int(np.isinf(v).sum())
        if n_nan or n_inf:
            nan_inf.append((c, n_nan, n_inf))
 
    print(f"\nconstant columns (zero variance): {len(constants)}")
    for c, val in constants:
        print(f"    {c:<26} = {val}")
 
    print("\ncolumns with NaN or inf:")
    for c, n_nan, n_inf in nan_inf:
        print(f"    {c:<26} NaN={n_nan:>6,}  inf={n_inf:>6,}")
 
    neg = int((pd.to_numeric(df["Flow Duration"], errors="coerce") < 0).sum())
    print(f"\nrows with negative Flow Duration (corrupt): {neg:,}")
 
 
def s3_duplicates(df: pd.DataFrame, cols: list[str]) -> None:
    banner("3. BIT-IDENTICAL DUPLICATE COLUMNS")
    print("Two columns with different names holding the same bytes means the\n"
          "generating tool assigned them wrong. This is evidence, not opinion.\n")
 
    digests: dict[str, list[str]] = {}
    for c in cols:
        v = pd.to_numeric(df[c], errors="coerce").to_numpy(dtype=np.float64)
        v = np.nan_to_num(v, nan=-9e99, posinf=9e99, neginf=-8e99)
        digests.setdefault(hashlib.md5(v.tobytes()).hexdigest(), []).append(c)
 
    for group in digests.values():
        if len(group) > 1:
            print("   ", group)
 
 
def s4_flags(df: pd.DataFrame) -> None:
    banner("4. TCP FLAG AUDIT")
 
    print("4.1 value range per flag column")
    for c in FLAG_COLS + OTHER_FLAG_COLS:
        u = sorted(df[c].unique())
        print(f"    {c:<18} dtype={df[c].dtype} n_unique={df[c].nunique()} values={u[:6]}")
 
    print("\n4.2 observed combinations of (FIN, SYN, RST, PSH, ACK)")
    a = df[FLAG_COLS].to_numpy(dtype=np.int8)
    code = a[:, 0] * 16 + a[:, 1] * 8 + a[:, 2] * 4 + a[:, 3] * 2 + a[:, 4]
    vals, counts = np.unique(code, return_counts=True)
    for v, n in sorted(zip(vals, counts), key=lambda x: -x[1]):
        b = format(v, "05b")
        print(f"    FIN={b[0]} SYN={b[1]} RST={b[2]} PSH={b[3]} ACK={b[4]}"
              f"   {n:>10,}  ({100 * n / len(df):5.2f}%)")
    print(f"    -> {len(vals)} of 32 possible combinations; "
          f"max flags set at once = {int(a.sum(axis=1).max())}")
 
    print("\n4.3 the decisive test: real TCP conversations")
    print("    Flows with >=4 packets in EACH direction and >1 ms duration.")
    print("    Every such flow must contain ACKs. TCP cannot work otherwise.")
    real = df[
        (df["Total Fwd Packets"] >= 4)
        & (df["Total Backward Packets"] >= 4)
        & (df["Flow Duration"] > 1000)
    ]
    print(f"    n = {len(real):,}")
    for c in FLAG_COLS:
        print(f"      {c:<18} == 0 in {100 * (real[c] == 0).mean():5.1f}% of them")
 
    print("\n4.4 PortScan: SYN scan against closed ports is SYN -> RST")
    ps = df[df["Label"] == "PortScan"]
    if len(ps):
        print(f"    n = {len(ps):,}   flows with SYN=1: {(ps['SYN Flag Count'] == 1).sum()}"
              f"   flows with RST=1: {(ps['RST Flag Count'] == 1).sum()}")
 
 
def s5_units(df: pd.DataFrame) -> None:
    banner("5. UNITS AND SEMANTICS (CSV vs. our extractor)")
 
    d = pd.to_numeric(df["Flow Duration"], errors="coerce")
    print("5.1 Flow Duration")
    print(f"    median={d.median():,.0f}   max={d.max():,.0f}")
    print("    max ~1.2e8 with a 120 s active timeout => MICROSECONDS.")
    print("    Our extractor reports seconds. Factor 1e6.")
 
    print("\n5.2 packet length: payload or full frame?")
    ps = df[df["Label"] == "PortScan"]
    if len(ps):
        print(f"    PortScan  Fwd Packet Length Max: median="
              f"{ps['Fwd Packet Length Max'].median():.0f}  min={ps['Fwd Packet Length Max'].min():.0f}")
        print(f"    PortScan  Fwd Header Length:     median={ps['Fwd Header Length'].median():.0f}")
        print("    A SYN probe carries no data. Median 0 => CSV measures PAYLOAD.")
        print("    Our extractor returned 54 for a bare SYN => FULL FRAME.")
 
    print("\n5.3 Down/Up Ratio")
    u = sorted(pd.to_numeric(df["Down/Up Ratio"], errors="coerce").dropna().unique())
    print(f"    distinct values: {u[:15]}{' ...' if len(u) > 15 else ''}")
    print("    Integers only => integer division. Our extractor returns floats (0.75).")
 
 
def s6_fingerprint(df: pd.DataFrame) -> None:
    banner("6. ENVIRONMENT FINGERPRINT CHECK (initial TCP window)")
    print("A feature that identifies the attacker's OS rather than its behaviour\n"
          "scores brilliantly offline and collapses in a lab where both machines\n"
          "run the same stack. Fedora 44 on both VMs is exactly that case.\n")
    cols = ["Init_Win_bytes_forward", "Init_Win_bytes_backward"]
    print(df.groupby("Label")[cols].agg(["median", "nunique"]).to_string())
    print("\n29200 is the Linux default initial window. If it appears as the median\n"
          "for most attack classes and not for BENIGN, the split is by operating\n"
          "system, not by attack.")
 
 
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", action="store_true",
                    help="60k rows per file instead of the full dataset")
    args = ap.parse_args()
 
    df = load(args.sample)
    feature_cols = [c for c in df.columns if c not in {"Label", "__source"}]
 
    s1_schema(df)
    s2_quality(df, feature_cols)
    s3_duplicates(df, feature_cols)
    s4_flags(df)
    s5_units(df)
    s6_fingerprint(df)
 
    banner("DONE")
    print("Nothing was written. data/raw/ is untouched.")
 
 
if __name__ == "__main__":
    main()