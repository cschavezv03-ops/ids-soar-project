"""
CICIDS2017 preprocessing: 8 raw CSVs -> one reproducible stratified split.

Scope. This module loads, labels, cleans and splits. It does NOT train, tune,
scale, resample or evaluate anything. There is no model and no metric here on
purpose: everything downstream must be able to assume that the split it reads
was produced by this file and nothing else.

Class imbalance is NOT treated here. The decision, taken in A1, is
`class_weight="balanced"` inside the sklearn Pipeline in task A4. That is a
model hyperparameter, not a property of the data, so `X_train` leaves this
module holding exactly what the CSV said. No resampling, no SMOTE, no
undersampling - resampling would change the data the model sees without
changing what the data means, and the reweighting achieves the same end while
leaving the evidence intact.

Which contract rules apply on THIS side of the pipeline, and why:

  R1 (time, seconds -> microseconds)  does NOT apply.
      The CSV is already in microseconds. It is the reference space; the
      extractor is the side that converts toward it. Applying R1 here would
      convert the reference away from itself.

  R2 (packet length = payload, Ethernet padding included)  does NOT apply.
      The CSV *defines* the measurement. There is no operation that turns
      payload bytes back into frame lengths, so the fix necessarily lives in
      the extractor's measurement, not in a post-hoc correction here.

  R3 (non-finite -> 0.0)  APPLIES.
      The only bidirectional rule: identical behaviour on both sides, and the
      same source of truth. This module calls `contract.sanitize_frame()`, the
      live extractor calls `contract.sanitize()`, and a test pins them equal.

  R4 (corrupt rows)  applies HERE ONLY.
      Offline we can drop a row. Live we cannot: a flow arrives, it must be
      classified. R4 therefore has no live counterpart by design.

Usage (from the repo root):
    python src/intelligence/preprocess.py
    python src/intelligence/preprocess.py --drop-duplicates
"""

import argparse
import glob
import os
import sys

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

# Runnable as a script from the repo root as well as importable as a module.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence import contract  # noqa: E402

RAW_GLOB = os.path.join("data", "raw", "*.csv")
PROCESSED_DIR = os.path.join("data", "processed")
REPORT_PATH = os.path.join("scripts", "scripts_output", "preprocess_report.txt")

# Frozen. The split must be byte-identical on any machine, on any day, or the
# numbers quoted in the notes stop meaning anything.
RANDOM_STATE = 42
TEST_SIZE = 0.2

# The original label string, kept alongside the binary target. It is not
# decoration: it is what we stratify on (step 7) and what A5 needs to report
# recall per attack family.
LABEL_COL = "label"
TARGET_COL = "target"

# The 25 columns we read out of 79. See load_raw().
KEEP_CSV_COLUMNS = set(contract.CSV_COLUMNS_24) | {"Label"}


# ---------------------------------------------------------------------------
# Report plumbing
# ---------------------------------------------------------------------------

class Report:
    """Prints as it goes and keeps a copy, so the run and the committed file
    can never disagree about what happened."""

    def __init__(self) -> None:
        self.lines: list[str] = []

    def __call__(self, text: str = "") -> None:
        print(text)
        self.lines.append(text)

    def banner(self, text: str) -> None:
        self("")
        self("=" * 78)
        self(text)
        self("=" * 78)

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(self.lines) + "\n")


# ---------------------------------------------------------------------------
# 1. Load
# ---------------------------------------------------------------------------

def load_raw(rep: Report, raw_glob: str = RAW_GLOB) -> pd.DataFrame:
    """Read the 8 raw CSVs and concatenate them once.

    Two decisions worth defending:

    - `usecols` keeps 25 of the 79 columns. This is a deliberate memory
      choice, not tidiness: the full dataset is 2.8M rows, and reading all 79
      columns costs roughly 1.7 GB before we have dropped a single one. The 54
      columns we skip were excluded by the A1 audit and no later step can
      resurrect them, so paying to materialise them is pure waste.
    - the callable strips each header before matching. The raw file ships
      inconsistent leading spaces (" Flow Duration"), so a literal list would
      match some columns and silently miss others.
    """
    files = sorted(glob.glob(raw_glob))
    if not files:
        raise SystemExit(f"No CSVs found at {raw_glob}. Run from the repo root.")

    frames = []
    rep.banner("1. LOAD")
    rep(f"reading {len(files)} files, keeping {len(KEEP_CSV_COLUMNS)} of 79 columns")
    rep("")

    for path in files:
        # latin-1: the Web Attack labels carry a byte sequence that is not
        # valid UTF-8. Same encoding the A1 audit used, so the label strings
        # here are the same strings contract.py was written against.
        d = pd.read_csv(
            path,
            encoding="latin-1",
            low_memory=False,
            usecols=lambda name: name.strip() in KEEP_CSV_COLUMNS,
        )
        d.columns = d.columns.str.strip()

        missing = KEEP_CSV_COLUMNS - set(d.columns)
        if missing:
            raise SystemExit(
                f"{os.path.basename(path)} is missing {sorted(missing)}. "
                f"The contract cannot be built from this file."
            )

        rep(f"    {os.path.basename(path):<52} {len(d):>10,} rows")
        frames.append(d)

    df = pd.concat(frames, ignore_index=True)
    rep("")
    rep(f"    {'TOTAL':<52} {len(df):>10,} rows")
    return df


# ---------------------------------------------------------------------------
# 2. Labels
# ---------------------------------------------------------------------------

def map_labels(rep: Report, df: pd.DataFrame) -> pd.DataFrame:
    """Map Label -> binary target, drop the excluded families, keep the string.

    `label_to_target` raises on an unrecognised label and we do not catch it.
    That is the point of the function: a default would quietly file an unknown
    attack under BENIGN and poison the training set with no error anywhere.
    """
    rep.banner("2. LABELS")

    labels = df["Label"].astype(str).str.strip()
    inventory = labels.value_counts()

    rep(f"label inventory before mapping ({len(inventory)} distinct values):")
    rep("")
    for name, n in inventory.items():
        rep(f"    {name:<40} {n:>10,}")

    # One call per DISTINCT label rather than per row: label_to_target is pure,
    # and 15 calls beat 2.8M. It still raises on anything unlisted.
    target_by_label = {lab: contract.label_to_target(lab) for lab in inventory.index}

    target = labels.map(target_by_label)
    dropped_mask = target.isna()

    rep("")
    rep("rows dropped per excluded family (excluded is NOT benign - the model")
    rep("never forms an opinion about these):")
    rep("")
    excluded = inventory[[lab for lab, t in target_by_label.items() if t is None]]
    if len(excluded) == 0:
        rep("    (none)")
    for name, n in excluded.sort_values(ascending=False).items():
        rep(f"    {name:<40} {n:>10,}")
    rep("")
    rep(f"    {'dropped total':<40} {int(dropped_mask.sum()):>10,}")
    rep(f"    {'rows kept':<40} {int((~dropped_mask).sum()):>10,}")

    out = df.loc[~dropped_mask].copy()
    out[LABEL_COL] = labels.loc[~dropped_mask]
    out[TARGET_COL] = target.loc[~dropped_mask].astype("int8")
    return out.drop(columns=["Label"])


# ---------------------------------------------------------------------------
# 3. Rename and coerce
# ---------------------------------------------------------------------------

def rename_and_coerce(df: pd.DataFrame) -> pd.DataFrame:
    """Rename CSV_COLUMNS_24 -> FEATURES_24 in contract order and force numeric.

    `errors="coerce"` on purpose: a stray non-numeric cell becomes NaN and is
    caught by R3 two steps later. Without it the column would stay object
    dtype, survive every check here, and blow up inside sklearn with a message
    that says nothing about which row was wrong.
    """
    renamed = df[list(contract.CSV_COLUMNS_24)].rename(
        columns=dict(zip(contract.CSV_COLUMNS_24, contract.FEATURES_24))
    )
    for col in contract.FEATURES_24:
        renamed[col] = pd.to_numeric(renamed[col], errors="coerce")

    renamed[LABEL_COL] = df[LABEL_COL]
    renamed[TARGET_COL] = df[TARGET_COL]
    return renamed


# ---------------------------------------------------------------------------
# 4. R4 - drop corrupt rows
# ---------------------------------------------------------------------------

def drop_corrupt_rows(rep: Report, df: pd.DataFrame) -> pd.DataFrame:
    """R4: drop any row holding a FINITE negative value in any of the 24.

    Not "negative Flow Duration". `contract.validate()` declares all 24
    positions to be non-negative magnitudes (NON_NEGATIVE_IDX is the full
    range), so the rule follows the contract rather than the one column the A1
    audit happened to look at. If a negative shows up somewhere else, we want
    it dropped and reported, not tolerated because it was not on a list.

    Finite negatives only: -inf is R3's business, not R4's. And this MUST run
    BEFORE sanitize, because sanitize turns -inf into 0.0 - a corrupt row
    would then look pristine and be trained on.
    """
    rep.banner("4. R4 - CORRUPT ROWS (finite negative in any of the 24)")

    features = df[contract.FEATURES_24]
    # NaN and +inf are never < 0; -inf is, so it is excluded explicitly.
    negative = (features < 0) & (features != -np.inf)
    per_column = negative.sum()
    rows = negative.any(axis=1)

    rep(f"rows dropped: {int(rows.sum()):,}")
    rep("")
    rep("per-column breakdown (a row can offend in more than one column):")
    rep("")
    offenders = per_column[per_column > 0]
    if len(offenders) == 0:
        rep("    (no column holds a finite negative value)")
    for name, n in offenders.sort_values(ascending=False).items():
        rep(f"    {name:<40} {int(n):>10,}")

    rep("")
    rep("Reconciliation with the A1 audit, which predicted 22 rows via")
    rep("Flow Duration. Two separate discrepancies, both explained:")
    rep("  - 22 was measured on the audit's --sample run (60k rows per file,")
    rep("    ~17% of the dataset). The same query over the full 8 CSVs returns")
    rep("    115. Reproduce: audit_dataset.py WITHOUT --sample.")
    rep("  - the audit only ever tested Flow Duration for negatives. The bulk")
    rep("    of the corruption is in Flow IAT Min, which nothing had looked at.")
    rep("    Checking all 24 positions, as contract.validate() already demands,")
    rep("    is what surfaced it.")

    return df.loc[~rows].copy()


# ---------------------------------------------------------------------------
# 5. R3 - sanitize
# ---------------------------------------------------------------------------

def apply_r3(rep: Report, df: pd.DataFrame) -> pd.DataFrame:
    """R3 via contract.sanitize_frame - the same rule the live extractor runs."""
    rep.banner("5. R3 - NON-FINITE VALUES -> 0.0")

    features = df[contract.FEATURES_24]
    nan_counts = features.isna().sum()
    inf_counts = features.isin([np.inf, -np.inf]).sum()

    rep("cells fixed per column (NaN and inf counted separately):")
    rep("")
    rep(f"    {'column':<40} {'NaN':>10} {'inf':>10}")
    touched = [c for c in contract.FEATURES_24 if nan_counts[c] or inf_counts[c]]
    if not touched:
        rep("    (no non-finite cell in any of the 24 columns)")
    for col in touched:
        rep(f"    {col:<40} {int(nan_counts[col]):>10,} {int(inf_counts[col]):>10,}")
    rep("")
    rep(f"    {'TOTAL cells':<40} {int(nan_counts.sum()):>10,} {int(inf_counts.sum()):>10,}")

    out = df.copy()
    out[contract.FEATURES_24] = contract.sanitize_frame(features)
    return out


# ---------------------------------------------------------------------------
# 6. Duplicates - measure only
# ---------------------------------------------------------------------------

def measure_duplicates(rep: Report, df: pd.DataFrame) -> pd.Series:
    """Count exact duplicates over the 24 features + the original label.

    Deliberately measure-and-report, not act. Whether a repeated flow vector is
    redundancy (a flood really does emit thousands of identical flows, and
    deleting them tells the model that floods are rare) or leakage (the same
    row landing in train and test) is a modelling decision that has not been
    taken yet. It will be taken from these numbers, not from a default buried
    in a preprocessing script.

    Returns the boolean mask of duplicate rows so main() can act on the flag.
    """
    rep.banner("6. EXACT DUPLICATES (24 features + original label) - MEASURED ONLY")

    subset = contract.FEATURES_24 + [LABEL_COL]
    dup_mask = df.duplicated(subset=subset, keep="first")
    n_dup = int(dup_mask.sum())

    rep(f"duplicate rows (keeping the first of each group): {n_dup:,} "
        f"({n_dup / len(df):.2%} of {len(df):,})")
    rep("")
    rep("per family:")
    rep("")
    rep(f"    {'family':<40} {'total':>12} {'duplicate':>12} {'share':>8}")
    totals = df[LABEL_COL].value_counts()
    dups = df.loc[dup_mask, LABEL_COL].value_counts()
    for name in totals.index:
        d = int(dups.get(name, 0))
        rep(f"    {name:<40} {int(totals[name]):>12,} {d:>12,} "
            f"{d / totals[name]:>7.1%}")

    # What the class balance WOULD become. Reported, not applied.
    kept = df.loc[~dup_mask]
    rep("")
    rep("hypothetical proportions IF duplicates were dropped "
        f"({len(kept):,} rows would remain):")
    rep("")
    _class_balance(rep, kept, indent="    ")
    rep("")
    rep("Not applied. --drop-duplicates exists and defaults to OFF: the choice")
    rep("belongs to A4/A5 and must be made from these numbers.")

    return dup_mask


# ---------------------------------------------------------------------------
# 7. Split
# ---------------------------------------------------------------------------

def _class_balance(rep: Report, df: pd.DataFrame, indent: str = "") -> None:
    """benign vs attack, then per family. Absolute and percentage."""
    n = len(df)
    n_benign = int((df[TARGET_COL] == contract.BENIGN).sum())
    n_attack = int((df[TARGET_COL] == contract.ATTACK).sum())
    rep(f"{indent}{'BENIGN (0)':<40} {n_benign:>12,} {n_benign / n:>8.2%}")
    rep(f"{indent}{'ATTACK (1)':<40} {n_attack:>12,} {n_attack / n:>8.2%}")
    rep(f"{indent}{'TOTAL':<40} {n:>12,} {1.0:>8.2%}")
    rep("")
    for name, count in df[LABEL_COL].value_counts().items():
        rep(f"{indent}  {name:<38} {int(count):>12,} {count / n:>8.2%}")


def split(df: pd.DataFrame):
    """Stratify on the ORIGINAL label string, train on the binary target.

    Stratifying on the binary target would only guarantee that the test set has
    the right benign/attack ratio - it could still take almost every
    DoS Slowhttptest flow into train and leave the test set unable to say
    anything about that family. Stratifying on the string makes every family
    proportionally present, which is what A5 needs to report recall per family.
    """
    X = df[contract.FEATURES_24]
    y = df[TARGET_COL]
    labels = df[LABEL_COL]

    X_train, X_test, y_train, y_test, label_train, label_test = train_test_split(
        X, y, labels,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=labels,
    )
    return X_train, X_test, y_train, y_test, label_train, label_test


# ---------------------------------------------------------------------------
# 8. Persist
# ---------------------------------------------------------------------------

def persist(out_dir, X_train, X_test, y_train, y_test, label_train, label_test):
    """Write the split to data/processed/.

    parquet because pyarrow 25.0.1 is ALREADY in requirements.txt - no new
    dependency was added for this. It also keeps the float64 dtypes, which a
    CSV round-trip would not.

    Two files rather than six: the target and the label ride along as columns
    so that a row can never be separated from its own label by a mismatched
    index. `load_processed()` splits them back into the six objects.

    data/ is gitignored. The reproducible artifact is this script plus
    contract/A3_preprocessing_note.md, not the bytes on disk.
    """
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for name, X, y, lab in (
        ("train", X_train, y_train, label_train),
        ("test", X_test, y_test, label_test),
    ):
        frame = X.copy()
        frame[TARGET_COL] = y
        frame[LABEL_COL] = lab
        path = os.path.join(out_dir, f"{name}.parquet")
        frame.to_parquet(path, index=False)
        written.append((path, len(frame)))
    return written


def load_processed(out_dir: str = PROCESSED_DIR):
    """Read back the six objects persist() wrote. For A4 onward."""
    out = []
    for name in ("train", "test"):
        frame = pd.read_parquet(os.path.join(out_dir, f"{name}.parquet"))
        out.append((frame[contract.FEATURES_24], frame[TARGET_COL], frame[LABEL_COL]))
    (X_train, y_train, label_train), (X_test, y_test, label_test) = out
    return X_train, X_test, y_train, y_test, label_train, label_test


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def preprocess(rep: Report, *, drop_duplicates: bool = False,
               raw_glob: str = RAW_GLOB):
    """Steps 1-7. Returns the six split objects."""
    df = load_raw(rep, raw_glob)
    df = map_labels(rep, df)

    rep.banner("3. RENAME AND COERCE")
    df = rename_and_coerce(df)
    rep(f"renamed {len(contract.CSV_COLUMNS_24)} CSV columns to contract names, "
        f"in contract order")
    rep("all 24 coerced with errors='coerce'; any stray text is now NaN and is")
    rep("R3's problem in step 5, not an object dtype that reaches sklearn")

    df = drop_corrupt_rows(rep, df)
    df = apply_r3(rep, df)

    dup_mask = measure_duplicates(rep, df)
    if drop_duplicates:
        df = df.loc[~dup_mask].copy()

    rep.banner("7. FINAL CLASS BALANCE")
    rep(f"duplicates dropped: {'YES (--drop-duplicates)' if drop_duplicates else 'NO (default)'}")
    rep("")
    _class_balance(rep, df)

    parts = split(df)
    X_train, X_test, y_train, y_test, label_train, label_test = parts

    rep.banner("8. STRATIFIED SPLIT")
    rep(f"test_size={TEST_SIZE}   random_state={RANDOM_STATE}   "
        f"stratify=original label string")
    rep("")
    rep(f"    {'train rows':<40} {len(X_train):>12,}")
    rep(f"    {'test rows':<40} {len(X_test):>12,}")
    rep("")
    rep("class proportion in EACH half - stratification is meant to be checked")
    rep("by eye here, not asserted:")
    rep("")
    for name, y, lab in (("TRAIN", y_train, label_train), ("TEST", y_test, label_test)):
        rep(f"  {name}")
        half = pd.DataFrame({TARGET_COL: y, LABEL_COL: lab})
        _class_balance(rep, half, indent="    ")
        rep("")

    return parts


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--drop-duplicates",
        action="store_true",
        help="drop exact duplicate rows before splitting. OFF by default: the "
             "decision is pending and must be taken from the measured numbers.",
    )
    ap.add_argument("--out-dir", default=PROCESSED_DIR)
    ap.add_argument("--report", default=REPORT_PATH)
    args = ap.parse_args()

    rep = Report()
    rep("CICIDS2017 preprocessing report")
    rep(f"contract version {contract.CONTRACT_VERSION}   "
        f"random_state={RANDOM_STATE}   test_size={TEST_SIZE}")
    rep("Rules applied on this side: R3 (sanitize) and R4 (corrupt rows).")
    rep("R1 and R2 do not apply to the CSV: it is the reference space the")
    rep("extractor converts toward. See contract/A3_preprocessing_note.md.")

    parts = preprocess(rep, drop_duplicates=args.drop_duplicates)

    rep.banner("9. PERSISTED")
    for path, n in persist(args.out_dir, *parts):
        rep(f"    {path:<52} {n:>10,} rows")
    rep("")
    rep("data/ is gitignored on purpose. Rerun the command at the top of")
    rep("contract/A3_preprocessing_note.md to regenerate these files.")

    rep.banner("DONE")
    rep("Nothing was trained, scaled or resampled. data/raw/ is untouched.")

    rep.save(args.report)
    print(f"\nreport saved to {args.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
