"""
Confirm the CICIDS2017 CSVs load and inspect their schema.

Reads one file to list its columns, then samples every file to see which
attack labels are present. Sampling keeps this fast -- the full set is
~880 MB and we only need the schema and the label vocabulary here.
"""

from pathlib import Path
import pandas as pd

RAW_DIR = Path("data/raw")

def main() -> None:
    files = sorted(RAW_DIR.glob("*.csv")) #Found every csv file in the raw data directory 
    if not files:
        raise FileNotFoundError(f"No CSV files found in {RAW_DIR.resolve()}")
    print(f"Found {len(files)} CSV files\n")

    #Schema, from a single file
    sample = pd.read_csv(files[0], nrows=5)
    print(f"Schema from: {files[0].name}")
    print(f"Columns: {list(sample.columns)}\n")
    for i, col in enumerate(sample.columns):
        print(f"{i:>3} {col!r}")

    #Labels, across every file
    print("\nLabel counts (first 200k rows of each file):")
    for path in files:
        df = pd.read_csv(path, nrows=200_000, low_memory=False)
        label_col = [c for c in df.columns if c.strip() == "Label"][0]
        counts = df[label_col].value_counts()
        print(f"\n {path.name}")
        for label, n in counts.items():
            print(f"  {label!r:<32} {n:>8,}")

if __name__ == "__main__":
    main()