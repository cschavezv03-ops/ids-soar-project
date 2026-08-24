"""
Audit of two CICIDS2017 measurement semantics that the live extractor must match.

Parity is defined against the CSV, not against correctness. Before patching the
Python cicflowmeter we have to know what the Java CICFlowMeter that produced
CICIDS2017 actually measured - otherwise a "fix" silently breaks parity.

PART 1 - Bug 3: single-interval IAT statistics.
    utils.get_statistics() guards the whole statistics block with
    `len(alist) > 1`, a condition only std actually needs. A one-element list
    therefore returns zeros. N packets delimit N-1 intervals, so a two-packet
    conversation has exactly one interval and reports it as zero.
    Test: in a two-packet flow the only interval IS the flow duration, so
    Flow IAT Mean must equal Flow Duration. Three-packet flows are the control.

PART 2 - Rule R2: what counts as "packet length".
    The CSV measures payload bytes; the Python tool measures the whole frame.
    Two questions, in order:
      (a) Is the CSV really payload and not frame?
          A TCP packet over Ethernet cannot be shorter than 54 bytes, so any
          value below 54 rules out frame measurement.
      (b) Does the CSV count Ethernet padding as payload?
          Ethernet pads frames below 60 bytes. A 54-byte packet therefore
          carries 6 bytes of filler. If the Java tool counted that filler,
          `len(pkt["TCP"].payload)` in scapy would reproduce it and IP-header
          arithmetic would not - and we must replicate the defect, not fix it.
          Known truth: the RST that a closed port returns to a SYN probe
          carries no data. Its payload is zero by definition of the protocol.

Run:  python scripts/audit_dataset_semantics.py
"""
from pathlib import Path

import pandas as pd

RAW_DIR = Path("data/raw")
ENCODING = "latin-1"       # the Web Attack labels are not valid utf-8
TOLERANCE_US = 1.0         # microseconds; durations are integers, means are floats

# Minimum size of a TCP packet over Ethernet: 14 (Ethernet) + 20 (IP) + 20 (TCP).
MIN_TCP_FRAME = 54
# Ethernet pads frames below 60 bytes, so a 54-byte packet carries 6 of filler.
ETHERNET_PADDING = 6

# Columns converted to numbers.
NUMERIC_COLUMNS = [
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Duration",
    "Flow IAT Mean",
    "Flow IAT Max",
    "Flow IAT Min",
    "Flow IAT Std",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "Fwd Packet Length Min",
    "Bwd Packet Length Min",
]

# Read as text and never coerced. pd.to_numeric would turn every label into NaN
# and the dropna below would leave an empty frame.
LABEL_COLUMN = "Label"

WANTED = NUMERIC_COLUMNS + [LABEL_COLUMN]


# ---------------------------------------------------------------------------
# 1. Loading
#
# CICIDS2017 headers carry inconsistent leading blanks (" Flow Duration").
# Reading the header alone first lets us map clean names to real ones and pull
# only the columns we need, instead of loading 79 columns x 2.8M rows.
# ---------------------------------------------------------------------------

def load_one(path: Path) -> pd.DataFrame:
    header = pd.read_csv(path, nrows=0, encoding=ENCODING)
    actual_by_clean = {name.strip(): name for name in header.columns}

    missing = [name for name in WANTED if name not in actual_by_clean]
    if missing:
        raise KeyError(f"{path.name} is missing {missing}")

    frame = pd.read_csv(
        path,
        usecols=[actual_by_clean[name] for name in WANTED],
        encoding=ENCODING,
        low_memory=False,
    )
    frame.columns = frame.columns.str.strip()
    return frame[WANTED]


def load_dataset() -> pd.DataFrame:
    paths = sorted(RAW_DIR.glob("*.csv"))
    if not paths:
        raise FileNotFoundError(f"no CSV files under {RAW_DIR.resolve()}")

    print(f"Reading {len(paths)} files from {RAW_DIR}/")
    frames = []
    for path in paths:
        frame = load_one(path)
        print(f"  {path.name:<52} {len(frame):>9,} rows")
        frames.append(frame)

    data = pd.concat(frames, ignore_index=True)

    for name in NUMERIC_COLUMNS:
        data[name] = pd.to_numeric(data[name], errors="coerce")
    data[LABEL_COLUMN] = data[LABEL_COLUMN].astype(str).str.strip()

    before = len(data)
    # subset= is what keeps the label column out of the drop decision.
    data = data.dropna(subset=NUMERIC_COLUMNS)
    print(f"\nTotal {before:,} rows; {before - len(data):,} dropped as non-numeric\n")
    return data


def header(title: str) -> None:
    print("=" * 72)
    print(title)
    print("=" * 72)


# ---------------------------------------------------------------------------
# 2. Bug 3, part A: whole-flow IAT, two packets vs the three-packet control
# ---------------------------------------------------------------------------

def report_flow_iat(data: pd.DataFrame) -> float:
    total_packets = data["Total Fwd Packets"] + data["Total Backward Packets"]
    usable = data["Flow Duration"] > 0

    two = data[(total_packets == 2) & usable]
    three = data[(total_packets == 3) & usable]

    header("TEST A - whole-flow IAT on two-packet flows")
    print(f"two-packet flows with positive duration:   {len(two):>9,}")
    print(f"three-packet control group:                {len(three):>9,}\n")

    if len(two) == 0:
        print("No two-packet flows found. Test is inconclusive.\n")
        return float("nan")

    gap_error = (two["Flow IAT Mean"] - two["Flow Duration"]).abs()
    agrees = (gap_error <= TOLERANCE_US).mean()
    zero_two = (two["Flow IAT Mean"] == 0).mean()
    zero_three = (three["Flow IAT Mean"] == 0).mean() if len(three) else float("nan")

    print(f"Flow IAT Mean == Flow Duration (identity):  {agrees:>8.2%}")
    print(f"Flow IAT Mean is exactly zero:              {zero_two:>8.2%}")
    print(f"  ...in the three-packet control:           {zero_three:>8.2%}")
    print(f"Flow IAT Max is exactly zero:               {(two['Flow IAT Max'] == 0).mean():>8.2%}")
    print(f"Flow IAT Min is exactly zero:               {(two['Flow IAT Min'] == 0).mean():>8.2%}")
    print(f"Flow IAT Std is exactly zero:               {(two['Flow IAT Std'] == 0).mean():>8.2%}")
    print("  (Std zero is CORRECT here - one sample has no spread)\n")
    return zero_two


# ---------------------------------------------------------------------------
# 3. Bug 3, part B: directional IAT on two-packet directions
# ---------------------------------------------------------------------------

def report_directional_iat(data: pd.DataFrame) -> None:
    usable = data["Flow Duration"] > 0

    header("TEST B - directional IAT on two-packet directions")

    for count_column, iat_column in [
        ("Total Fwd Packets", "Fwd IAT Mean"),
        ("Total Backward Packets", "Bwd IAT Mean"),
    ]:
        two = data[(data[count_column] == 2) & usable]
        three = data[(data[count_column] == 3) & usable]

        zero_two = (two[iat_column] == 0).mean() if len(two) else float("nan")
        zero_three = (three[iat_column] == 0).mean() if len(three) else float("nan")

        print(f"{iat_column}")
        print(f"  zero when {count_column} == 2:   {zero_two:>8.2%}  (n={len(two):,})")
        print(f"  zero when {count_column} == 3:   {zero_three:>8.2%}  (n={len(three):,})")
    print()


def verdict_iat(zero_rate: float) -> None:
    header("VERDICT - bug 3")

    if zero_rate != zero_rate:            # NaN
        print("Inconclusive - not enough two-packet flows to decide.")
    elif zero_rate > 0.95:
        print("The Java CICFlowMeter COLLAPSES single-interval IAT to zero too.")
        print("Decision -> REPLICATE the behaviour, do not fix it.")
    elif zero_rate < 0.05:
        print("The Java CICFlowMeter reports the real interval. Only the Python")
        print("reimplementation collapses it to zero.")
        print("Decision -> PATCH get_statistics (guard on len > 0, not len > 1).")
    else:
        print(f"Mixed result ({zero_rate:.2%} zeros). Something else is going on.")
    print()


# ---------------------------------------------------------------------------
# 4. R2, question (a): payload or frame?
#
# A TCP packet over Ethernet cannot be shorter than 54 bytes. Any value below
# that rules out frame measurement - there is no arithmetic that produces it.
# ---------------------------------------------------------------------------

def report_payload_or_frame(data: pd.DataFrame) -> None:
    header("TEST C - does the CSV measure payload or whole frames?")

    for column in ["Fwd Packet Length Min", "Bwd Packet Length Min"]:
        # A direction with no packets reports 0 by convention, not by
        # measurement. Including those rows would fake the payload evidence.
        if column.startswith("Fwd"):
            present = data[data["Total Fwd Packets"] > 0]
        else:
            present = data[data["Total Backward Packets"] > 0]

        values = present[column]
        print(f"{column}   (n={len(values):,}, direction not empty)")
        print(f"  exactly 0:               {(values == 0).mean():>8.2%}")
        print(f"  below {MIN_TCP_FRAME} bytes:          {(values < MIN_TCP_FRAME).mean():>8.2%}")
        print(f"  minimum observed:        {values.min():>8}")
        print()


# ---------------------------------------------------------------------------
# 5. R2, question (b): is Ethernet padding counted as payload?
#
# Ethernet pads frames below 60 bytes, so a 54-byte packet carries 6 bytes of
# filler. If the Java tool counted it, small packets would report 6 instead
# of 0, and scapy's len(pkt["TCP"].payload) - which also sees the filler -
# would be the right way to reproduce the CSV. IP-header arithmetic would not.
# ---------------------------------------------------------------------------

def report_padding_hypothesis(data: pd.DataFrame) -> float:
    header("TEST D - is Ethernet padding counted as payload?")

    print("Most frequent values (a real payload distribution has no isolated")
    print(f"spike at {ETHERNET_PADDING}; padding would produce exactly that):\n")

    for column in ["Fwd Packet Length Min", "Bwd Packet Length Min"]:
        if column.startswith("Fwd"):
            present = data[data["Total Fwd Packets"] > 0]
        else:
            present = data[data["Total Backward Packets"] > 0]

        counts = present[column].value_counts().head(10)
        print(f"{column}")
        for value, count in counts.items():
            share = count / len(present)
            mark = ""
            if value == ETHERNET_PADDING:
                mark = "   <-- Ethernet padding"
            elif value == 0:
                mark = "   <-- no payload"
            print(f"  {value:>8}  {count:>10,}  {share:>7.2%}{mark}")
        print()

    # The known truth. A closed port answers a SYN probe with a RST, and a RST
    # carries no data. Whatever the CSV reports for the backward direction of a
    # PortScan flow IS the tool's definition of "no payload".
    header("TEST E - known truth: the RST answering a scan probe carries no data")

    scan = data[
        (data[LABEL_COLUMN] == "PortScan")
        & (data["Total Backward Packets"] > 0)
    ]
    print(f"PortScan flows with a backward packet: {len(scan):,}\n")

    if len(scan) == 0:
        print("No such flows. Test inconclusive.\n")
        return float("nan")

    counts = scan["Bwd Packet Length Min"].value_counts().head(5)
    print("Bwd Packet Length Min")
    for value, count in counts.items():
        share = count / len(scan)
        mark = ""
        if value == ETHERNET_PADDING:
            mark = "   <-- padding counted as payload"
        elif value == 0:
            mark = "   <-- padding NOT counted"
        print(f"  {value:>8}  {count:>10,}  {share:>7.2%}{mark}")
    print()

    return (scan["Bwd Packet Length Min"] == ETHERNET_PADDING).mean()


def verdict_padding(padding_rate: float) -> None:
    header("VERDICT - rule R2")

    if padding_rate != padding_rate:      # NaN
        print("Inconclusive - no PortScan flows with a backward packet.")
    elif padding_rate > 0.80:
        print("The Java CICFlowMeter COUNTS Ethernet padding as payload.")
        print("Reproduce it with scapy's len(pkt['TCP'].payload), which sees")
        print("the filler too. Do NOT use IP-header arithmetic: it is correct")
        print("and would therefore break parity.")
        print("Decision -> REPLICATE, and document it as deliberate.")
    elif padding_rate < 0.05:
        print("The Java CICFlowMeter EXCLUDES Ethernet padding.")
        print("Use IP-header arithmetic: ip.len - ip.ihl*4 - transport header.")
        print("len(pkt['TCP'].payload) would inject the filler as fake data.")
        print("Decision -> IP-HEADER ARITHMETIC. The 6 seen in the sample rows")
        print("comes from somewhere else and needs a separate look.")
    else:
        print(f"Mixed result ({padding_rate:.2%} at {ETHERNET_PADDING} bytes).")
        print("Inspect the distributions above before deciding.")
    print()


if __name__ == "__main__":
    dataset = load_dataset()

    zero_rate = report_flow_iat(dataset)
    report_directional_iat(dataset)
    verdict_iat(zero_rate)

    report_payload_or_frame(dataset)
    padding_rate = report_padding_hypothesis(dataset)
    verdict_padding(padding_rate)