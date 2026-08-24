"""
Single source of truth for the 24-feature contract.

PUBLIC:
    CONTRACT_VERSION   version string; must match the one inside model.pkl
    FEATURES_24        canonical names, in vector order - for the dashboard
    N_FEATURES         24
    validate()         sanity-check a vector before calling predict()

INTERNAL:
    CSV_COLUMNS_24, label_to_target, TIME_IDX, PAYLOAD_IDX,
    COUNT_IDX, RATE_IDX, sanitize, seconds_to_contract_time

Spec: contract/contract_characteristics.md
"""

CONTRACT_VERSION = "1,0"

#Canonical names in frozen order. Position is part of the contract.

FEATURES_24 = [
    "flow_duration",        #  0  duration and volume
    "tot_fwd_pkts",         #  1
    "tot_bwd_pkts",         #  2
    "totlen_fwd_pkts",      #  3
    "totlen_bwd_pkts",      #  4
    "fwd_pkt_len_min",      #  5  forward packet sizes
    "fwd_pkt_len_mean",     #  6
    "fwd_pkt_len_std",      #  7
    "fwd_pkt_len_max",      #  8
    "bwd_pkt_len_min",      #  9  backward packet sizes
    "bwd_pkt_len_mean",     # 10
    "bwd_pkt_len_std",      # 11
    "bwd_pkt_len_max",      # 12
    "pkt_len_mean",         # 13  whole-flow sizes
    "pkt_len_std",          # 14
    "flow_iat_mean",        # 15  timing
    "flow_iat_std",         # 16
    "flow_iat_max",         # 17
    "flow_iat_min",         # 18
    "fwd_iat_mean",         # 19
    "bwd_iat_mean",         # 20
    "flow_pkts_s",          # 21  rates and useful data
    "flow_byts_s",          # 22
    "fwd_act_data_pkts",    # 23
]

#Same 24, same order, as named in the dataset after str.strip()
CSV_COLUMNS_24 = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Fwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Bwd Packet Length Max",
    "Packet Length Mean",
    "Packet Length Std",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "Flow Packets/s",
    "Flow Bytes/s",
    "act_data_pkt_fwd",
]

N_FEATURES = len(FEATURES_24)

#Fails at import time
assert N_FEATURES == 24, f"Contract must have 24 features, not {N_FEATURES}"
assert len(CSV_COLUMNS_24) == N_FEATURES, f"Contract must have 24 CSV columns, not {len(CSV_COLUMNS_24)}"
assert len(set(FEATURES_24)) == N_FEATURES, "Contract must have 24 unique features, there's a duplicate feature name"

# ---------------------------------------------------------------------------
# Label mapping
#
# CICIDS2017 ships 15 label values. We train on BENIGN plus eight attack
# families and drop the rest. Excluded is NOT the same as benign: those rows
# are removed before training, so the model never forms an opinion about them.
#
# Beware the label text: the Web Attack labels contain byte sequence EF BF BD,
# which is U+FFFD (the replacement character) baked into the file back in 2017.
# The Python string you get depends on the encoding you read with:
#   utf-8    -> 'Web Attack \ufffd Brute Force'
#   latin-1  -> 'Web Attack \u00ef\u00bf\u00bd Brute Force'
# So we never spell those labels out. We match them by ASCII prefix instead.
# ---------------------------------------------------------------------------

BENIGN_LABEL = "BENIGN"

ATTACK_LABELS = frozenset({
    "DoS Hulk",           # 231,073 flows
    "PortScan",           # 158,930
    "DDoS",               # 128,027
    "DoS GoldenEye",      #  10,293
    "FTP-Patator",        #   7,938
    "SSH-Patator",        #   5,897
    "DoS slowloris",      #   5,796
    "DoS Slowhttptest",   #   5,499
})

EXCLUDED_LABELS = frozenset({
    "Bot",            # 1,966 - not a demo scenario
    "Infiltration",   #    36 - too few to stratify or measure
    "Heartbleed",     #    11 - same
})

# Matched by prefix, never by full string. See the note above.
EXCLUDED_LABEL_PREFIXES = ("Web Attack",)   # 2,180 flows across 3 variants

BENIGN = 0
ATTACK = 1


def label_to_target(label: str) -> int | None:
    """
    Map one CICIDS2017 label to its training target.

    Returns 0 (benign), 1 (attack), or None if the row must be dropped.
    Raises on anything unrecognised: a silent default here would quietly
    poison the training set.
    """
    label = label.strip()

    if label == BENIGN_LABEL:
        return BENIGN
    if label in ATTACK_LABELS:
        return ATTACK
    if label in EXCLUDED_LABELS:
        return None
    if label.startswith(EXCLUDED_LABEL_PREFIXES):
        return None

    raise ValueError(
        f"Unknown label {label!r}. Every label must be listed explicitly in "
        f"contract.py before training. Do not add a default."
    )

# ---------------------------------------------------------------------------
# Feature semantics
#
# Two things differ between the CICIDS2017 CSV (Java CICFlowMeter, 2017) and
# our live extractor (Python cicflowmeter). They are NOT the same kind of
# problem, and they are not fixed in the same place.
#
#   R1 - TIME. CSV is in microseconds, the tool reports seconds. A scalar
#        multiply on the value. Fixable here.
#
#   R2 - PACKET LENGTH. CSV measures payload bytes, the tool measures the
#        whole frame. NOT a scalar: the header size varies per packet
#        (TCP options, Ethernet padding), and by the time we hold the
#        24-vector the means and stds were already computed over the wrong
#        lengths. This must be fixed where packets are measured, inside the
#        extractor. Listed here only to mark which features are at risk,
#        so task A2 knows what to verify.
# ---------------------------------------------------------------------------

SECONDS_TO_MICROSECONDS = 1_000_000

# R1: positions whose unit is time. Multiply by the factor above.
TIME_IDX = (0, 15, 16, 17, 18, 19, 20)

# R2: positions whose value depends on how a packet's length is defined.
# Nothing to apply here - these are the features A2 must verify one by one.
PAYLOAD_IDX = (3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 22)

# Plain counts. Same meaning on both sides, nothing to convert.
COUNT_IDX = (1, 2, 23)

# Rates. Already per-second on both sides. flow_byts_s is also in PAYLOAD_IDX
# because its numerator inherits the packet-length definition.
RATE_IDX = (21, 22)

# Every feature in this contract is a magnitude: none can be negative.
# A negative value means a corrupt flow or a bug, never valid data.
NON_NEGATIVE_IDX = tuple(range(N_FEATURES))

assert set(TIME_IDX) | set(PAYLOAD_IDX) | set(COUNT_IDX) | set(RATE_IDX) == set(
    range(N_FEATURES)
), "every position must be classified"
assert not (set(TIME_IDX) & set(PAYLOAD_IDX)), "a feature cannot be both"


def seconds_to_contract_time(vector: list[float]) -> list[float]:
    """Apply R1 in place-ish: convert the time positions from seconds to
    microseconds. Only needed if the extractor emits seconds; if it is
    patched to emit microseconds directly, this is a no-op you never call.
    """
    out = list(vector)
    for i in TIME_IDX:
        out[i] = out[i] * SECONDS_TO_MICROSECONDS
    return out

# ---------------------------------------------------------------------------
# Shared value handling
#
# Both paths - CSV preprocessing and live extraction - call these. That is the
# whole point: R3 is implemented once, so training and inference cannot drift
# apart no matter who writes the calling code.
# ---------------------------------------------------------------------------

import math

MISSING_VALUE = 0.0


def sanitize(vector: list[float]) -> list[float]:
    """
    Apply contract rule R3 to one 24-vector.

    NaN and +/-inf become MISSING_VALUE. These arise from division by a zero
    flow duration (single-packet flows), which is exactly what a port scan
    produces - so getting this wrong breaks the attack we most want to catch.

    Everything is cast to float: the model must never see ints in some runs
    and floats in others.
    """
    out = []
    for value in vector:
        value = float(value)
        out.append(MISSING_VALUE if (math.isnan(value) or math.isinf(value)) else value)
    return out


def validate(vector: list[float], *, strict: bool = True) -> list[str]:
    """
    Check one vector against the contract. Returns a list of problems;
    empty means it is fine.

    strict=True raises instead of returning. Use strict in tests and offline
    work. In the live pipeline prefer strict=False: a single malformed flow
    should be logged and skipped, never take the IDS down.
    """
    problems: list[str] = []

    if len(vector) != N_FEATURES:
        problems.append(f"expected {N_FEATURES} values, got {len(vector)}")
        if strict:
            raise ValueError(problems[0])
        return problems

    for i, value in enumerate(vector):
        name = FEATURES_24[i]

        if not isinstance(value, (int, float)) or isinstance(value, bool):
            problems.append(f"[{i}] {name}: not a number ({type(value).__name__})")
            continue

        value = float(value)

        if math.isnan(value) or math.isinf(value):
            problems.append(f"[{i}] {name}: non-finite ({value}); call sanitize() first")

        elif i in NON_NEGATIVE_IDX and value < 0:
            problems.append(f"[{i}] {name}: negative ({value}); corrupt flow or a bug")

    if problems and strict:
        raise ValueError("contract violation: " + "; ".join(problems))
    return problems