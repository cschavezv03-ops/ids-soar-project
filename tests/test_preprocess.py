"""
Tests for the A3 preprocessing pipeline.

None of these touch data/raw/. They run on hand-built frames of a few rows,
or a random frame of a few thousand, so the whole file finishes in under a
second and can be run on every save. The dataset is evidence, not a fixture.

Each test corresponds to one way the preprocessing could be wrong while
looking right:

  - sanitize_frame forking away from sanitize, so the training data and the
    live vectors stop obeying the same R3;
  - R4 checking only Flow Duration, so a corrupt value anywhere else survives;
  - R4 running after R3, so -inf becomes 0.0 and the corrupt row is trained on;
  - an excluded family being relabelled benign instead of dropped;
  - a split that is not actually stratified, or not actually reproducible.

Run:  pytest -v tests/test_preprocess.py
"""
import math

import numpy as np
import pandas as pd
import pytest

from intelligence import contract as c
from intelligence import preprocess as p


def _frame(rows: list[list[float]]) -> pd.DataFrame:
    """A frame with the 24 contract columns, in contract order."""
    return pd.DataFrame(rows, columns=c.FEATURES_24)


# ---------------------------------------------------------------------------
# 1. sanitize_frame == sanitize. The guarantee that D2 did not fork the rule.
# ---------------------------------------------------------------------------

EDGE_VALUES = [
    float("nan"), float("inf"), float("-inf"), 0.0, -1.0, -0.0,
    1, 7, 1e308, -1e308, 1.5e-300, 123456789.123456,
]


def test_sanitize_frame_matches_sanitize_on_edge_cases():
    """Every awkward value we can think of, in every one of the 24 positions."""
    rows = []
    for value in EDGE_VALUES:
        # One row per edge value in every column, plus one row where the edge
        # value sits alone among ordinary numbers - column position must not
        # matter, and this is what catches an accidental per-column branch.
        rows.append([value] * c.N_FEATURES)
        for i in range(c.N_FEATURES):
            row = [1.0] * c.N_FEATURES
            row[i] = value
            rows.append(row)

    df = _frame(rows)
    vectorised = c.sanitize_frame(df).to_numpy()
    row_by_row = np.array([c.sanitize(list(r)) for r in df.to_numpy()])

    assert vectorised.shape == row_by_row.shape
    assert np.array_equal(vectorised, row_by_row)


def test_sanitize_frame_matches_sanitize_on_a_random_frame():
    """A few thousand rows of noise seeded with non-finite values."""
    rng = np.random.default_rng(0)
    n = 3000
    a = rng.normal(0, 1e6, size=(n, c.N_FEATURES))

    # Scatter NaN, +inf and -inf at random positions so no column is special.
    for fill in (np.nan, np.inf, -np.inf):
        idx = rng.integers(0, n, size=200), rng.integers(0, c.N_FEATURES, size=200)
        a[idx] = fill

    df = _frame(list(a))
    vectorised = c.sanitize_frame(df).to_numpy()
    row_by_row = np.array([c.sanitize(list(r)) for r in a])

    assert np.array_equal(vectorised, row_by_row)


def test_sanitize_frame_does_not_use_the_nan_to_num_default():
    """The trap: np.nan_to_num maps +inf to ~1.8e308, not to 0.0."""
    out = c.sanitize_frame(_frame([[float("inf")] * c.N_FEATURES]))
    assert (out.to_numpy() == c.MISSING_VALUE).all()


def test_sanitize_frame_casts_ints_to_float():
    """The model must never see ints in some runs and floats in others."""
    df = pd.DataFrame(
        [[1] * c.N_FEATURES], columns=c.FEATURES_24, dtype="int64"
    )
    out = c.sanitize_frame(df)
    assert (out.dtypes == np.float64).all()


def test_sanitize_frame_does_not_modify_its_input():
    df = _frame([[float("inf")] + [1.0] * (c.N_FEATURES - 1)])
    c.sanitize_frame(df)
    assert math.isinf(df.iloc[0, 0])


# ---------------------------------------------------------------------------
# 2. R4 - corrupt rows
# ---------------------------------------------------------------------------

def _labelled(rows: list[list[float]], labels: list[str]) -> pd.DataFrame:
    df = _frame(rows)
    df[p.LABEL_COL] = labels
    df[p.TARGET_COL] = [c.label_to_target(l) for l in labels]
    return df


def test_r4_drops_a_finite_negative_outside_flow_duration():
    """The rule follows contract.NON_NEGATIVE_IDX (all 24), not the one column
    the A1 audit happened to find offenders in."""
    good = [1.0] * c.N_FEATURES
    bad = [1.0] * c.N_FEATURES
    bad[c.FEATURES_24.index("bwd_pkt_len_mean")] = -5.0

    out = p.drop_corrupt_rows(p.Report(), _labelled([good, bad], ["BENIGN", "DDoS"]))

    assert len(out) == 1
    assert out[p.LABEL_COL].tolist() == ["BENIGN"]


def test_r4_drops_a_negative_flow_duration():
    """The 22 rows the A1 audit predicted."""
    good = [1.0] * c.N_FEATURES
    bad = [1.0] * c.N_FEATURES
    bad[c.FEATURES_24.index("flow_duration")] = -1.0

    out = p.drop_corrupt_rows(p.Report(), _labelled([good, bad], ["BENIGN", "BENIGN"]))
    assert len(out) == 1


def test_r4_keeps_a_row_whose_only_offence_is_minus_inf():
    """-inf is R3's job, not R4's. Dropping it here would delete a legitimate
    zero-duration flow - which is exactly what a port scan produces."""
    good = [1.0] * c.N_FEATURES
    neg_inf = [1.0] * c.N_FEATURES
    neg_inf[c.FEATURES_24.index("flow_byts_s")] = float("-inf")

    out = p.drop_corrupt_rows(p.Report(), _labelled([good, neg_inf], ["BENIGN", "PortScan"]))
    assert len(out) == 2


def test_r4_keeps_nan_and_plus_inf():
    """Neither is negative; neither is R4's business."""
    rows = []
    for fill in (float("nan"), float("inf")):
        row = [1.0] * c.N_FEATURES
        row[c.FEATURES_24.index("flow_pkts_s")] = fill
        rows.append(row)

    out = p.drop_corrupt_rows(p.Report(), _labelled(rows, ["BENIGN", "BENIGN"]))
    assert len(out) == 2


def test_r4_before_r3_leaves_minus_inf_as_zero_not_dropped():
    """The ordering, end to end: R4 keeps the -inf row, R3 then turns the value
    into 0.0. Run the other way round, sanitize would have hidden a genuinely
    corrupt row behind a pristine-looking 0.0."""
    rows = [[1.0] * c.N_FEATURES, [1.0] * c.N_FEATURES]
    i = c.FEATURES_24.index("flow_byts_s")
    rows[1][i] = float("-inf")

    df = _labelled(rows, ["BENIGN", "PortScan"])
    out = p.apply_r3(p.Report(), p.drop_corrupt_rows(p.Report(), df))

    assert len(out) == 2
    assert out.iloc[1, i] == c.MISSING_VALUE


# ---------------------------------------------------------------------------
# 3. label_to_target integration
# ---------------------------------------------------------------------------

def test_excluded_families_are_removed_not_relabelled_benign():
    """Bot must disappear, not become a benign example. Teaching the model that
    a botnet flow is normal traffic is worse than never showing it one."""
    raw = pd.DataFrame({
        "Label": ["BENIGN", "Bot", "DDoS", "Heartbleed", "Infiltration"],
        **{col: [1.0] * 5 for col in c.CSV_COLUMNS_24},
    })

    out = p.map_labels(p.Report(), raw)

    assert out[p.LABEL_COL].tolist() == ["BENIGN", "DDoS"]
    assert out[p.TARGET_COL].tolist() == [c.BENIGN, c.ATTACK]


def test_web_attack_variants_are_dropped_by_prefix():
    """The label carries a byte sequence that is not valid UTF-8; it is matched
    by ASCII prefix, never spelled out."""
    raw = pd.DataFrame({
        "Label": ["BENIGN", "Web Attack ï¿½ Brute Force"],
        **{col: [1.0] * 2 for col in c.CSV_COLUMNS_24},
    })
    assert p.map_labels(p.Report(), raw)[p.LABEL_COL].tolist() == ["BENIGN"]


def test_unknown_label_raises_and_is_not_caught():
    """A silent default would poison the training set with no error anywhere."""
    raw = pd.DataFrame({
        "Label": ["BENIGN", "SomeNewAttack2026"],
        **{col: [1.0] * 2 for col in c.CSV_COLUMNS_24},
    })
    with pytest.raises(ValueError, match="Unknown label"):
        p.map_labels(p.Report(), raw)


# ---------------------------------------------------------------------------
# 4. The split
# ---------------------------------------------------------------------------

def _synthetic_split_frame() -> pd.DataFrame:
    """Imbalanced on purpose: a large benign class and a small attack family,
    which is where a non-stratified split goes wrong first."""
    rng = np.random.default_rng(7)
    families = {"BENIGN": 4000, "DDoS": 800, "PortScan": 400, "SSH-Patator": 100}

    rows, labels = [], []
    for name, n in families.items():
        rows.extend(rng.normal(10, 1, size=(n, c.N_FEATURES)))
        labels.extend([name] * n)

    df = _frame(list(rows))
    df[p.LABEL_COL] = labels
    df[p.TARGET_COL] = [c.label_to_target(l) for l in labels]
    return df


def test_split_is_stratified_on_the_family_not_the_binary_target():
    """Every family must keep its share in both halves - otherwise A5 cannot
    report recall for the small families at all."""
    df = _synthetic_split_frame()
    _, _, _, _, label_train, label_test = p.split(df)

    overall = df[p.LABEL_COL].value_counts(normalize=True)
    for name, share in overall.items():
        assert label_train.value_counts(normalize=True)[name] == pytest.approx(share, abs=0.01)
        assert label_test.value_counts(normalize=True)[name] == pytest.approx(share, abs=0.01)


def test_split_sizes_follow_test_size():
    df = _synthetic_split_frame()
    X_train, X_test, *_ = p.split(df)
    assert len(X_test) == pytest.approx(len(df) * p.TEST_SIZE, abs=1)
    assert len(X_train) + len(X_test) == len(df)


def test_split_is_reproducible_across_runs():
    """RANDOM_STATE is frozen so the numbers in the note keep meaning something."""
    df = _synthetic_split_frame()
    first = p.split(df)
    second = p.split(df)

    for a, b in zip(first, second):
        assert a.index.equals(b.index)


def test_split_keeps_rows_aligned_with_their_labels():
    """A row separated from its own label is the failure no metric detects."""
    df = _synthetic_split_frame()
    X_train, X_test, y_train, y_test, label_train, label_test = p.split(df)

    for X, y, lab in ((X_train, y_train, label_train), (X_test, y_test, label_test)):
        assert X.index.equals(y.index)
        assert X.index.equals(lab.index)
        assert (lab.map(c.label_to_target) == y).all()


# ---------------------------------------------------------------------------
# 5. Duplicates are measured, not acted on
# ---------------------------------------------------------------------------

def test_duplicates_are_measured_but_not_dropped():
    row = [1.0] * c.N_FEATURES
    df = _labelled([row, list(row), row], ["DDoS", "DDoS", "DDoS"])

    mask = p.measure_duplicates(p.Report(), df)

    assert int(mask.sum()) == 2      # two of the three are duplicates
    assert len(df) == 3              # and the frame is untouched


def test_same_features_different_label_is_not_a_duplicate():
    """The label is part of the key: two families sharing a vector is a
    modelling problem, not a repeated row."""
    row = [1.0] * c.N_FEATURES
    df = _labelled([row, list(row)], ["BENIGN", "DDoS"])
    assert int(p.measure_duplicates(p.Report(), df).sum()) == 0
