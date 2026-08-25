"""
Tests for the A6 threshold module.

Light: A6 computes metrics from artifacts A5 already verified. These cover only
what could break silently - a threshold policy that no longer matches the one
the running system uses, or a band boundary that is off by one comparison.

Run:  pytest -v tests/test_threshold.py
"""
import numpy as np
import pandas as pd
import pytest

from common import config
from intelligence import contract as c
from intelligence import threshold as th


# ---------------------------------------------------------------------------
# 1. The decision and the running system must not drift apart
# ---------------------------------------------------------------------------

def test_config_carries_the_a6_decision():
    """config.py is shared with component B and nothing else forces the two to
    agree. If it drifts, the report describes an operating point the system
    does not use - a documentation lie no other test would catch."""
    assert config.THRESHOLD == th.CONTAIN_THRESHOLD
    assert config.SEV_MEDIUM == th.CONTAIN_THRESHOLD
    assert config.SEV_HIGH == th.HIGH_THRESHOLD
    th.assert_config_matches_decision()


def test_drifted_config_stops_the_run(monkeypatch):
    monkeypatch.setattr(config, "THRESHOLD", 0.5)
    with pytest.raises(SystemExit, match="disagrees with the A6 decision"):
        th.assert_config_matches_decision()


def test_the_bands_are_ordered_and_leave_no_gap():
    """A gap between the tiers would silently ignore flows above the
    containment floor; an inversion would make MEDIUM stricter than HIGH."""
    assert th.CONTAIN_THRESHOLD < th.HIGH_THRESHOLD
    assert config.SHORT_BLOCK_TTL < config.BLOCK_TTL_SECONDS


# ---------------------------------------------------------------------------
# 2. Band boundaries
# ---------------------------------------------------------------------------

def _labelled(proba, y):
    labels = np.where(np.asarray(y) == c.ATTACK, "DDoS", c.BENIGN_LABEL)
    return np.asarray(proba), np.asarray(y), labels


def test_band_boundaries_are_inclusive_below_exclusive_above():
    """A flow at exactly 0.70 must be contained, and one at exactly 0.90 must
    escalate. Off-by-one here changes what gets blocked and for how long."""
    proba, y, labels = _labelled(
        [0.69, 0.70, 0.89, 0.90], [c.BENIGN, c.ATTACK, c.ATTACK, c.ATTACK]
    )
    bands = th.band_composition(y, proba, labels).set_index("band")
    totals = bands["total"].to_dict()

    assert list(totals.values()) == [1, 2, 1]   # ignored, MEDIUM, HIGH


def test_every_flow_lands_in_exactly_one_band():
    rng = np.random.default_rng(0)
    proba = rng.random(500)
    y = (rng.random(500) < 0.3).astype(int)
    _, y, labels = _labelled(proba, y)

    bands = th.band_composition(y, proba, labels)
    assert bands["total"].sum() == len(proba)
    assert (bands["attack"] + bands["benign"] == bands["total"]).all()


# ---------------------------------------------------------------------------
# 3. Metrics
# ---------------------------------------------------------------------------

def test_sweep_reports_counts_not_just_rates():
    """'FPR 0.0023' hides how many real users that is. The counts are the
    number the operational argument is made with."""
    proba, y, _ = _labelled([0.1, 0.8, 0.9, 0.95], [c.BENIGN, c.BENIGN, c.ATTACK, c.ATTACK])
    row = th.sweep_metrics(y, proba, [0.85]).iloc[0]

    assert row["tp"] == 2 and row["fp"] == 0 and row["fn"] == 0
    assert row["recall"] == pytest.approx(1.0)
    assert row["precision"] == pytest.approx(1.0)


def test_raising_the_threshold_never_increases_recall():
    """Monotonicity. A violation would mean the comparison is inverted
    somewhere, which no aggregate score would reveal."""
    rng = np.random.default_rng(1)
    proba = rng.random(2000)
    y = (rng.random(2000) < 0.3).astype(int)

    sweep = th.sweep_metrics(y, proba)
    assert (sweep["recall"].diff().dropna() <= 1e-12).all()
    assert (sweep["fp"].diff().dropna() <= 0).all()


def test_precision_at_prevalence_matches_the_measured_value():
    """Feeding the test set's own prevalence back must reproduce the precision
    actually measured, or the base-rate projection is wrong."""
    rng = np.random.default_rng(2)
    proba = rng.random(5000)
    y = (rng.random(5000) < 0.25).astype(int)

    row = th.sweep_metrics(y, proba, [0.5]).iloc[0]
    prevalence = float((y == c.ATTACK).mean())

    projected = th.precision_at_prevalence(row["recall"], row["fpr"], prevalence)
    assert projected == pytest.approx(row["precision"], abs=1e-9)


def test_precision_collapses_as_attacks_get_rarer():
    """The finding A6 cannot fix: the same model degrades on a quieter network
    purely by arithmetic."""
    high = th.precision_at_prevalence(0.99, 0.002, 0.1667)
    low = th.precision_at_prevalence(0.99, 0.002, 0.001)
    assert high > 0.9 and low < 0.4


# ---------------------------------------------------------------------------
# 4. Per-family table
# ---------------------------------------------------------------------------

def test_family_table_separates_recall_from_false_positive_rate():
    proba, y, labels = _labelled(
        [0.2, 0.95, 0.95, 0.2], [c.BENIGN, c.BENIGN, c.ATTACK, c.ATTACK]
    )
    table = th.family_recall_by_threshold(labels, y, proba, [0.9]).set_index("family")

    assert table.loc["DDoS", "metric"] == "recall"
    assert table.loc["DDoS", 0.9] == pytest.approx(0.5)
    assert table.loc[c.BENIGN_LABEL, "metric"] == "false positive rate"
    assert table.loc[c.BENIGN_LABEL, 0.9] == pytest.approx(0.5)
