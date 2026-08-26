"""
Tests for the A7 first-pass module.

Light: the module's value is the measurement it reports, and that measurement
needs the real pcaps and the fitted model, neither of which belongs in a unit
test. These cover the pure logic that could silently mislabel a result.

Run:  pytest -v tests/test_lab_calibration.py
"""
import numpy as np
import pandas as pd
import pytest

from common import config
from intelligence import contract as c
from intelligence import lab_calibration as lc


# ---------------------------------------------------------------------------
# 1. Band assignment must follow config.py, not a copy of the numbers
# ---------------------------------------------------------------------------

def test_bands_follow_config_and_are_boundary_correct():
    """A flow at exactly the threshold must be contained; one at exactly
    SEV_HIGH must escalate. Off by one here changes what gets blocked."""
    assert lc.band_of(config.THRESHOLD - 0.001) == "ignored"
    assert lc.band_of(config.THRESHOLD) == "MEDIUM"
    assert lc.band_of(config.SEV_HIGH - 0.001) == "MEDIUM"
    assert lc.band_of(config.SEV_HIGH) == "HIGH"
    assert lc.band_of(1.0) == "HIGH"


def test_band_of_reads_config_rather_than_hardcoding(monkeypatch):
    """If someone moves the operating point, this module must move with it."""
    monkeypatch.setattr(config, "THRESHOLD", 0.30)
    monkeypatch.setattr(config, "SEV_HIGH", 0.60)
    assert lc.band_of(0.35) == "MEDIUM"
    assert lc.band_of(0.65) == "HIGH"


# ---------------------------------------------------------------------------
# 2. The capture map must stay coherent with the contract
# ---------------------------------------------------------------------------

def test_every_expected_family_is_one_the_model_was_trained_on():
    """A capture mapped to a family the model never saw would be compared
    against a reference distribution that does not exist."""
    for name, family in lc.CAPTURES:
        if family is not None:
            assert family in c.ATTACK_LABELS, f"{name} -> {family}"


def test_benign_captures_are_marked_as_benign_not_as_a_family():
    benign = [name for name, family in lc.CAPTURES if family is None]
    assert benign, "A7 needs benign captures to measure the false positive rate"
    assert all("benigno" in name for name in benign)


def test_compare_features_are_all_in_the_contract():
    """The comparison table indexes the training parquet by these names."""
    for feature in lc.COMPARE_FEATURES:
        assert feature in c.FEATURES_24


# ---------------------------------------------------------------------------
# 3. Scoring passes named columns, not a bare array
# ---------------------------------------------------------------------------

def test_score_returns_the_attack_probability_column():
    """Column 1 is P(attack). Taking column 0 would invert every conclusion in
    the report while still producing plausible-looking numbers."""

    class FakeModel:
        def predict_proba(self, frame):
            assert list(frame.columns) == list(c.FEATURES_24)
            n = len(frame)
            return np.column_stack([np.full(n, 0.25), np.full(n, 0.75)])

    frame = pd.DataFrame(np.zeros((3, c.N_FEATURES)), columns=c.FEATURES_24)
    assert lc.score(FakeModel(), frame) == pytest.approx([0.75] * 3)
