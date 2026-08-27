"""
Tests for the A7 third-pass validation module.

Light: the value is the measurement over the lab pcaps. These pin the logic
that could silently mislabel a result.

Run:  pytest -v tests/test_validate_lab_attacks.py
"""
from intelligence import contract as c
from intelligence import validate_lab_attacks as v


def test_every_capture_maps_to_a_real_contract_family():
    """A capture mapped to a family the model never trained on would be
    compared against a reference distribution that does not exist."""
    for name, family in v.CAPTURES_V21.items():
        assert name.endswith(".pcap")
        assert family in c.ATTACK_LABELS, f"{name} -> {family}"


def test_verdict_thresholds_are_ordered():
    """DETECTED must need more than PARTIAL, which must need more than MISSED,
    or the one-word read in the report is meaningless."""
    assert v.verdict(0.9, 0) == "DETECTED"
    assert v.verdict(0.2, 0).startswith("PARTIAL")
    assert v.verdict(0.0, 0) == "MISSED"
    assert v.verdict(0.038, 0) == "MISSED"      # http_flood per-flow
    assert v.verdict(0.5, 0) == "DETECTED"      # boundary


def test_feature_groups_are_disjoint_and_in_the_contract():
    """The report separates the size gap from the timing gap; a feature in both
    groups, or in neither list, would blur that distinction."""
    assert not (set(v.SIZE_FEATURES) & set(v.TIME_FEATURES))
    for feature in v.SIZE_FEATURES + v.TIME_FEATURES:
        assert feature in c.FEATURES_24


def test_sweep_includes_the_live_cut():
    """The false-positive table must show the operating point itself."""
    from common import config
    assert any(abs(cut - config.THRESHOLD) < 1e-9 for cut in v.SWEEP)
