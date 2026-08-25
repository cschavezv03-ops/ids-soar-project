"""
Tests for the A7 recalibration module.

Light: the value of this module is the measurement, which needs the lab pcaps
and the fitted model. These cover the logic that could silently misreport.

Run:  pytest -v tests/test_recalibrate.py
"""
import numpy as np
import pytest

from common import config
from intelligence import contract as c
from intelligence import recalibrate as r
from intelligence import threshold as th


def test_config_carries_the_a7_decision():
    """config.py is the source of truth shared with component B. If it drifts,
    every report describes an operating point the system does not use."""
    assert config.THRESHOLD == r.NEW_CONTAIN
    assert config.SEV_MEDIUM == r.NEW_CONTAIN
    assert config.SEV_HIGH == r.NEW_HIGH


def test_a6_guard_moved_with_the_decision():
    """threshold.py refuses to run unless config matches its own constants.
    A7 moved the point, so A6's guard has to move too or nothing runs."""
    assert th.CONTAIN_THRESHOLD == r.NEW_CONTAIN
    assert th.HIGH_THRESHOLD == r.NEW_HIGH
    th.assert_config_matches_decision()


def test_the_new_point_is_lower_than_the_old_one():
    """A7 lowered the cut. If a later edit inverts this, the note's whole
    argument - that 0.70 was too high for our traffic - stops holding."""
    assert r.NEW_CONTAIN < r.OLD_CONTAIN
    assert r.NEW_HIGH < r.OLD_HIGH
    assert r.NEW_CONTAIN < r.NEW_HIGH


def test_capture_manifest_maps_to_real_contract_families():
    """A capture mapped to a family the model never trained on would be
    compared against a reference distribution that does not exist."""
    for name, family in r.CAPTURES_V2.items():
        assert name.endswith(".pcap")
        if family is not None:
            assert family in c.ATTACK_LABELS, f"{name} -> {family}"


def test_benign_and_attack_captures_are_both_present():
    """Without benign captures there is no false positive rate to measure,
    which is exactly what blocked the first pass."""
    benign = [n for n, f in r.CAPTURES_V2.items() if f is None]
    attack = [n for n, f in r.CAPTURES_V2.items() if f is not None]
    assert benign and attack
    assert all(r.is_benign(n) for n in benign)
    assert not any(r.is_benign(n) for n in attack)


def test_flood_captured_at_several_intensities():
    """Three intensities are what let the report state that the flood's score
    is independent of speed, instead of arguing it."""
    floods = [n for n in r.CAPTURES_V2 if n.startswith("ataque_syn")]
    assert len(floods) >= 3


def test_sweep_covers_both_operating_points():
    """The report marks the old and new cuts on the sweep; if the grid misses
    them the marks silently disappear."""
    assert any(abs(v - r.NEW_CONTAIN) < 1e-9 for v in r.SWEEP)
    assert any(abs(v - r.OLD_CONTAIN) < 1e-9 for v in r.SWEEP)
