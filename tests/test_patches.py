"""
Tests for the runtime patches applied to cicflowmeter 0.5.0.

These are not tests of "does the code run". Each one corresponds to a
concrete way a patch could fail in silence -- a wrong branch, a missing key,
a substitution that lands on a name nobody reads -- and produces a CSV that
looks perfectly reasonable and is wrong.

Run:  pytest -v tests/test_patches.py
"""
from pathlib import Path

import numpy
import pytest

from intelligence.cicflowmeter_patches import (
    _patched_get_statistics,
    apply_patches,
)

PCAP = Path("data/pcap/synthetic_smoke.pcap")
KEYS = {"total", "max", "min", "mean", "std"}


def _original_get_statistics(alist):
    """The upstream implementation, reproduced verbatim as the regression
    baseline for lists of two or more elements."""
    iat = dict()
    alist = [float(x) for x in alist]
    if len(alist) > 1:
        iat["total"] = sum(alist)
        iat["max"] = max(alist)
        iat["min"] = min(alist)
        iat["mean"] = numpy.mean(alist)
        iat["std"] = numpy.sqrt(numpy.var(alist))
    else:
        iat["total"] = 0
        iat["max"] = 0
        iat["min"] = 0
        iat["mean"] = 0
        iat["std"] = 0
    return iat


# ---------------------------------------------------------------------------
# 1. The defect itself: one interval is a measurement, not a missing value
# ---------------------------------------------------------------------------

def test_single_interval_reports_its_own_value():
    """This is the defect. A two-packet conversation delimits exactly one
    interval; upstream reports zero for it. If this test fails, every
    port-scan probe reaches the model with flow_iat_mean/max/min = 0 while
    the training CSV carries the real interval, and parity is broken."""
    stats = _patched_get_statistics([0.01])
    assert stats["mean"] == pytest.approx(0.01)
    assert stats["max"] == pytest.approx(0.01)
    assert stats["min"] == pytest.approx(0.01)
    assert stats["total"] == pytest.approx(0.01)


def test_single_interval_reports_zero_dispersion():
    """flow_iat_std is the one statistic upstream got right: dispersion of a
    single sample is zero, and that is what the reference CICFlowMeter that
    produced CICIDS2017 reports too. Returning anything else here would
    introduce a new parity break while fixing the old one."""
    assert _patched_get_statistics([0.01])["std"] == pytest.approx(0.0)


def test_empty_list_reports_zeros():
    """A single-packet flow has no interval at all. Zero is the correct
    answer here, and the patch must keep that case explicit -- widening the
    fix to the empty list would invent a measurement out of nothing."""
    stats = _patched_get_statistics([])
    assert all(stats[k] == 0 for k in KEYS)


# ---------------------------------------------------------------------------
# 2. The shape of the returned dictionary
# ---------------------------------------------------------------------------

def test_both_branches_return_the_same_five_keys():
    """flow.py reads ["total"], ["max"], ["min"], ["mean"] and ["std"] by
    name. If the empty branch returned a trimmed dictionary or None, every
    single-packet flow would die with KeyError instead of being written."""
    assert set(_patched_get_statistics([]).keys()) == KEYS
    assert set(_patched_get_statistics([0.01]).keys()) == KEYS
    assert set(_patched_get_statistics([0.01, 0.02]).keys()) == KEYS


# ---------------------------------------------------------------------------
# 3. No regression on the cases upstream already handled
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("values", [
    [0.01, 0.02],
    [0.01, 0.02, 0.03],
    [0.05, 0.01, 0.02, 0.02],
    [1.0, 1.0, 1.0],
    [0.0, 0.0],
])
def test_multi_element_lists_match_the_original(values):
    """The patch is meant to change one branch and nothing else. Any drift on
    lists of two or more elements would move features that are already in
    parity with the dataset -- a far worse outcome than the defect itself."""
    patched = _patched_get_statistics(values)
    original = _original_get_statistics(values)
    for key in KEYS:
        assert patched[key] == pytest.approx(original[key]), key


# ---------------------------------------------------------------------------
# 4. The substitution lands where the code actually reads it
# ---------------------------------------------------------------------------

def test_patch_replaces_the_reference_flow_actually_uses():
    """flow.py does `from .utils import get_statistics` at import time, which
    binds its own reference. Patching only cicflowmeter.utils would leave the
    running code untouched: the tests above would pass and the CSV would
    still carry zeros. This test is what catches that mistake."""
    apply_patches()
    import cicflowmeter.flow
    import cicflowmeter.utils

    assert cicflowmeter.flow.get_statistics is _patched_get_statistics
    assert cicflowmeter.utils.get_statistics is _patched_get_statistics


def test_apply_patches_is_idempotent():
    """apply_patches() is called by the pcap wrapper and, later, by the live
    extractor. Without the module flag, a second call would wrap the already
    patched Flow.__init__ inside itself. That still runs, so nothing would
    look broken -- it would just clear self.packets twice."""
    from cicflowmeter.flow import Flow
    import cicflowmeter.flow

    apply_patches()
    init_after_first = Flow.__init__
    stats_after_first = cicflowmeter.flow.get_statistics

    apply_patches()

    assert Flow.__init__ is init_after_first
    assert cicflowmeter.flow.get_statistics is stats_after_first


# ---------------------------------------------------------------------------
# 5. End to end, against the synthetic capture of known ground truth
# ---------------------------------------------------------------------------

def test_end_to_end_on_synthetic_capture(tmp_path):
    """The unit tests above check the patched function in isolation. This one
    checks that the corrected value survives the whole pipeline and reaches
    the CSV column the contract reads. In a two-packet flow the only interval
    is the whole flow duration; in the seven-packet conversation the packets
    are 10 ms apart by construction."""
    if not PCAP.exists():
        pytest.skip(
            f"{PCAP} not found. Generate it with: "
            "python scripts/check_cicflowmeter.py"
        )
    pandas = pytest.importorskip("pandas")

    from intelligence.pcap_to_csv import pcap_to_csv

    out = tmp_path / "flows.csv"
    try:
        pcap_to_csv(PCAP, out)
    except (ImportError, OSError, FileNotFoundError) as exc:
        pytest.skip(
            f"cicflowmeter could not read the capture ({exc}). "
            "Reading a pcap needs libpcap and tcpdump installed."
        )

    df = pandas.read_csv(out)
    probes = df[df["tot_fwd_pkts"] + df["tot_bwd_pkts"] == 2]
    conversation = df[df["tot_fwd_pkts"] + df["tot_bwd_pkts"] == 7]

    assert len(probes) == 3, "the capture defines three two-packet probes"
    assert len(conversation) == 1, "the capture defines one seven-packet flow"

    for _, row in probes.iterrows():
        assert row["flow_iat_mean"] == pytest.approx(row["flow_duration"])
        assert row["flow_iat_max"] == pytest.approx(row["flow_duration"])
        assert row["flow_iat_min"] == pytest.approx(row["flow_duration"])

    assert conversation.iloc[0]["flow_iat_mean"] == pytest.approx(0.01)
