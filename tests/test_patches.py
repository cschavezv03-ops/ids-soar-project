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
    _patched_get_bytes,
    _patched_get_packet_length,
    _patched_get_statistics,
    _payload_length,
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


# ---------------------------------------------------------------------------
# 6. R2 -- packet length measured as payload, Ethernet padding included
# ---------------------------------------------------------------------------

def _framed(packet):
    """Serialise a packet and pad it to Ethernet's 60-byte minimum, the way a
    real network interface would.

    wrpcap() does not pad, which is why the synthetic capture never exercises
    the padding case and why these unit tests have to build it by hand.
    """
    from scapy.layers.l2 import Ether
    from scapy.compat import raw

    frame = raw(packet)
    if len(frame) < 60:
        frame += b"\x00" * (60 - len(frame))
    return Ether(frame)


def _tcp(flags, options=None, payload=b""):
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw

    pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.10") / TCP(
        sport=40000, dport=22, flags=flags, options=options or []
    )
    if payload:
        pkt = pkt / Raw(load=payload)
    return _framed(pkt)


def test_bare_rst_reports_six_bytes_of_padding():
    """The RST a closed port sends back carries no data whatsoever, yet the
    CSV reports 6 for it in 99.26% of the 158,870 PortScan flows: the Java
    CICFlowMeter counts the Ethernet padding as payload. Computing the payload
    arithmetically from ip.len would return the mathematically correct 0 and
    would break parity on the single most discriminating attack class."""
    assert _payload_length(_tcp("RA")) == 6


def test_four_bytes_of_tcp_options_leave_two_bytes_of_padding():
    """TCP options grow the header in 4-byte words, so the padding needed to
    reach 60 bytes can only be 6, 2 or 0. This is the middle value: a
    54 + 4 = 58-byte frame padded with 2. If this returned anything else, the
    three-peak distribution the dataset shows would not be reproducible."""
    assert _payload_length(_tcp("SA", options=[("MSS", 1460)])) == 2


def test_twenty_bytes_of_tcp_options_leave_no_padding():
    """With 20 bytes of options the frame reaches 74 bytes and is never
    padded, so there is no payload to report. This is the 0.44% of PortScan
    flows where the CSV reports 0: open ports, whose SYN-ACK carries options.
    Those exceptions confirm the padding mechanism rather than contradict it,
    and the patch must reproduce them too."""
    assert _payload_length(
        _tcp("SA", options=[("MSS", 1460), ("SAckOK", b""),
                            ("Timestamp", (1, 0)), ("NOP", None),
                            ("WScale", 7)])
    ) == 0


def test_real_data_is_reported_as_itself():
    """The padding cases must not come at the cost of ordinary traffic: a
    packet with 400 bytes of data reports 400, not 400 plus the 54 bytes of
    headers the frame also carries."""
    assert _payload_length(_tcp("PA", payload=b"x" * 400)) == 400


def test_udp_payload_is_measured_too():
    """UDP reaches the flow constructor as well -- the capture filter is
    "ip and (tcp or udp)". A helper that only knew about TCP would silently
    report 0 for every DNS packet, and every UDP flow would look empty."""
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw

    # 14 + 20 + 8 + 40 = 82 bytes: above the 60-byte minimum, so no padding
    # is added and the expected value is unambiguous.
    pkt = _framed(
        Ether() / IP(src="10.0.0.5", dst="10.0.0.10")
        / UDP(sport=40000, dport=53) / Raw(load=b"y" * 40)
    )
    assert _payload_length(pkt) == 40


def test_r2_patch_replaces_both_measurement_points():
    """PacketLength.get_packet_length feeds eleven contract positions and
    FlowBytes.get_bytes feeds flow_byts_s. Patching only the first would leave
    position 22 measuring frames while the other twelve measure payload -- an
    internally inconsistent vector that no test of a single feature catches."""
    apply_patches()
    from cicflowmeter.features.flow_bytes import FlowBytes
    from cicflowmeter.features.packet_length import PacketLength

    assert PacketLength.get_packet_length is _patched_get_packet_length
    assert FlowBytes.get_bytes is _patched_get_bytes


def test_end_to_end_probes_carry_no_payload(tmp_path):
    """A scan probe is SYN out, RST back: two packets, no data in either
    direction. Under R2 the whole flow must report zero bytes. If these
    columns came back at 54, the extractor would be measuring frames while the
    training CSV measures payload, and every byte-volume feature would be
    offset by the header size."""
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
    assert len(probes) == 3, "the capture defines three two-packet probes"

    assert (probes["totlen_fwd_pkts"] == 0).all()
    assert (probes["totlen_bwd_pkts"] == 0).all()
    assert (probes["flow_byts_s"] == 0).all()
