"""
Runtime corrections applied to cicflowmeter 0.5.0.

The library is not modified on disk. Every fix lives here, in project code,
so it travels with the repository and applies identically on any machine.

Three defects were found while validating the tool against a synthetic
capture of known ground truth, plus one definition divergence against the
CICIDS2017 dataset that is not a defect at all. The full evidence -- how
each one was detected, why it matters and how it was verified -- is in
copilot/cicflowmeter_bugs.md.

BUG 1 (CLI, loud): main() calls create_sniffer() with positional arguments
that no longer match its signature, so `verbose` lands in `fields` and every
command-line invocation crashes. NOT fixed here: it is fixed at the call
site, by bypassing main() and passing keyword arguments to create_sniffer()
in pcap_to_csv.py. Listed here so the inventory of defects is complete in
one place.

BUG 2 (double counting, silent): Flow.__init__ seeds self.packets with the
first packet, and FlowSession.process() then calls add_packet() with that
same packet. Every flow counts its first packet twice, inflating forward
packet/byte counts, SYN counts, rates, and corrupting IAT statistics (the
duplicate carries an identical timestamp, so it injects a 0-second gap).
Fixed here by clearing the pre-seeded list.

BUG 3 (single-interval statistics collapse to zero, silent): utils
get_statistics() guards the whole statistics block with `len(alist) > 1`,
so a one-element list returns zeros for total, max, min and mean as well as
for std. N packets delimit N-1 intervals, so a two-packet conversation has
exactly one inter-arrival time and reports it as zero. That is the shape of
a port-scan probe. Fixed here by guarding only the empty case.

R2 (packet length, a divergence and NOT a defect): cicflowmeter measures
packet length as the full frame; the CICIDS2017 CSV measures it as transport
payload. Neither is wrong -- they are two implementations of the same idea --
but the model trains on the CSV, so the extractor has to say what the CSV
says. Aligned here by measuring payload instead of frame. This is the exact
opposite of what bug 3 called for, under the same criterion: parity is
defined against the CSV, not against mathematical correctness.
"""
import numpy
from scapy.layers.inet import TCP, UDP

import cicflowmeter.flow
import cicflowmeter.utils
from cicflowmeter.features.flow_bytes import FlowBytes
from cicflowmeter.features.packet_length import PacketLength
from cicflowmeter.flow import Flow

# Set once apply_patches() has run. The module-level flag is what makes the
# function idempotent: without it, a second call would wrap the already
# patched Flow.__init__ inside itself.
_PATCHES_APPLIED = False

_original_flow_init = Flow.__init__


def _patched_flow_init(self, packet, direction):
    """Bug 2. Protects every count-derived and rate-derived feature of the
    contract -- tot_fwd_pkts, totlen_fwd_pkts, fwd_pkt_len_*, pkt_len_*,
    flow_pkts_s, flow_byts_s, fwd_act_data_pkts -- plus the IAT features,
    which the duplicated timestamp would otherwise seed with a 0-second gap.
    """
    _original_flow_init(self, packet, direction)
    # Drop the pre-seeded packet. FlowSession.process() adds it back
    # immediately after construction, so nothing is lost.
    self.packets = []


def _patched_get_statistics(alist: list) -> dict:
    """Bug 3. Protects flow_iat_mean, flow_iat_max and flow_iat_min (contract
    positions 15, 17 and 18), and fwd_iat_mean / bwd_iat_mean (19 and 20) when
    a direction carries exactly two packets. flow_iat_std is not affected:
    with a single sample, zero dispersion is the correct answer, and it is
    what the reference CICFlowMeter reports too.
    """
    values = [float(x) for x in alist]
    if not values:
        # A single-packet flow has no interval at all: zero is the correct
        # answer here, not a stand-in for a missing value. Both branches must
        # return the same five keys - flow.py reads every one of them by name.
        return {"total": 0, "max": 0, "min": 0, "mean": 0, "std": 0}
    return {
        "total": sum(values),
        "max": max(values),
        "min": min(values),
        "mean": numpy.mean(values),
        "std": numpy.sqrt(numpy.var(values)),
    }


def _payload_length(packet) -> int:
    """Length of a packet as the CICIDS2017 CSV measures it: transport payload
    rather than full frame.

    The Ethernet padding is deliberately counted as payload. Ethernet requires
    a minimum frame of 60 bytes, so a bare 54-byte TCP packet travels with 6
    bytes of zeros appended, and the Java CICFlowMeter that produced the
    dataset counts them. Since TCP header options grow in 4-byte words, the
    only padding values that can occur are 6, 2 and 0 -- which is exactly the
    distribution the dataset shows: in 158,870 PortScan flows, the RST that a
    closed port sends back (a packet that carries no data at all) reports a
    Bwd Packet Length Min of 6 in 99.26% of cases.

    scapy reproduces this for free: it attaches the padding as a Padding layer
    inside the transport payload, so len(packet[TCP].payload) already includes
    it. Computing the payload arithmetically from ip.len would be *correct*
    and would report 0 -- and would therefore break parity. See section 6 of
    copilot/cicflowmeter_bugs.md.

    Only IPv4 TCP and UDP packets reach a Flow: flow_session.py drops
    everything else behind the "ip and (tcp or udp)" filter. Anything else
    returns 0.
    """
    if TCP in packet:
        return len(packet[TCP].payload)
    if UDP in packet:
        return len(packet[UDP].payload)
    return 0


def _patched_get_packet_length(self, packet_direction=None) -> list:
    """R2. Every packet-length statistic goes through this one method, so it
    covers eleven contract positions at once: totlen_fwd_pkts,
    totlen_bwd_pkts (3, 4), fwd_pkt_len_min/mean/std/max (5-8),
    bwd_pkt_len_min/mean/std/max (9-12) and pkt_len_mean/std (13, 14).
    """
    if packet_direction is not None:
        return [
            _payload_length(packet)
            for packet, direction in self.flow.packets
            if direction == packet_direction
        ]
    return [_payload_length(packet) for packet, _ in self.flow.packets]


def _patched_get_bytes(self) -> int:
    """R2. Feeds flow_byts_s, contract position 22.

    FlowBytes.get_bytes_sent() and get_bytes_received() measure frames too,
    and are left alone on purpose: they feed none of the 24 contract
    positions, so changing them would widen the patch for no gain.
    """
    return sum(_payload_length(packet) for packet, _ in self.flow.packets)


def apply_patches() -> None:
    """Apply every runtime correction to cicflowmeter. Safe to call repeatedly.

    Must run before any Flow is built, i.e. before the sniffer is created.
    """
    global _PATCHES_APPLIED
    if _PATCHES_APPLIED:
        return

    # Bug 3. flow.py does `from .utils import get_statistics` at import time,
    # which binds its own reference in the flow module namespace. Replacing
    # cicflowmeter.utils.get_statistics alone has no effect whatsoever on the
    # code that actually runs: cicflowmeter.flow.get_statistics is the name
    # the Flow object resolves. Both are replaced -- flow because it is the
    # one that matters, utils for module-wide consistency.
    cicflowmeter.flow.get_statistics = _patched_get_statistics
    cicflowmeter.utils.get_statistics = _patched_get_statistics

    # Bug 2.
    Flow.__init__ = _patched_flow_init

    # R2. No import trap here, unlike bug 3: flow.py imports the classes, not
    # the methods, so replacing an attribute on the class object is seen by
    # every holder of a reference to it.
    PacketLength.get_packet_length = _patched_get_packet_length
    FlowBytes.get_bytes = _patched_get_bytes

    _PATCHES_APPLIED = True
