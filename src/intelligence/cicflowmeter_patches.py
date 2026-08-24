"""
Runtime corrections applied to cicflowmeter 0.5.0.

The library is not modified on disk. Every fix lives here, in project code,
so it travels with the repository and applies identically on any machine.

Three defects were found while validating the tool against a synthetic
capture of known ground truth. The full evidence -- how each one was
detected, why it matters and how it was verified -- is in
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
"""
import numpy

import cicflowmeter.flow
import cicflowmeter.utils
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

    _PATCHES_APPLIED = True
