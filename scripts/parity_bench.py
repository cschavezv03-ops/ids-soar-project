"""
Parity bench - the exit criterion of phase 0.

Proves that extract_features() lands each of the 24 contract features where the
CICIDS2017 CSV would put it. Not "does the code run" (the unit tests cover that)
but "do the measured values match tool-independent ground truth".

The trap this avoids: comparing the extractor against the tool's own CSV would
compare cicflowmeter with itself - they share get_data(), so they always agree,
even if both are wrong (parity A: the extractor with itself). Real proof needs
truth that does NOT come from the tool.

That truth is the synthetic pcap from scripts/check_cicflowmeter.py, whose every
packet we wrote by hand. GROUND_TRUTH below was derived from those packet
definitions - counts by counting, durations from the gaps, payloads from the
byte lengths - and independently cross-checked to agree with the tool on all
96 values. It encodes the three patches working: R1 (time in microseconds),
R2 (packet length as payload -> scan flows read 0), and bug 3 (single-interval
IAT reads the real interval, 10000, not 0).

Three comparison rules, one per feature group (from contract.py):
    COUNT_IDX    exact, no tolerance   - integer counts of things
    TIME_IDX     tolerance, post-R1    - floats, already scaled to microseconds
    PAYLOAD_IDX  tolerance             - the R2 features, vs hand truth
    everything else                    - tolerance (rates, means)

Run:  python scripts/parity_bench.py
Exit code 0 if every feature passes, 1 otherwise (usable in CI).
"""
import sys
from pathlib import Path

sys.path.insert(0, "src")

from intelligence import contract as c
from intelligence.cicflowmeter_patches import apply_patches
from intelligence.extractor import features_from_dict

PCAP = Path("data/pcap/synthetic_smoke.pcap")

# Relative tolerance for float comparisons. Counts use exact equality instead.
REL_TOL = 1e-6

FLOW_LABELS = ["HTTP conversation", "scan :22", "scan :443", "scan :3306"]

# Tool-independent ground truth, one dict per flow, keyed by contract feature.
# Derived by hand from the packet definitions in check_cicflowmeter.py; time
# features are in microseconds (post-R1). See the module docstring.
GROUND_TRUTH = [
    {   # Flow 0: the full HTTP conversation (4 fwd, 3 bwd packets)
        "flow_duration": 60000.0,
        "tot_fwd_pkts": 4, "tot_bwd_pkts": 3,
        "totlen_fwd_pkts": 18, "totlen_bwd_pkts": 419,
        "fwd_pkt_len_min": 0, "fwd_pkt_len_mean": 4.5,
        "fwd_pkt_len_std": 7.794228634059948, "fwd_pkt_len_max": 18,
        "bwd_pkt_len_min": 0, "bwd_pkt_len_mean": 139.66666666666666,
        "bwd_pkt_len_std": 197.5184942114423, "bwd_pkt_len_max": 419,
        "pkt_len_mean": 62.42857142857143, "pkt_len_std": 145.7021003308337,
        "flow_iat_mean": 10000.0, "flow_iat_std": 0.0,
        "flow_iat_max": 10000.0, "flow_iat_min": 10000.0,
        "fwd_iat_mean": 16666.666666666668, "bwd_iat_mean": 25000.0,
        "flow_pkts_s": 116.66666666666667, "flow_byts_s": 7283.333333333333,
        "fwd_act_data_pkts": 1,
    },
]
# Flows 1-3: the three scan probes, one SYN out and one RST back each. Identical
# in every feature - only the timing differs, and durations are all equal.
_SCAN = {
    "flow_duration": 10000.0,
    "tot_fwd_pkts": 1, "tot_bwd_pkts": 1,
    "totlen_fwd_pkts": 0, "totlen_bwd_pkts": 0,
    "fwd_pkt_len_min": 0, "fwd_pkt_len_mean": 0,
    "fwd_pkt_len_std": 0, "fwd_pkt_len_max": 0,
    "bwd_pkt_len_min": 0, "bwd_pkt_len_mean": 0,
    "bwd_pkt_len_std": 0, "bwd_pkt_len_max": 0,
    "pkt_len_mean": 0, "pkt_len_std": 0,
    # bug 3 in action: one interval must read the real gap (10000), not zero.
    "flow_iat_mean": 10000.0, "flow_iat_std": 0.0,
    "flow_iat_max": 10000.0, "flow_iat_min": 10000.0,
    # one packet per direction: no interval at all, legitimately zero.
    "fwd_iat_mean": 0, "bwd_iat_mean": 0,
    "flow_pkts_s": 200.0, "flow_byts_s": 0,
    "fwd_act_data_pkts": 0,
}
GROUND_TRUTH += [_SCAN, _SCAN, _SCAN]


def run_extractor_on_pcap(pcap: Path) -> list[list[float]]:
    """Run the patched tool over the pcap and return one 24-vector per flow,
    in capture order, by spying on each Flow's get_data()."""
    apply_patches()

    import cicflowmeter.flow as flow_module
    from cicflowmeter.sniffer import create_sniffer

    captured: list[dict] = []
    original = flow_module.Flow.get_data

    def spy(self, *args, **kwargs):
        data = original(self, *args, **kwargs)
        captured.append(dict(data))
        return data

    flow_module.Flow.get_data = spy
    try:
        sniffer, session = create_sniffer(
            input_file=str(pcap), input_interface=None, output_mode="csv",
            output="/tmp/parity_bench.csv", input_directory=None,
            fields=None, verbose=False,
        )
        sniffer.start()
        sniffer.join()
        if hasattr(session, "_gc_stop"):
            session._gc_stop.set()
            session._gc_thread.join(timeout=2.0)
        session.flush_flows()
    finally:
        flow_module.Flow.get_data = original

    return [features_from_dict(d) for d in captured]


def compare(expected: float, actual: float, position: int) -> bool:
    """Apply the rule for this feature's group."""
    if position in c.COUNT_IDX:
        return float(expected) == float(actual)          # exact, no tolerance
    return abs(expected - actual) <= REL_TOL * max(1.0, abs(expected))


def rule_name(position: int) -> str:
    if position in c.COUNT_IDX:
        return "count/exact"
    if position in c.TIME_IDX:
        return "time/R1"
    if position in c.PAYLOAD_IDX:
        return "payload/R2"
    return "rate"


def main() -> int:
    if not PCAP.exists():
        sys.exit(f"synthetic pcap missing: {PCAP}\nRun: python scripts/check_cicflowmeter.py")

    vectors = run_extractor_on_pcap(PCAP)

    if len(vectors) != len(GROUND_TRUTH):
        sys.exit(
            f"flow count mismatch: extractor produced {len(vectors)}, "
            f"ground truth has {len(GROUND_TRUTH)}. The pcap changed."
        )

    print(f"Parity bench over {PCAP.name}: {len(vectors)} flows x {c.N_FEATURES} features\n")

    # Per-feature pass/fail, aggregated across all flows.
    failures = []
    per_feature_ok = [True] * c.N_FEATURES

    for flow_index, (vector, truth) in enumerate(zip(vectors, GROUND_TRUTH)):
        for position, name in enumerate(c.FEATURES_24):
            expected = float(truth[name])
            actual = vector[position]
            if not compare(expected, actual, position):
                per_feature_ok[position] = False
                failures.append((position, name, flow_index, expected, actual))

    header = f"{'#':>2} {'feature':<20} {'rule':<12} result"
    print(header)
    print("-" * len(header))
    for position, name in enumerate(c.FEATURES_24):
        status = "PASS" if per_feature_ok[position] else "FAIL"
        print(f"{position:>2} {name:<20} {rule_name(position):<12} {status}")

    passed = sum(per_feature_ok)
    print(f"\n{passed}/{c.N_FEATURES} features match ground truth on all {len(vectors)} flows.")

    if failures:
        print("\nFAILURES:")
        for position, name, flow_index, expected, actual in failures:
            print(f"  [{position}] {name} on {FLOW_LABELS[flow_index]}: "
                  f"expected {expected}, got {actual}")
        print("\nPhase 0 is NOT closed. A failing feature must be fixed or, if it")
        print("cannot reach parity, replaced - bumping the contract to v1.1.")
        return 1

    print("\nAll 24 features reach parity. Phase 0 exit criterion met.")
    return 0


if __name__ == "__main__":
    sys.exit(main())