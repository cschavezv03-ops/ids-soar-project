"""
Profile a real pcap through the extractor.

This is NOT a parity check. The parity bench (parity_bench.py) proves the
extractor matches hand-derived truth on the synthetic pcap. That needs truth
known packet by packet, which real traffic does not have - nobody hand-computed
the 24 features of Frank's hundreds of flows.

What this tool answers instead, on real captures:

  1. ROBUSTNESS - does the extractor survive real, messy traffic? Every flow
     must yield 24 finite, non-negative floats. No NaN/inf leaking through, no
     flow that raises. The synthetic pcap is too clean to test this.

  2. ATTACK SIGNATURE - does the traffic look like what it claims to be? We
     cannot check exact values, but we know the SHAPE: a scan is many tiny,
     asymmetric, zero-payload flows; a conversation is fewer, larger, symmetric
     ones. If a capture labelled "scan" shows big payloads, something is wrong.

Both are qualitative. Neither is parity. For statistical closeness to CICIDS2017
(domain shift), that is task A7 and needs the CSV distributions, not this.

Run:  python scripts/profile_pcap.py data/pcap/portscan_rapido.pcap [more.pcap ...]
"""
import sys
from pathlib import Path

sys.path.insert(0, "src")

from intelligence import contract as c
from intelligence.cicflowmeter_patches import apply_patches
from intelligence.extractor import features_from_dict


def extract_all(pcap: Path) -> list[list[float]]:
    """Run the patched tool over the pcap, one 24-vector per flow."""
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
            output="/tmp/profile_pcap.csv", input_directory=None,
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


def is_finite_nonneg(value: float) -> bool:
    return value == value and value not in (float("inf"), float("-inf")) and value >= 0


def robustness(vectors: list[list[float]]) -> bool:
    """Part 1: every flow is a valid contract vector. Returns True if all pass."""
    print("  ROBUSTNESS")
    if not vectors:
        print("    no flows extracted - nothing to check")
        return True

    bad_length = [i for i, v in enumerate(vectors) if len(v) != c.N_FEATURES]
    bad_values = [
        (i, pos) for i, v in enumerate(vectors)
        for pos in range(len(v)) if not is_finite_nonneg(v[pos])
    ]
    contract_fail = [
        i for i, v in enumerate(vectors) if c.validate(v, strict=False)
    ]

    print(f"    flows extracted:            {len(vectors):>7,}")
    print(f"    wrong length (!= 24):       {len(bad_length):>7,}")
    print(f"    non-finite or negative:     {len(bad_values):>7,}")
    print(f"    fail contract validation:   {len(contract_fail):>7,}")

    ok = not (bad_length or bad_values or contract_fail)
    if not ok and bad_values[:3]:
        for i, pos in bad_values[:3]:
            print(f"      e.g. flow {i}, {c.FEATURES_24[pos]} = {vectors[i][pos]}")
    print("    -> " + ("all flows valid" if ok else "INVALID FLOWS FOUND"))
    return ok


def signature(vectors: list[list[float]]) -> None:
    """Part 2: the shape of the traffic. Descriptive only, no pass/fail."""
    print("  SIGNATURE")
    if not vectors:
        return

    # Positions we read for the shape.
    i_fwd = c.FEATURES_24.index("tot_fwd_pkts")
    i_bwd = c.FEATURES_24.index("tot_bwd_pkts")
    i_flen = c.FEATURES_24.index("totlen_fwd_pkts")
    i_blen = c.FEATURES_24.index("totlen_bwd_pkts")
    i_dur = c.FEATURES_24.index("flow_duration")

    n = len(vectors)
    total_pkts = [v[i_fwd] + v[i_bwd] for v in vectors]
    total_bytes = [v[i_flen] + v[i_blen] for v in vectors]

    tiny = sum(1 for p in total_pkts if p <= 3)            # scan-like: 1-3 packets
    # "control-only": no real data, just handshake/reset packets. R2 counts
    # Ethernet padding as payload, so these carry a few filler bytes, not 0.
    # 64 bytes is well below any real payload and above the padding.
    CONTROL_BYTE_CEILING = 64
    control_only = sum(1 for b in total_bytes if b <= CONTROL_BYTE_CEILING)
    # asymmetry: how one-sided the byte volume is, 0 = balanced, 1 = one-way.
    # Bytes, not packet counts: a SYN->RST scan is 1-vs-1 in packets (symmetric)
    # but a real conversation moves far more data one way than the other.
    asym = []
    for v in vectors:
        f, b = v[i_flen], v[i_blen]
        asym.append(abs(f - b) / (f + b) if (f + b) else 0.0)
    mean_asym = sum(asym) / n

    print(f"    flows:                      {n:>7,}")
    print(f"    tiny flows (<= 3 packets):  {tiny:>7,}   {tiny / n:>6.1%}")
    print(f"    control-only flows (<=64B): {control_only:>7,}   {control_only / n:>6.1%}")
    print(f"    mean asymmetry (0..1):      {mean_asym:>7.2f}")
    print(f"    median packets/flow:        {sorted(total_pkts)[n // 2]:>7.0f}")
    print(f"    median bytes/flow:          {sorted(total_bytes)[n // 2]:>7.0f}")

    # A one-line read of the shape, to eyeball against the filename.
    tiny_share = tiny / n
    control_share = control_only / n
    if tiny_share > 0.6 and control_share > 0.6:
        shape = "scan/flood-like: mostly tiny control-only flows"
    elif control_share < 0.4 and mean_asym > 0.3:
        shape = "conversation-like: larger flows with one-sided payload"
    else:
        shape = "mixed: no single dominant shape"
    print(f"    -> looks {shape}")


def main() -> int:
    paths = [Path(p) for p in sys.argv[1:]]
    if not paths:
        sys.exit("usage: python scripts/profile_pcap.py <capture.pcap> [...]")

    all_ok = True
    for path in paths:
        print("=" * 68)
        print(path.name)
        print("=" * 68)
        if not path.exists():
            print("  not found - skipped\n")
            continue
        vectors = extract_all(path)
        ok = robustness(vectors)
        all_ok = all_ok and ok
        signature(vectors)
        print()

    # Exit non-zero only if a flow was actually invalid, so this is CI-usable
    # for the robustness half. Signature is descriptive and never fails.
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())