"""
Block 0 - measure what the live path actually produces.

Replays a pcap through PacketCapture and prints the 24 contract values that
reach the model. Changes nothing: SOAR is stubbed out so the run does not
create cases in cases.db, and no source file is touched.

Usage:
    PYTHONPATH=. python3 tests/dump_vectors.py ./pcaps/portscan_lento_corrected.pcap
    PYTHONPATH=. python3 tests/dump_vectors.py ./pcapsv3/slowloris.pcap 8
"""
import io
import sys
from contextlib import redirect_stdout

from scapy.all import rdpcap

from src.intelligence import contract as c
from src.intelligence.extractor import extract_features
from src.intelligence.flow_adapter import FlowAdapter
from src.system.capture import PacketCapture


def main(pcap_path: str, show: int = 5) -> None:
    capture = PacketCapture()

    # This is a measurement, not a run. SOAR must not create cases.
    capture.soar.process_alert = lambda flow, probability: {
        "case": None, "severity": "-", "action": "-", "ttl": 0
    }

    records = []

    def spy(flow):
        vector = extract_features(FlowAdapter(flow))
        probability = capture.inference_pipeline.predictor(vector)
        records.append((flow, vector, probability))
        return {"case": None, "severity": "-", "action": "-", "ttl": 0}

    # Replace the inference step entirely: we want the vector, not the prints.
    capture.process_inference = spy

    packets = rdpcap(pcap_path)

    # process_manager prints one line per packet; swallow it.
    with redirect_stdout(io.StringIO()):
        for packet in packets:
            capture.process_manager(packet)

        # A pcap just stops. Without this the still-open windows are dropped.
        capture.flush()

    report(pcap_path, len(packets), records, show)


def print_vector(flow, vector, probability):
    print(f"key        : {flow.key()}")
    print(f"packets    : {flow.packet_count}   "
          f"fwd={flow.forward_packets} bwd={flow.backward_packets}")
    print(f"probability: {probability:.4f}")
    for i, name in enumerate(c.FEATURES_24):
        print(f"  [{i:2d}] {name:<20} {vector[i]:>18,.4f}")


def stats(label, records):
    probabilities = [p for _, _, p in records]
    print(f"{label:<28} n={len(records):<5}"
          f" min={min(probabilities):.4f}"
          f" mean={sum(probabilities) / len(probabilities):.4f}"
          f" max={max(probabilities):.4f}"
          f"  >=0.50: {sum(1 for p in probabilities if p >= 0.50)}"
          f"  >=0.70: {sum(1 for p in probabilities if p >= 0.70)}")


def report(pcap_path, packet_total, records, show):
    print("=" * 72)
    print("PCAP           :", pcap_path)
    print("Packets read   :", packet_total)
    print("Inferences     :", len(records))
    print("=" * 72)

    if not records:
        print("No inferences. Nothing to measure.")
        return

    single = sum(1 for flow, _, _ in records if flow.packet_count == 1)
    print(f"\nInferences on a 1-packet flow : {single}/{len(records)}"
          f"  ({100 * single / len(records):.1f}%)")

    sizes = {}
    for flow, _, _ in records:
        sizes[flow.packet_count] = sizes.get(flow.packet_count, 0) + 1
    print("Packets per inferred flow     :",
          ", ".join(f"{n} pkt x{count}" for n, count in sorted(sizes.items())))

    # Split the population. A flow with no backward packet is a filtered port:
    # it has no duration and no rate by definition, and CICIDS2017 contains no
    # rows shaped like it, so averaging it together with real SYN/RST exchanges
    # hides what the model is actually doing.
    complete = [r for r in records if r[0].backward_packets > 0]
    partial = [r for r in records if r[0].backward_packets == 0]

    print()
    stats("ALL inferences", records)
    if complete:
        stats("WITH backward packet", complete)
    if partial:
        stats("WITHOUT backward packet", partial)

    always_zero = [
        c.FEATURES_24[i]
        for i in range(c.N_FEATURES)
        if all(vector[i] == 0.0 for _, vector, _ in records)
    ]
    print(f"\nFeatures that are 0.0 in EVERY inference: "
          f"{len(always_zero)}/{c.N_FEATURES}")
    for name in always_zero:
        print("   ", name)

    if complete:
        print("\n" + "=" * 72)
        print("HIGHEST probability among flows with a backward packet")
        print("=" * 72)
        best = max(complete, key=lambda r: r[2])
        print_vector(*best)

    print("\n" + "=" * 72)
    print(f"Top {show} vectors by packet count")
    print("=" * 72)

    ranked = sorted(records, key=lambda r: -r[0].packet_count)

    for n, (flow, vector, probability) in enumerate(ranked[:show], start=1):
        print(f"\n--- inference {n} ---")
        print_vector(flow, vector, probability)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        raise SystemExit(1)

    main(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 5)
