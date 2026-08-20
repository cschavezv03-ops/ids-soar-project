"""
Thin wrapper around cicflowmeter's internals.

Why this exists: cicflowmeter 0.5.0 ships a broken CLI. Its main()
calls create_sniffer() with positional arguments that no longer match
the function signature (an `input_directory` parameter was inserted
mid-signature and the call site was never updated), so `verbose` lands
in `fields` and every invocation crashes. We bypass main() entirely and
call create_sniffer() with KEYWORD arguments, which is immune to that
misalignment. The flow-extraction engine itself is unaffected.
"""
import sys
from pathlib import Path

from cicflowmeter.sniffer import create_sniffer


def pcap_to_csv(pcap_path: str | Path, csv_path: str | Path) -> Path:
    """Extract network flows from a pcap file into a CSV."""
    pcap_path, csv_path = Path(pcap_path), Path(csv_path)

    if not pcap_path.exists():
        raise FileNotFoundError(f"pcap not found: {pcap_path}")
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    # Every argument by name: this is what sidesteps the 0.5.0 bug.
    sniffer, session = create_sniffer(
        input_file=str(pcap_path),
        input_interface=None,      # exactly one input source may be set
        output_mode="csv",         # the value `-c` maps to
        output=str(csv_path),
        input_directory=None,
        fields=None,               # None = keep all columns
        verbose=False,
    )

    sniffer.start()
    try:
        sniffer.join()             # block until the whole pcap is read
    finally:
        # The library spawns a background thread that expires idle flows.
        if hasattr(session, "_gc_stop"):
            session._gc_stop.set()
            session._gc_thread.join(timeout=2.0)
        # Flows still open in memory are written out here. Without this
        # call, unterminated flows (e.g. scan probes) never reach the CSV.
        session.flush_flows()

    return csv_path


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: python pcap_to_csv.py <input.pcap> <output.csv>")
    print(f"Wrote flows to {pcap_to_csv(sys.argv[1], sys.argv[2])}")