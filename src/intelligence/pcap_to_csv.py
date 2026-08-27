"""
Thin wrapper around cicflowmeter's internals.

cicflowmeter 0.5.0 carries three defects that would silently corrupt the
feature vector. They are documented in copilot/cicflowmeter_bugs.md and
corrected in cicflowmeter_patches.py, except for the command-line defect
(bug 1), whose fix lives here: main() mis-orders its positional arguments,
so this module bypasses it and calls create_sniffer() with keyword arguments
instead. Do not turn that call back into positional form.
"""
import sys
from pathlib import Path

from cicflowmeter.sniffer import create_sniffer

try:  # imported as part of the package (tests, live extractor)
    from .cicflowmeter_patches import apply_patches
except ImportError:  # run directly: python src/intelligence/pcap_to_csv.py
    from cicflowmeter_patches import apply_patches


def pcap_to_csv(pcap_path: str | Path, csv_path: str | Path) -> Path:
    """Extract network flows from a pcap file into a CSV."""
    pcap_path, csv_path = Path(pcap_path), Path(csv_path)

    if not pcap_path.exists():
        raise FileNotFoundError(f"pcap not found: {pcap_path}")
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    # Must happen before the sniffer exists: it is what builds the Flow
    # objects, and a Flow built from unpatched code carries the defects.
    apply_patches()

    sniffer, session = create_sniffer(
        input_file=str(pcap_path),
        input_interface=None,
        output_mode="csv",
        output=str(csv_path),
        input_directory=None,
        fields=None,
        verbose=False,
    )

    sniffer.start()
    try:
        sniffer.join()
    finally:
        if hasattr(session, "_gc_stop"):
            session._gc_stop.set()
            session._gc_thread.join(timeout=2.0)
        # Flows still open in memory are written here. Without this,
        # unterminated flows (e.g. scan probes) never reach the CSV.
        session.flush_flows()

    return csv_path


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: python pcap_to_csv.py <input.pcap> <output.csv>")
    print(f"Wrote flows to {pcap_to_csv(sys.argv[1], sys.argv[2])}")
