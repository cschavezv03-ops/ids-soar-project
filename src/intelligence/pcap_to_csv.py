"""
Thin wrapper around cicflowmeter's internals, with two bugs worked around.

BUG 1 (CLI): cicflowmeter 0.5.0's main() calls create_sniffer() with
positional arguments that no longer match its signature, so `verbose`
lands in `fields` and every command-line invocation crashes. We bypass
main() and pass keyword arguments instead.

BUG 2 (double counting): Flow.__init__ seeds self.packets with the first
packet, and FlowSession.process() then calls add_packet() with that same
packet. Every flow counts its first packet twice, inflating forward
packet/byte counts, SYN counts, rates, and corrupting IAT statistics
(the duplicate has an identical timestamp, so it injects a 0-second gap).
We clear the pre-seeded list so process() is the only thing that adds it.
"""
import sys
from pathlib import Path

from cicflowmeter.flow import Flow
from cicflowmeter.flow_session import FlowSession
from cicflowmeter.sniffer import create_sniffer

# --- Bug 2 patch. Applied at import time, before any Flow is built. ---
_original_flow_init = Flow.__init__


def _patched_flow_init(self, packet, direction):
    _original_flow_init(self, packet, direction)
    # Drop the pre-seeded packet. FlowSession.process() adds it back
    # immediately after construction, so nothing is lost.
    self.packets = []


Flow.__init__ = _patched_flow_init
# ---------------------------------------------------------------------


def pcap_to_csv(pcap_path: str | Path, csv_path: str | Path) -> Path:
    """Extract network flows from a pcap file into a CSV."""
    pcap_path, csv_path = Path(pcap_path), Path(csv_path)

    if not pcap_path.exists():
        raise FileNotFoundError(f"pcap not found: {pcap_path}")
    csv_path.parent.mkdir(parents=True, exist_ok=True)

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