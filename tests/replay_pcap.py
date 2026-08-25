#!/usr/bin/env python3
"""
Replay a PCAP through PacketCapture without flooding the terminal.

Default mode:
    Shows only inference/window events and a final summary.

Use --verbose if you want every packet printed by PacketCapture.
"""

import argparse
import contextlib
import io
import sys
from pathlib import Path

from scapy.utils import PcapReader

from src.system.capture import PacketCapture


def main():
    parser = argparse.ArgumentParser(
        description="Replay a PCAP through the IDS inference pipeline."
    )
    parser.add_argument("pcap", help="Path to the PCAP file")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show PacketCapture's per-packet output",
    )
    args = parser.parse_args()

    pcap_path = Path(args.pcap).expanduser()

    if not pcap_path.is_file():
        print(f"ERROR: no existe el PCAP: {pcap_path}")
        sys.exit(1)

    capture = PacketCapture()

    packet_count = 0
    inference_count = 0
    window_events = []
    original_process_inference = capture.process_inference

    def tracked_inference(flow):
        nonlocal inference_count
        inference_count += 1
        window_events.append(
            {
                "packets": flow.packet_count,
                "bytes": flow.total_bytes,
                "key": flow.key(),
            }
        )
        return original_process_inference(flow)

    capture.process_inference = tracked_inference

    print("=" * 70)
    print("IDS PCAP REPLAY - SUMMARY MODE")
    print("=" * 70)
    print("PCAP:", pcap_path)
    print()

    try:
        with PcapReader(str(pcap_path)) as reader:
            for packet in reader:
                packet_count += 1

                if args.verbose:
                    capture.process_manager(packet)
                else:
                    # PacketCapture currently prints every packet. Suppress
                    # those low-level prints while keeping inference output.
                    buffer = io.StringIO()
                    with contextlib.redirect_stdout(buffer):
                        capture.process_manager(packet)

                    # The inference/SOAR output is produced inside
                    # process_inference, so tracked_inference captured the
                    # event even though stdout is suppressed.

    except KeyboardInterrupt:
        print("\nReplay interrumpido por el usuario.")

    finally:
        # Process any windows left alive at the end of the PCAP.
        pending = list(capture.inference_windows.items())

        if pending:
            print()
            print("========== END OF PCAP: PENDING WINDOWS ==========")

            for key, window in pending:
                if window.packet_count > 0:
                    print(f"Flow: {key}")
                    print(f"Window packets: {window.packet_count}")
                    print(f"Window bytes: {window.total_bytes}")

                    tracked_inference(window)

            capture.inference_windows.clear()

        print()
        print("=" * 70)
        print("PCAP REPLAY FINISHED")
        print("=" * 70)
        print(f"Packets read: {packet_count}")
        print(f"Total inferences: {inference_count}")
        print()

        if window_events:
            print("Inference windows:")
            for i, event in enumerate(window_events, 1):
                print(
                    f"  #{i:04d}  packets={event['packets']:4d}  "
                    f"bytes={event['bytes']:8d}  flow={event['key']}"
                )
        else:
            print("No inference windows were generated.")


if __name__ == "__main__":
    main()
