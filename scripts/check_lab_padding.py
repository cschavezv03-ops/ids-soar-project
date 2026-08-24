"""
Does the lab traffic carry Ethernet padding, and does it carry it in BOTH
directions?

Why this matters. CICIDS2017 counts Ethernet padding as payload: a closed port
answers a SYN probe with a 54-byte RST, Ethernet pads it to the 60-byte minimum,
and the CSV reports 6 bytes of "payload" (verified: 99.26% of PortScan flows).
Rule R2 therefore replicates that behaviour instead of correcting it.

But padding is added by the network card on TRANSMIT. A packet captured on the
machine that SENDS it may still be unpadded; the same packet captured on the
machine that RECEIVES it arrives padded. The IDS runs on the victim, so:

    inbound  (attacker -> victim)   already padded    matches the CSV
    outbound (victim -> attacker)   possibly NOT      would break parity

If outbound small frames are unpadded, contract positions 9-12 (bwd_pkt_len_min,
_mean, _std, _max) would read 0 live where the CSV reads 6 - and precisely on the
RSTs that answer a port scan.

Only frames below 60 bytes can show padding, so the report is restricted to them.
TCP headers grow in 4-byte words, so the only possible padding values are 6
(no TCP options), 2 (a 4-byte option) and 0 (8+ bytes of options).

Run:  python scripts/check_lab_padding.py data/pcap/*.pcap
"""
import sys
from collections import Counter
from pathlib import Path

from scapy.all import Ether, PcapReader

VICTIM_IP = "192.168.56.10"      # keep in sync with src/common/config.py
ETHERNET_MIN_FRAME = 60


def payload_as_the_csv_measures_it(packet) -> int:
    """R2: scapy's transport payload, which includes Ethernet padding -
    exactly what the Java CICFlowMeter counted."""
    for protocol in ("TCP", "UDP"):
        if protocol in packet:
            return len(packet[protocol].payload)
    return 0


def payload_without_padding(packet) -> int:
    """The arithmetically correct payload, immune to padding. Kept only as a
    contrast: if the two columns differ, the difference IS the padding."""
    if "IP" not in packet:
        return 0
    ip = packet["IP"]
    if "TCP" in packet:
        transport_header = packet["TCP"].dataofs * 4
    elif "UDP" in packet:
        transport_header = 8
    else:
        return 0
    return max(0, ip.len - ip.ihl * 4 - transport_header)


def inspect(path: Path) -> None:
    print("=" * 72)
    print(path.name)
    print("=" * 72)

    stats = {
        "inbound": {"total": 0, "small": 0, "sizes": Counter(), "pad": Counter()},
        "outbound": {"total": 0, "small": 0, "sizes": Counter(), "pad": Counter()},
    }
    other = 0

    with PcapReader(str(path)) as reader:
        for packet in reader:
            if "IP" not in packet:
                continue
            ip = packet["IP"]
            if ip.dst == VICTIM_IP:
                bucket = stats["inbound"]
            elif ip.src == VICTIM_IP:
                bucket = stats["outbound"]
            else:
                other += 1
                continue

            size = len(packet)
            bucket["total"] += 1
            if size < ETHERNET_MIN_FRAME:
                # Below the Ethernet minimum: this frame was NOT padded.
                bucket["small"] += 1
            bucket["sizes"][size] += 1
            bucket["pad"][
                payload_as_the_csv_measures_it(packet) - payload_without_padding(packet)
            ] += 1

    if other:
        print(f"(ignored {other:,} packets not involving {VICTIM_IP})\n")

    for name, label in [("inbound", f"INBOUND   -> {VICTIM_IP}"),
                        ("outbound", f"OUTBOUND  <- {VICTIM_IP}")]:
        bucket = stats[name]
        print(label)
        if bucket["total"] == 0:
            print("  no packets in this direction\n")
            continue

        print(f"  packets:                       {bucket['total']:>8,}")
        print(f"  frames under {ETHERNET_MIN_FRAME} bytes (unpadded): {bucket['small']:>8,}"
              f"   {bucket['small'] / bucket['total']:>7.2%}")

        print("  frame sizes seen (5 most common):")
        for size, count in bucket["sizes"].most_common(5):
            mark = "   <-- unpadded" if size < ETHERNET_MIN_FRAME else ""
            print(f"    {size:>6} bytes  {count:>8,}{mark}")

        print("  padding counted as payload by R2:")
        for pad, count in sorted(bucket["pad"].items()):
            share = count / bucket["total"]
            note = "" if pad == 0 else "   <-- fake payload bytes, as in the CSV"
            print(f"    {pad:>6} bytes  {count:>8,}  {share:>7.2%}{note}")
        print()

    verdict(stats)


def verdict(stats) -> None:
    inbound, outbound = stats["inbound"], stats["outbound"]
    print("-" * 72)

    def unpadded_share(bucket):
        return bucket["small"] / bucket["total"] if bucket["total"] else float("nan")

    inbound_unpadded = unpadded_share(inbound)
    outbound_unpadded = unpadded_share(outbound)

    if outbound["total"] == 0:
        print("No outbound traffic in this capture: the question stays open.")
    elif outbound_unpadded > 0.05 and not (inbound_unpadded > 0.05):
        print("ASYMMETRY CONFIRMED. Inbound frames are padded, outbound ones are")
        print("not. Contract positions 9-12 (bwd_pkt_len_*) would read 0 live")
        print("where the CSV reads 6. R2 needs a live-side compensation.")
    elif outbound_unpadded <= 0.05 and inbound_unpadded <= 0.05:
        print("Both directions are padded on capture. R2 as decided is enough:")
        print("no compensation needed.")
    else:
        print("Unexpected pattern. Read the frame-size tables above before")
        print("concluding anything.")
    print()


if __name__ == "__main__":
    paths = [Path(p) for p in sys.argv[1:]]
    if not paths:
        sys.exit("usage: python scripts/check_lab_padding.py <capture.pcap> [...]")
    for path in paths:
        if not path.exists():
            print(f"skipping {path}: not found\n")
            continue
        inspect(path)