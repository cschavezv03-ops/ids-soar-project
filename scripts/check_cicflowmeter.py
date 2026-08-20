"""
Smoke test: verify that cicflowmeter can actually parse a pcap
on this Python version. Builds a synthetic pcap in memory --
no packet is ever sent or captured.
"""
from pathlib import Path
from scapy.all import Ether, IP, TCP, Raw, wrpcap

OUT = Path("data/pcap/synthetic_smoke.pcap")
OUT.parent.mkdir(parents=True, exist_ok=True)

CLIENT, SERVER = "10.0.0.5", "10.0.0.10"
SPORT, DPORT = 54321, 80

packets = []
t = 1_700_000_000.0

def add(src, dst, sport, dport, flags, payload=b"", gap=0.01):
    """Append one TCP packet and advance the clock by gap seconds."""
    global t
    pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    if payload:
        pkt = pkt / Raw(load=payload)
    pkt.time = t                # cicflowmeter reads durations from this
    t += gap
    packets.append(pkt)

# A complete, ordinary TCP conversation: handshake, data, teardown.
add(CLIENT, SERVER, SPORT, DPORT, "S")                    # SYN
add(SERVER, CLIENT, DPORT, SPORT, "SA")                   # SYN-ACK
add(CLIENT, SERVER, SPORT, DPORT, "A")                    # ACK
add(CLIENT, SERVER, SPORT, DPORT, "PA", b"GET / HTTP/1.1\r\n\r\n")
add(SERVER, CLIENT, DPORT, SPORT, "PA", b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 400)
add(CLIENT, SERVER, SPORT, DPORT, "FA")                   # FIN
add(SERVER, CLIENT, DPORT, SPORT, "FA")

# A few scan-like flows: SYN out, RST back, never completed.
for i, port in enumerate([22, 443, 3306]):
    add(CLIENT, SERVER, 40000 + i, port, "S")
    add(SERVER, CLIENT, port, 40000 + i, "RA")

wrpcap(str(OUT), packets)
print(f"Wrote {len(packets)} synthetic packets to {OUT}")