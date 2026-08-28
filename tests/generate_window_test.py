#!/usr/bin/env python3

from scapy.all import IP, TCP, Raw, wrpcap


PACKETS = []

SRC_IP = "192.168.56.20"
DST_IP = "192.168.56.10"
SRC_PORT = 50000
DST_PORT = 80


for i in range(250):
    packet = (
        IP(src=SRC_IP, dst=DST_IP)
        / TCP(
            sport=SRC_PORT,
            dport=DST_PORT,
            seq=i,
            ack=1,
            flags="PA",
        )
        / Raw(load=b"A" * 100)
    )

    PACKETS.append(packet)


output = "/tmp/window_test_250.pcap"

wrpcap(output, PACKETS)

print(f"PCAP creado: {output}")
print(f"Paquetes: {len(PACKETS)}")
