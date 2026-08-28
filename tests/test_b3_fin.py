from scapy.all import IP, TCP
from src.system.capture import PacketCapture

capture = PacketCapture()

SRC_IP = "192.168.10.66"
DST_IP = "192.168.10.100"
SRC_PORT = 50002
DST_PORT = 80

BASE_TIME = 3000.0


def send_packet(flags, src_ip, dst_ip, sport, dport, timestamp):
    packet = (
        IP(src=src_ip, dst=dst_ip)
        / TCP(
            sport=sport,
            dport=dport,
            flags=flags
        )
    )

    packet.time = timestamp
    capture.process_manager(packet)


# Tráfico normal
for i in range(10):
    send_packet(
        "S",
        SRC_IP,
        DST_IP,
        SRC_PORT,
        DST_PORT,
        BASE_TIME + (i * 0.01)
    )


# FIN de A -> B
send_packet(
    "FA",
    SRC_IP,
    DST_IP,
    SRC_PORT,
    DST_PORT,
    BASE_TIME + 1.0
)


# FIN de B -> A
send_packet(
    "FA",
    DST_IP,
    SRC_IP,
    DST_PORT,
    SRC_PORT,
    BASE_TIME + 1.1
)


# ACK final de A -> B
send_packet(
    "A",
    SRC_IP,
    DST_IP,
    SRC_PORT,
    DST_PORT,
    BASE_TIME + 1.2
)


print("\ntest fin ask finished")