from scapy.all import IP, TCP
from src.system.capture import PacketCapture

capture = PacketCapture()

SRC_IP = "192.168.10.66"
DST_IP = "192.168.10.100"
SRC_PORT = 50004
DST_PORT = 80

BASE_TIME = 5000.0


def make_packet(timestamp):
    packet = (
        IP(src=SRC_IP, dst=DST_IP)
        / TCP(
            sport=SRC_PORT,
            dport=DST_PORT,
            flags="S"
        )
    )

    packet.time = timestamp
    return packet


capture.process_manager(
    make_packet(BASE_TIME)
)


capture.process_manager(
    make_packet(BASE_TIME + 10)
)

capture.process_manager(
    make_packet(BASE_TIME + 130)
)

print("\n=== PRUEBA ACTIVE TIMEOUT TERMINADA ===")