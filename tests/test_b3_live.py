from scapy.all import IP, TCP
from src.system.capture import PacketCapture

capture = PacketCapture()

SRC_IP = "192.168.10.66"
DST_IP = "192.168.10.100"
SRC_PORT = 50000
DST_PORT = 80

BASE_TIME = 1000.0

for i in range(110):
    packet = (
        IP(src=SRC_IP, dst=DST_IP)
        / TCP(
            sport=SRC_PORT,
            dport=DST_PORT,
            flags="S"
        )
    )

    packet.time = BASE_TIME + (i * 0.01)

    capture.process_manager(packet)

print("\nfinished")