from scapy.all import IP, TCP
from src.system.capture import PacketCapture
from src.common import config


capture = PacketCapture()

SRC_IP = "192.168.10.66"
DST_IP = "192.168.10.100"
BASE_TIME = 6000.0


def make_packet(src_port, dst_port, timestamp):
    packet = (
        IP(src=SRC_IP, dst=DST_IP)
        / TCP(
            sport=src_port,
            dport=dst_port,
            flags="S"
        )
    )

    packet.time = timestamp
    return packet


# ============================================================
# FLOW 1
# ============================================================

for i in range(config.WINDOW_SIZE):
    capture.process_manager(
        make_packet(
            50005,
            80,
            BASE_TIME + i
        )
    )


# ============================================================
# FLOW 2
# ============================================================

for i in range(config.WINDOW_SIZE):
    capture.process_manager(
        make_packet(
            50006,
            443,
            BASE_TIME + config.WINDOW_SIZE + i
        )
    )


print("\n=== PRUEBA B3 MULTIPLE FLOWS TERMINADA ===")

print("\nWINDOW_SIZE:", config.WINDOW_SIZE)

print("\nFlows activos:")

for key, flow in capture.flow_manager.flows.items():
    print(
        key,
        "packets=", flow.packet_count,
        "bytes=", flow.total_bytes
    )