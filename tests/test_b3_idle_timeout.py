from scapy.all import IP, TCP
from src.system.capture import PacketCapture

capture = PacketCapture()

SRC_IP = "192.168.10.66"
DST_IP = "192.168.10.100"
SRC_PORT = 50003
DST_PORT = 80

BASE_TIME = 4000.0


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


# Primer paquete: crea el flow
capture.process_manager(
    make_packet(BASE_TIME)
)

# Segundo paquete: sigue dentro del mismo flow
capture.process_manager(
    make_packet(BASE_TIME + 1)
)

# Han pasado 20 segundos desde el último paquete.
# Esto supera IDLE_TIMEOUT = 15 s.
capture.process_manager(
    make_packet(BASE_TIME + 21)
)

print("\nidle timeout test finished")