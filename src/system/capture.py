from scapy.all import sniff, IP, TCP, UDP

from src.capture.flow_manager import FlowManager
from src.common import config

class PacketCapture:

    def __init__(self):
        self.flow_manager = FlowManager()

    def process_manager(self, packet):

        if IP not in packet:
            return

        if TCP not in packet and UDP not in packet:
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = "TCP"
            tcp_flags = str(packet[TCP].flags)
        else:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = "UDP"
            tcp_flags = None

        packet_size = len(packet)
        timestamp = float(packet.time)

        completed_flow = self.flow_manager.process_packet(
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol= protocol,
            packet_size=packet_size,
            timestamp=timestamp,
            tcp_flags=tcp_flags
        )

        if completed_flow is not None:
            print("Flow completed")
            print("Key:", completed_flow.key())
            print("Packages: ", completed_flow.packet_count)
            print("Byes: ", completed_flow.total_bytes)
            print("Features: ", len(completed_flow.get_features()))

    def start(self):
        print("IDS CAPTURE:")
        print("Interface: ", config.CAPTURE_INTERFACE)
        print("BPF: ", config.BPF_FILTER)
        print("Waiting packages...")
        print("ctrl + c to stop.. ")

        sniff(iface = config.CAPTURE_INTERFACE, filter = config.BPF_FILTER, prn = self.process_manager, store = False)
