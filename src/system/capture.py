from scapy.all import sniff, IP, TCP, UDP

from src.capture.flow_manager import FlowManager
from src.common import config
from src.system.pipeline import (InferencePipeline, dummy_predictor)
from src.system.soar import SOAREngine


class PacketCapture:

    def __init__(self):
        self.flow_manager = FlowManager()
        self.inference_pipeline = InferencePipeline(predictor=dummy_predictor)
        self.soar = SOAREngine()

    def process_inference(self, flow):
        result = self.inference_pipeline.process_flow(flow)

        src_ip, probability = result

        soar_result = self.soar.process_alert(
            flow=flow,
            probability=probability
        )

        print("Inference: ", result)
        print("SOAR: ", soar_result)

        return soar_result
        

    def process_manager(self, packet):

        if IP not in packet:
            return

        if TCP not in packet and UDP not in packet:
            return

        # IPs
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = "TCP"
            tcp_flags = str(packet[TCP].flags)
            payload_size = len(packet[TCP].payload)

        else:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = "UDP"
            tcp_flags = None
            payload_size = len(packet[UDP].payload)

        packet_size = len(packet)

        if src_ip == config.VICTIM_IP and packet_size < 60:
            packet_size = 60

        timestamp = float(packet.time)

        print(
            f"[PACKET] {protocol} "
            f"{src_ip}:{src_port} -> "
            f"{dst_ip}:{dst_port} "
            f"size={packet_size} "
            f"payload={payload_size}"
        )

        # TIMEOUTS


        # IDLE TIMEOUT


        # ACTIVE TIMEOUT
        active_flows = self.flow_manager.check_active_timeouts(timestamp)

        for flow in active_flows:
            print("========== FLOW ACTIVE TIMEOUT ==========")
            print("Key:", flow.key())
            print("Packets:", flow.packet_count)
            print("Bytes:", flow.total_bytes)

            self.process_inference(flow)

        idle_flows = self.flow_manager.check_timeouts(timestamp)

        for flow in idle_flows:
            print("========== FLOW IDLE TIMEOUT ==========")
            print("Key:", flow.key())
            print("Packets:", flow.packet_count)
            print("Bytes:", flow.total_bytes)

            self.process_inference(flow)

        completed_flow = self.flow_manager.process_packet(
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            packet_size=packet_size,
            timestamp=timestamp,
            tcp_flags=tcp_flags,
            payload_size=payload_size
        )


        # FLOW COMPLETED BY FIN / RST


        if completed_flow is not None:
            print("========== FLOW COMPLETED ==========")
            print("Key:", completed_flow.key())
            print("Packets:", completed_flow.packet_count)
            print("Bytes:", completed_flow.total_bytes)

            self.process_inference(completed_flow)

            return


        # ACTIVE FLOW


        flow = self.flow_manager.get_or_create_flow(
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol
        )


        # PARTIAL WINDOW

        if flow.packet_count % config.WINDOW_SIZE == 0:

            self.process_inference(flow)

            features = flow.get_features()

            print("========== PARTIAL WINDOW ==========")
            print("Flow:", flow.key())
            print("Packets:", flow.packet_count)
            print("Bytes:", flow.total_bytes)


    def start(self):

        print("IDS CAPTURE:")
        print("Interface:", config.CAPTURE_INTERFACE)
        print("BPF:", config.BPF_FILTER)
        print("Waiting packets...")
        print("Ctrl + C to stop..")

        sniff(
            iface=config.CAPTURE_INTERFACE,
            filter=config.BPF_FILTER,
            prn=self.process_manager,
            store=False
        )