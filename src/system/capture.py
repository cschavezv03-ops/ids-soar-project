from scapy.all import sniff, IP, TCP, UDP

from src.capture.flow import Flow
from src.capture.flow_manager import FlowManager
from src.common import config
from src.system.pipeline import InferencePipeline, dummy_predictor
from src.system.soar import SOAREngine


class PacketCapture:

    def __init__(self):

        self.flow_manager = FlowManager()

        self.inference_pipeline = InferencePipeline(
            predictor=dummy_predictor
        )

        self.soar = SOAREngine()

        # Guarda una ventana independiente por cada flow activo.
        self.inference_windows = {}

    def process_inference(self, flow):

        result = self.inference_pipeline.process_flow(flow)

        src_ip, probability = result

        soar_result = self.soar.process_alert(
            flow=flow,
            probability=probability
        )

        print("Inference:", result)
        print("SOAR:", soar_result)

        return soar_result

    def process_pending_window(self, flow):

        key = flow.key()

        window = self.inference_windows.pop(key, None)

        if window is None:
            return

        if window.packet_count == 0:
            return

        print("========== PARTIAL WINDOW ==========")
        print("Flow:", key)
        print("Window packets:", window.packet_count)
        print("Window bytes:", window.total_bytes)

        self.process_inference(window)

    def get_inference_window(self, flow):

        key = flow.key()

        if key not in self.inference_windows:

            self.inference_windows[key] = Flow(
                src_ip=flow.src_ip,
                src_port=flow.src_port,
                dst_ip=flow.dst_ip,
                dst_port=flow.dst_port,
                protocol=flow.protocol
            )

        return self.inference_windows[key]

    def process_manager(self, packet):

        if IP not in packet:
            return

        if TCP not in packet and UDP not in packet:
            return

        # IPs

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Transport protocol

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

        # Packet size

        packet_size = len(packet)

        # Ethernet minimum frame size / padding handling
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



        # ACTIVE TIMEOUT

        active_flows = self.flow_manager.check_active_timeouts(
            timestamp
        )

        for flow in active_flows:

            print("========== FLOW ACTIVE TIMEOUT ==========")
            print("Key:", flow.key())
            print("Packets:", flow.packet_count)
            print("Bytes:", flow.total_bytes)

            self.process_pending_window(flow)


        # IDLE TIMEOUT


        idle_flows = self.flow_manager.check_timeouts(
            timestamp
        )

        for flow in idle_flows:

            print("========== FLOW IDLE TIMEOUT ==========")
            print("Key:", flow.key())
            print("Packets:", flow.packet_count)
            print("Bytes:", flow.total_bytes)

            self.process_pending_window(flow)

        # UPDATE FLOW MANAGER


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


        # GET ACTIVE FLOW

        flow = self.flow_manager.get_or_create_flow(

            src_ip,
            src_port,

            dst_ip,
            dst_port,

            protocol
        )

        # INFERENCE WINDOW

        window = self.get_inference_window(flow)

        window.add_packet(

            src_ip=src_ip,
            src_port=src_port,

            dst_ip=dst_ip,
            dst_port=dst_port,

            packet_size=packet_size,
            timestamp=timestamp,

            tcp_flags=tcp_flags,
            payload_size=payload_size
        )


        # COMPLETE INFERENCE WINDOW
  

        if window.packet_count >= config.WINDOW_SIZE:

            print("========== INFERENCE WINDOW ==========")
            print("Flow:", flow.key())
            print("Window packets:", window.packet_count)
            print("Window bytes:", window.total_bytes)

            self.process_inference(window)


            del self.inference_windows[flow.key()]

 
        # FLOW COMPLETED BY FIN / RST


        if completed_flow is not None:

            print("========== FLOW COMPLETED ==========")
            print("Key:", completed_flow.key())
            print("Packets:", completed_flow.packet_count)
            print("Bytes:", completed_flow.total_bytes)

  
            self.process_pending_window(completed_flow)

            return

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