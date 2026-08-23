from src.capture.flow import Flow


class FlowManager:

    def __init__(self):
        self.flows = {}

    def get_or_create_flow(
            self,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol
    ):

        key = (
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol
        )

        reverse_key = (
            dst_ip,
            dst_port,
            src_ip,
            src_port,
            protocol
        )

        if key in self.flows:
            return self.flows[key]

        if reverse_key in self.flows:
            return self.flows[reverse_key]

        self.flows[key] = Flow(
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol
        )

        return self.flows[key]

    def process_packet(
            self,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol,
            packet_size,
            timestamp,
            tcp_flags = None

    ):

        flow = self.get_or_create_flow(
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol
        )

        flow.add_packet(
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            packet_size,
            timestamp,
            tcp_flags
        )

        if tcp_flags and ("F" in tcp_flags or "R" in tcp_flags):

            key = flow.key()

            if key in self.flows:
                del self.flows[key]

            return flow

        return None

    def check_timeouts(self, current_time):
        expired_flows = []

        for key, flow in list(self.flows.items()):
            if not flow.timestamps:
                continue

            last_packet_time = flow.timestamps[0]

            if current_time - last_packet_time >= 15:
                expired_flows.append(flow)
                del self.flows[key]

        return expired_flows


    def check_active_timeouts(self, current_time):

        print("CHECK ACTIVE TIMEOUTS")
        print("Current:", current_time)
        print("Flows:", len(self.flows))

        expired_flows = []

        for key, flow in list(self.flows.items()):

            print("Flow:", key)
            print("Timestamps:", flow.timestamps)

            if not flow.timestamps:
                print("SIN TIMESTAMPS")
                continue

            first_packet_time = flow.timestamps[0]
            flow_duration = current_time - first_packet_time

            print("First:", first_packet_time)
            print("Duration:", flow_duration)
            print("Expired:", flow_duration >= 120)

            if flow_duration >= 120:
                print(">>> EXPIRANDO <<<")

                expired_flows.append(flow)
                del self.flows[key]

        return expired_flows
        