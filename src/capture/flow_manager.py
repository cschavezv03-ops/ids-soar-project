from src.capture.flow import Flow
from src.common import config


class FlowManager:

    def __init__(self):
        self.flows = {}

        # guarda en que direccion se dio el FIN
        self.fin_seen = {}

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
            tcp_flags=None,
            payload_size= None
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
            tcp_flags,
            payload_size
        )

        key = flow.key()

        
        # RST
        

        if tcp_flags and "R" in tcp_flags:

            if key in self.flows:
                del self.flows[key]

            self.fin_seen.pop(key, None)

            return flow

        
        # FIN
        
        if tcp_flags and "F" in tcp_flags:

            if key not in self.fin_seen:
                self.fin_seen[key] = {
                    "directions": set(),
                    "waiting_final_ack": False
                }

            direction= (src_ip, src_port, dst_ip, dst_port)

            self.fin_seen[key]["directions"].add(direction)

            if len(self.fin_seen[key]["directions"]) >= 2:
                self.fin_seen[key]["waiting_final_ack"] = True

            return None

    #ack final

        if tcp_flags and "A" in tcp_flags:  
            
            if key in self.fin_seen:  
                if self.fin_seen[key]["waiting_final_ack"]:

                    if key in self.flows:
                        del self.flows[key]

                    self.fin_seen.pop(key,None)

                    return flow
        return None

    def check_timeouts(self, current_time):

        expired_flows = []

        for key, flow in list(self.flows.items()):

            if not flow.timestamps:
                continue

            # Para timeout de INACTIVIDAD necesitamos el ultimo paquete que se ha recibido
            last_packet_time = flow.timestamps[-1]

            if current_time - last_packet_time >= config.IDLE_TIMEOUT:

                expired_flows.append(flow)

                del self.flows[key]

                self.fin_seen.pop(key, None)

        return expired_flows

    def check_active_timeouts(self, current_time):

        expired_flows = []

        for key, flow in list(self.flows.items()):

            if not flow.timestamps:
                continue

            first_packet_time = flow.timestamps[0]

            flow_duration = current_time - first_packet_time

            if flow_duration >= config.ACTIVE_TIMEOUT:

                expired_flows.append(flow)

                del self.flows[key]

                self.fin_seen.pop(key, None)

        return expired_flows