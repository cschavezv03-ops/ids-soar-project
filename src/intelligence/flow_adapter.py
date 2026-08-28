from typing import Any

class FlowAdapter:

    def __init__(self, flow):
        self.flow  = flow


    def get_data(self) -> dict[str, Any]:
        flow = self.flow

        return {
            "flow_duration": flow.calculate_duration(),

            "tot_fwd_pkts": flow.forward_packets,
            "tot_bwd_pkts": flow.backward_packets,

            "totlen_fwd_pkts": flow.forward_bytes,
            "totlen_bwd_pkts": flow.backward_bytes,

            "fwd_pkt_len_min": flow.calculate_forward_packet_size_min(),
            "fwd_pkt_len_mean": flow.calculate_forward_packet_size_mean(),
            "fwd_pkt_len_std": flow.calculate_forward_packet_size_std(),
            "fwd_pkt_len_max": flow.calculate_forward_packet_size_max(),

            "bwd_pkt_len_min": flow.calculate_backward_packet_size_min(),
            "bwd_pkt_len_mean": flow.calculate_backward_packet_size_mean(),
            "bwd_pkt_len_std": flow.calculate_backward_packet_size_std(),
            "bwd_pkt_len_max": flow.calculate_backward_packet_size_max(),

            "pkt_len_mean": flow.calculate_packet_size_mean(),
            "pkt_len_std": flow.calculate_packet_size_std(),

            "flow_iat_mean": flow.calculate_iat_mean(),
            "flow_iat_std": flow.calculate_iat_std(),
            "flow_iat_max": flow.calculate_iat_max(),
            "flow_iat_min": flow.calculate_iat_min(),

            "fwd_iat_mean": flow.calculate_iat_forward_mean(),
            "bwd_iat_mean": flow.calculate_iat_backward_mean(),

            "flow_pkts_s": flow.calculate_packets_per_second(),
            "flow_byts_s": flow.calculate_bytes_per_second(),

            "fwd_act_data_pkts": flow.fwd_act_data_pkts,
        }