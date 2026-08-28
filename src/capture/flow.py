from dataclasses import dataclass, field


@dataclass

#clase flow que representa una conversacion
class Flow:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str

    packet_count: int = 0
    total_bytes: int = 0

    #forward direction
    forward_packets: int = 0
    forward_bytes: int = 0

    #backward direction
    backward_packets: int = 0
    backward_bytes: int = 0

    #timestamps
    timestamps: list = field(default_factory=list)
    timestamps_forward: list = field(default_factory=list)
    timestamps_backward: list = field(default_factory=list)

    #size of payload
    packet_sizes: list = field(default_factory=list)
    packet_sizes_forward: list = field(default_factory=list)
    packet_sizes_backward: list = field(default_factory=list)

    #size of package forward that have data

    fwd_act_data_pkts: int = 0

    #tcp flags only for the close logic
    
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0


 

#Devuelve la 5 tupla - la informacion necesaria para saber a que conversacion pertenece cada paquete 

    def key(self):
        return(
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port,
            self.protocol,
        )

    
#Para cada paquete
    def is_forward(self, src_ip, src_port, dst_ip, dst_port):
        return (
            src_ip == self.src_ip
            and src_port == self.src_port
            and dst_ip == self.dst_ip
            and dst_port == self.dst_port
        )

    
    #for the duration

    def calculate_duration(self):
        if len(self.timestamps) < 2:
            return 0.0

        return self.timestamps[-1] - self.timestamps[0]

    #IAT

    def calculate_iat(self):
        
        if len(self.timestamps) < 2:
            return []

        return [
            self.timestamps[i] - self. timestamps[i - 1]
            for i in range(1, len(self.timestamps))    
        ]

    def calculate_iat_mean(self):

        iat = self. calculate_iat()

        if not iat:
            return 0.0

        return sum(iat) / len (iat)

    def calculate_iat_std(self):
        
        iat = self.calculate_iat()

        if len(iat) < 2:
            return 0.0

        mean = sum(iat) / len(iat)

        variance = sum((x - mean) ** 2 for x in iat) / len(iat)

        return variance ** 0.5

    def calculate_iat_max(self):

        iat = self.calculate_iat()

        if not iat:
            return 0.0

        return max(iat)


    def calculate_iat_min(self):

        iat = self.calculate_iat()

        if not iat:
            return 0.0

        return min(iat)

    #iat forward
        
    def calculate_iat_forward(self):

        if len(self.timestamps_forward) < 2:
            return []
        
        return [
            self.timestamps_forward[i] - self. timestamps_forward[i - 1]
            for i in range(1, len(self.timestamps_forward))    
        ]


    def calculate_iat_forward_mean(self):

        iat = self.calculate_iat_forward()

        if not iat:
            return 0.0

        return sum(iat) / len(iat)

    #iat backward

    def calculate_iat_backward(self):

        if len(self.timestamps_backward) < 2:
            return []
        
        return [
            self.timestamps_backward[i] - self. timestamps_backward[i - 1]
            for i in range(1, len(self.timestamps_backward))    
        ]

    def calculate_iat_backward_mean(self):
        
        iat = self.calculate_iat_backward()

        if not iat:
            return 0.0

        return sum(iat) / len(iat)

    #packet rate

    def calculate_packets_per_second(self):
        duration = self.calculate_duration()

        if duration <= 0:
            return 0.0

        return self.packet_count / duration 

    #forward packet length

    def calculate_forward_packet_size_min(self):

        if not self.packet_sizes_forward:
            return 0.0

        return min(self.packet_sizes_forward)
    
    def calculate_forward_packet_size_mean(self):

        if not self.packet_sizes_forward:
            return 0.0

        return sum(self.packet_sizes_forward) / len(self.packet_sizes_forward)

    def calculate_forward_packet_size_std(self):

        if len(self.packet_sizes_forward) < 2:
            return 0.0

        mean = self.calculate_forward_packet_size_mean()

        variance = sum((x - mean) ** 2 for x in self.packet_sizes_forward) / len (self.packet_sizes_forward)

        return variance ** 0.5

    def calculate_forward_packet_size_max(self):

        if not self.packet_sizes_forward:
            return 0.0

        return max(self.packet_sizes_forward)

    #backward packet length

    def calculate_backward_packet_size_min(self):

        if not self.packet_sizes_backward:
            return 0.0

        return min(self.packet_sizes_backward)

    def calculate_backward_packet_size_mean(self):

        if not self.packet_sizes_backward:
            return 0.0

        return sum(self.packet_sizes_backward) / len(self.packet_sizes_backward)

    def calculate_backward_packet_size_std(self):

        if len(self.packet_sizes_backward) < 2:
            return 0.0

        mean = self.calculate_backward_packet_size_mean()

        variance = sum((x - mean) ** 2 for x in self.packet_sizes_backward) / len (self.packet_sizes_backward)

        return variance ** 0.5

    def calculate_backward_packet_size_max(self):

        if not self.packet_sizes_backward:
            return 0.0

        return max(self.packet_sizes_backward)

    #all packet length

    def calculate_packet_size_mean(self):

        if not self.packet_sizes:
            return 0.0

        return sum(self.packet_sizes) / len(self.packet_sizes)

    def calculate_packet_size_std(self):

        if len(self.packet_sizes) < 2:
            return 0.0

        mean = self.calculate_packet_size_mean()

        variance = sum((x - mean) ** 2 for x in self.packet_sizes) / len (self.packet_sizes)

        return variance ** 0.5

    #bytes per second

    def calculate_bytes_per_second(self):
        duration = self.calculate_duration()

        if duration <= 0:
            return 0.0

        return self.total_bytes / duration

    

    def add_packet(self, src_ip, src_port, dst_ip, dst_port, packet_size, timestamp, tcp_flags =None, payload_size =None):

        if payload_size is None:
            payload_size = packet_size

        length = payload_size

        self.packet_count += 1
        self.total_bytes += length

        self.timestamps.append(timestamp)
        self.packet_sizes.append(length)

        if self.is_forward(
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        ):

            self.forward_packets += 1
            self.forward_bytes += length

            self.timestamps_forward.append(timestamp)
            self.packet_sizes_forward.append(length)

            if payload_size > 0:
                self.fwd_act_data_pkts += 1

        else:

            self.backward_packets += 1
            self.backward_bytes += length

            self.timestamps_backward.append(timestamp)
            self.packet_sizes_backward.append(length)

        #tcp flags only for logic

        if tcp_flags and "S" in tcp_flags:
            self.syn_count += 1

        if tcp_flags and "A" in tcp_flags:
            self.ack_count += 1

        if tcp_flags and "F" in tcp_flags:
            self.fin_count += 1

        if tcp_flags and "R" in tcp_flags:
            self.rst_count += 1

        if tcp_flags and "P" in tcp_flags:
            self.psh_count += 1

        