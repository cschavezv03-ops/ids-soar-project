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


    forward_packets: int = 0
    forward_bytes: int = 0
    backward_packets: int = 0
    backward_bytes: int = 0
    timestamps: list = field(default_factory=list)
    timestamps_forward: list = field(default_factory=list)
    timestamps_backward: list = field(default_factory=list)
    duration: float = 0.0
    packet_sizes_forward: list = field(default_factory=list)
    packet_sizes_backward: list = field(default_factory=list)
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


    #Para el ritmo temporal

    def calculate_duration(self):
        if len(self.timestamps) < 2:
            return 0.0

        return self.timestamps[-1] - self.timestamps[0]


    def calculate_iat(self):
        if len(self.timestamps) < 2:
            return []

        iat = []

        for i in range(1, len(self.timestamps)):
            iat.append(self.timestamps[i] - self. timestamps[i - 1])

        return iat

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

    def calculate_iat_forward(self):

        if len(self.timestamps_forward) < 2:
            return []

        iat = []

        for i in range(1, len(self.timestamps_forward)):
            iat.append(
                self.timestamps_forward[i] - self.timestamps_forward[i - 1]
            )

        return iat

    def calculate_iat_forward_mean(self):

        iat = self.calculate_iat_forward()

        if not iat:
            return 0.0

        return sum(iat) / len(iat)

    def calculate_iat_backward(self):

        if len(self.timestamps_backward) < 2:
            return []

        iat = []

        for i in range(1, len(self.timestamps_backward)):
            iat.append(
                self.timestamps_backward[i] - self.timestamps_backward[i - 1]
            )

        return iat

    def calculate_iat_backward_mean(self):
        
        iat = self.calculate_iat_backward()

        if not iat:
            return 0.0

        return sum(iat) / len(iat)

    def calculate_packets_per_second(self):
        duration = self.calculate_duration()

        if duration <= 0:
            return 0.0

        return self.packet_count / duration 

#Para los tamanios de los paquetes
    
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

    #Relacion bytes bajada/subida

    def calculate_byte_ratio(self):

        if self.forward_bytes == 0:
            return 0.0

        return self.backward_bytes / self.forward_bytes

    def calculate_mean_packet_size(self):
        if self.packet_count == 0:
            return 0.0

        return self.total_bytes / self.packet_count

    def calculate_bytes_per_second(self):
        duration = self.calculate_duration()

        if duration <= 0:
            return 0.0

        return self.total_bytes / duration

    

    def add_packet(self, src_ip, src_port, dst_ip, dst_port, packet_size, timestamps, tcp_flags = None):
        self.packet_count += 1
        self.total_bytes += packet_size

        self.timestamps.append(timestamps)   

        if self.is_forward(src_ip, src_port, dst_ip, dst_port):
            self.forward_packets += 1
            self.forward_bytes += packet_size
            self.timestamps_forward.append(timestamps)
            self.packet_sizes_forward.append(packet_size)
        else:
            self.backward_packets += 1
            self.backward_bytes += packet_size
            self.timestamps_backward.append(timestamps)
            self.packet_sizes_backward.append(packet_size)

#banderas tcp

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

    def get_features(self):
        return [
            # 1-5: duración y volumen
            self.calculate_duration(),
            self.forward_packets,
            self.backward_packets,
            self.forward_bytes,
            self.backward_bytes,

            # 6-11: tamaños de paquetes
            self.calculate_forward_packet_size_mean(),
            self.calculate_forward_packet_size_std(),
            self.calculate_forward_packet_size_max(),
            self.calculate_backward_packet_size_mean(),
            self.calculate_backward_packet_size_std(),
            self.calculate_backward_packet_size_max(),

            # 12-16: ritmo temporal
            self.calculate_iat_mean(),
            self.calculate_iat_std(),
            self.calculate_iat_forward_mean(),
            self.calculate_iat_backward_mean(),
            self.calculate_packets_per_second(),

            # 17-21: TCP flags
            self.syn_count,
            self.ack_count,
            self.fin_count,
            self.rst_count,
            self.psh_count,

            # 22-24: simetría y tasas
            self.calculate_byte_ratio(),
            self.calculate_mean_packet_size(),
            self.calculate_bytes_per_second(),
        ]