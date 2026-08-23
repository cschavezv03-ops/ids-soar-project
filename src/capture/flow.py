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

    
    

    def add_packet(self, src_ip, src_port, dst_ip, dst_port, packet_size, timestamps):
        self.packet_count += 1
        self.total_bytes += packet_size

        self.timestamps.append(timestamps)   

        if self.is_forward(src_ip, src_port, dst_ip, dst_port):
            self.forward_packets += 1
            self.forward_bytes += packet_size
            self.timestamps_forward.append(timestamps)
        else:
            self.backward_packets += 1
            self.backward_bytes += packet_size
            self.timestamps_backward.append(timestamps)
    

        
