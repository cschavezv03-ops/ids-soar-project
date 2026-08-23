from dataclasses import dataclass
from types import Optional

@dataclass

#clase flow que representa una conversacion
class Flow:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str

#Devuelve la 5 tupla - la informacion necesaria para saber a que conversacion pertenece cada paquete 

    def key(self):
        return(
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port,
            self.protocol,
        )