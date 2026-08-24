from pathlib import Path
import sys

from scapy.all import Ether, PcapReader, PcapWriter

ETHERNET_MIN_FRAME = 60


def pad_pcap(input_path: Path, output_path: Path):
    corrected = 0
    total = 0

    with PcapReader(str(input_path)) as reader, \
         PcapWriter(str(output_path), append=False, sync=True) as writer:

        for packet in reader:
            total += 1

            # Solo podemos corregir tramas Ethernet
            # y únicamente las que están por debajo del mínimo.
            if Ether in packet and len(packet) < ETHERNET_MIN_FRAME:
                padding_needed = ETHERNET_MIN_FRAME - len(packet)

                packet = packet.copy()
                packet = packet / (b"\x00" * padding_needed)

                corrected += 1

            writer.write(packet)

    print(f"Input:     {input_path}")
    print(f"Output:    {output_path}")
    print(f"Packets:   {total}")
    print(f"Corrected: {corrected}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(
            "Uso: python3 scripts/pad_pcap.py "
            "<input.pcap> <output.pcap>"
        )

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    if not input_path.exists():
        sys.exit(f"No existe: {input_path}")

    pad_pcap(input_path, output_path)