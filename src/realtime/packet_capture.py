from scapy.all import sniff, IP
from scapy.config import conf


def extract_packet(packet):

    try:
        if packet.haslayer(IP):

            ip = packet[IP]

            return {
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "proto": ip.proto,
                "packet_size": len(packet)
            }

    except:
        return None

    return None


def start_capture(callback):

    def process(packet):

        data = extract_packet(packet)

        if data:
            callback(data)

    print("Starting packet capture...")

    sniff(
        prn=process,
        store=False,
        filter="ip",
        iface=conf.iface
    )