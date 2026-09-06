import argparse
import os
import random
import time


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="generate_portscan_pcap")
    p.add_argument("--out", required=True, help="Output PCAP path")
    p.add_argument("--src", default="192.168.100.50", help="Source IP")
    p.add_argument("--dst", default="192.168.100.10", help="Destination IP")
    p.add_argument("--ports", default="22,23,80,443,445,3389,8080,8443,5900,135,139", help="Comma-separated ports")
    p.add_argument("--repeat", type=int, default=5, help="Repeat the port list N times")
    p.add_argument("--pps", type=float, default=50.0, help="Packets per second")
    return p


def main() -> int:
    args = _build_parser().parse_args()
    out_path = str(args.out)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

    try:
        from scapy.layers.inet import IP, TCP
        from scapy.utils import wrpcap
    except Exception as exc:
        raise RuntimeError("scapy is required. Install: pip install scapy") from exc

    ports = []
    for part in str(args.ports).split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ports.append(int(part))
        except Exception:
            continue
    if not ports:
        ports = [22, 80, 443, 445, 3389]

    seq = ports * max(1, int(args.repeat))
    random.shuffle(seq)

    pps = float(args.pps)
    pps = max(1.0, min(pps, 5000.0))

    base_t = time.time()
    pkts = []
    for i, dport in enumerate(seq):
        sport = random.randint(1024, 65535)
        pkt = IP(src=str(args.src), dst=str(args.dst)) / TCP(sport=sport, dport=int(dport), flags="S")
        pkt.time = float(base_t + (i / pps))
        pkts.append(pkt)

    wrpcap(out_path, pkts)
    print(f"WROTE {len(pkts)} packets -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

