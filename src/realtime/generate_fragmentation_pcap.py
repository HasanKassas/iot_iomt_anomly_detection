import argparse
import os
import time


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="generate_fragmentation_pcap")
    p.add_argument("--out", required=True, help="Output PCAP path")
    p.add_argument("--src", default="192.168.100.50", help="Source IP")
    p.add_argument("--dst", default="192.168.100.10", help="Destination IP")
    p.add_argument("--dport", type=int, default=9999, help="Destination UDP port")
    p.add_argument("--payload-bytes", type=int, default=2400, help="Payload size")
    p.add_argument("--fragsize", type=int, default=200, help="Fragment size")
    p.add_argument("--pps", type=float, default=100.0, help="Fragments per second")
    p.add_argument("--bursts", type=int, default=5, help="Number of bursts")
    return p


def main() -> int:
    args = _build_parser().parse_args()
    out_path = str(args.out)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

    try:
        from scapy.layers.inet import IP, UDP
        from scapy.layers.inet import fragment
        from scapy.packet import Raw
        from scapy.utils import wrpcap
    except Exception as exc:
        raise RuntimeError("scapy is required. Install: pip install scapy") from exc

    pps = float(args.pps)
    pps = max(1.0, min(pps, 5000.0))

    base_t = time.time()
    pkts = []
    tick = 0
    for b in range(int(args.bursts)):
        pkt = IP(src=str(args.src), dst=str(args.dst)) / UDP(dport=int(args.dport)) / Raw(b"X" * int(args.payload_bytes))
        frags = fragment(pkt, fragsize=int(args.fragsize))
        for f in frags:
            f.time = float(base_t + (tick / pps))
            pkts.append(f)
            tick += 1
        base_t += 0.25

    wrpcap(out_path, pkts)
    print(f"WROTE {len(pkts)} fragments -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
