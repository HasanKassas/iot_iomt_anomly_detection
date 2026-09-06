import argparse
import os
import time
from typing import Optional

from src.realtime.live_detection_engine import main as run_live


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="replay_attack_demo")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--pcap", default=None, help="Path to PCAP file")
    g.add_argument("--scenario", choices=["syn_scan", "portscan", "fragmentation", "jitter"], default=None, help="Generate a lab PCAP attack scenario")
    p.add_argument("--out", default=None, help="Output PCAP path when using --scenario (default: attacks/generated_<scenario>.pcap)")
    p.add_argument("--src", default="192.168.100.50", help="Attacker/source IP (scenario)")
    p.add_argument("--dst", default="192.168.100.10", help="Target/destination IP (scenario)")
    p.add_argument("--pps", type=float, default=200.0, help="Packets per second (scenario)")
    p.add_argument("--count", type=int, default=200, help="Packet count (jitter)")
    p.add_argument("--ports", default="22,23,80,443,445,3389,8080,8443,5900,135,139", help="Comma-separated ports (portscan)")
    p.add_argument("--start-port", type=int, default=1, help="Start port (syn_scan)")
    p.add_argument("--end-port", type=int, default=200, help="End port inclusive (syn_scan)")
    p.add_argument("--payload-bytes", type=int, default=2400, help="Payload size (fragmentation)")
    p.add_argument("--fragsize", type=int, default=200, help="Fragment size (fragmentation)")
    p.add_argument("--bursts", type=int, default=5, help="Number of bursts (fragmentation)")
    p.add_argument("--speed", type=float, default=1.0, help="Replay speed (1.0=real-time, >1 faster, 0=instant)")
    p.add_argument("--loop", action="store_true", help="Loop the PCAP forever")
    p.add_argument("--lab", action="store_true", help="Enable lab mode (better demo visibility)")
    p.add_argument("--api-url", default=None, help="Override IOMT_API_URL (default: http://localhost:3001)")
    return p


def _write_scenario_pcap(
    scenario: str,
    out_path: str,
    src: str,
    dst: str,
    pps: float,
    count: int,
    ports: str,
    start_port: int,
    end_port: int,
    payload_bytes: int,
    fragsize: int,
    bursts: int,
) -> str:
    try:
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.utils import wrpcap
    except Exception as exc:
        raise RuntimeError("scapy is required for scenario generation. Install: pip install scapy") from exc

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    pps = float(pps)
    pps = max(1.0, min(pps, 5000.0))
    base_t = time.time()

    if scenario == "syn_scan":
        import random

        ports_list = list(range(int(start_port), int(end_port) + 1))
        random.shuffle(ports_list)
        pkts = []
        for i, dport in enumerate(ports_list):
            sport = random.randint(1024, 65535)
            pkt = IP(src=str(src), dst=str(dst)) / TCP(sport=int(sport), dport=int(dport), flags="S")
            pkt.time = float(base_t + (i / pps))
            pkts.append(pkt)
        wrpcap(out_path, pkts)
        return out_path

    if scenario == "portscan":
        import random

        ports_list = []
        for part in str(ports).split(","):
            part = part.strip()
            if not part:
                continue
            try:
                ports_list.append(int(part))
            except Exception:
                continue
        if not ports_list:
            ports_list = [22, 80, 443, 445, 3389]
        seq = ports_list * 5
        random.shuffle(seq)
        pkts = []
        for i, dport in enumerate(seq):
            sport = random.randint(1024, 65535)
            pkt = IP(src=str(src), dst=str(dst)) / TCP(sport=int(sport), dport=int(dport), flags="S")
            pkt.time = float(base_t + (i / pps))
            pkts.append(pkt)
        wrpcap(out_path, pkts)
        return out_path

    if scenario == "fragmentation":
        try:
            from scapy.layers.inet import fragment
            from scapy.packet import Raw
        except Exception as exc:
            raise RuntimeError("scapy fragmentation helpers not available in this Scapy build") from exc
        pkts = []
        tick = 0
        for _ in range(max(1, int(bursts))):
            pkt = IP(src=str(src), dst=str(dst)) / UDP(dport=9999) / Raw(b"X" * int(payload_bytes))
            frags = fragment(pkt, fragsize=int(fragsize))
            for f in frags:
                f.time = float(base_t + (tick / pps))
                pkts.append(f)
                tick += 1
            base_t += 0.25
        wrpcap(out_path, pkts)
        return out_path

    if scenario == "jitter":
        try:
            from scapy.packet import Raw
        except Exception as exc:
            raise RuntimeError("scapy is required for jitter scenario") from exc
        n = max(10, int(count))
        base_t = time.time()
        pkts = []
        sport = 40000
        dport = 9999
        small = 0.001
        big = 0.05
        t = float(base_t)
        for i in range(n):
            t += (big if (i % 2 == 1) else small)
            pkt = IP(src=str(src), dst=str(dst)) / UDP(sport=int(sport), dport=int(dport)) / Raw(b"J" * 64)
            pkt.time = float(t)
            pkts.append(pkt)
        wrpcap(out_path, pkts)
        return out_path

    raise ValueError(f"unknown scenario: {scenario}")


def main() -> int:
    args = _build_parser().parse_args()

    if args.api_url:
        os.environ["IOMT_API_URL"] = str(args.api_url).rstrip("/")

    pcap_path: Optional[str] = None
    if args.scenario:
        os.environ.setdefault("LIVE_LAB_MODE", "1")
        os.environ.setdefault("LIVE_PUBLISH_THRESHOLD", "0.0")
        os.environ.setdefault("LIVE_MIN_PKTS", "1")
        os.environ.setdefault("LIVE_MIN_BYTES", "0")
        os.environ.setdefault("LIVE_CLEAR_HISTORY_ON_START", "1")
        out = str(args.out) if args.out else f"attacks/generated_{args.scenario}.pcap"
        pcap_path = _write_scenario_pcap(
            scenario=str(args.scenario),
            out_path=out,
            src=str(args.src),
            dst=str(args.dst),
            pps=float(args.pps),
            count=int(args.count),
            ports=str(args.ports),
            start_port=int(args.start_port),
            end_port=int(args.end_port),
            payload_bytes=int(args.payload_bytes),
            fragsize=int(args.fragsize),
            bursts=int(args.bursts),
        )
    else:
        pcap_path = str(args.pcap)

    os.environ["LIVE_MODE"] = "replay"
    os.environ["LIVE_REPLAY_PCAP"] = str(pcap_path)
    os.environ["LIVE_REPLAY_SPEED"] = str(float(args.speed))
    os.environ["LIVE_REPLAY_LOOP"] = "1" if bool(args.loop) else "0"
    os.environ.setdefault("LIVE_CLEAR_HISTORY_ON_START", "1")

    if args.lab:
        os.environ["LIVE_LAB_MODE"] = "1"
        if "LIVE_AUTOBLOCK" not in os.environ:
            os.environ["LIVE_AUTOBLOCK"] = "0"

    return int(run_live() or 0)


if __name__ == "__main__":
    raise SystemExit(main())
