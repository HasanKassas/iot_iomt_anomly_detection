import os
import queue
import signal
import threading
import time
import traceback
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class LiveMonitorConfig:
    interface: Optional[str] = None
    bpf_filter: Optional[str] = None
    pcap_path: Optional[str] = None
    replay_speed: float = 1.0
    replay_loop: bool = False
    replay_max_sleep_s: float = 2.0
    queue_maxsize: int = 50000
    sniff_timeout_s: float = 1.0


class LivePacketMonitor:
    def __init__(self, config: LiveMonitorConfig):
        self.config = config
        self.q: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=int(config.queue_maxsize))
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.dropped_packets = 0
        self.parse_errors = 0
        self.debug = os.getenv("DEBUG_LIVE", "0") == "1"

    def stop(self) -> None:
        self._stop.set()
        try:
            if self._thread is not None:
                self._thread.join(timeout=2.0)
        except Exception:
            return

    def _put(self, pkt: Dict[str, Any]) -> None:
        try:
            self.q.put_nowait(pkt)
        except Exception:
            self.dropped_packets += 1

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def get_batch(self, max_items: int = 256, timeout_s: float = 0.25) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        max_items = int(max_items) if max_items is not None else 256
        max_items = max(1, min(max_items, 10000))
        timeout_s = float(timeout_s) if timeout_s is not None else 0.25
        timeout_s = max(0.0, min(timeout_s, 5.0))

        try:
            first = self.q.get(timeout=timeout_s)
        except Exception:
            return out

        out.append(first)
        while len(out) < max_items:
            try:
                out.append(self.q.get_nowait())
            except Exception:
                break
        return out

    def _run(self) -> None:
        if self.config.pcap_path:
            self._run_replay(self.config.pcap_path)
            return
        self._run_sniff()

    def _run_sniff(self) -> None:
        try:
            from scapy.all import sniff
            from scapy.layers.inet import IP, TCP, UDP
        except Exception as exc:
            raise RuntimeError("scapy is required for live sniffing. Install: pip install scapy") from exc

        def handle(pkt):
            if self._stop.is_set():
                return
            try:
                if IP not in pkt:
                    return
                ip = pkt[IP]
                proto = int(ip.proto or 0)
                src_ip = str(ip.src)
                dst_ip = str(ip.dst)
                ttl = int(getattr(ip, "ttl", 0) or 0)
                ip_id = int(getattr(ip, "id", 0) or 0)
                ip_frag_offset = int(getattr(ip, "frag", 0) or 0)
                ip_mf = 0
                try:
                    ip_mf = 1 if bool(getattr(getattr(ip, "flags", None), "MF", False)) else 0
                except Exception:
                    ip_mf = 0
                src_port = 0
                dst_port = 0
                flags = ""
                if TCP in pkt:
                    tcp = pkt[TCP]
                    src_port = int(tcp.sport or 0)
                    dst_port = int(tcp.dport or 0)
                    flags = str(getattr(tcp, "flags", "") or "")
                    proto = 6
                elif UDP in pkt:
                    udp = pkt[UDP]
                    src_port = int(udp.sport or 0)
                    dst_port = int(udp.dport or 0)
                    proto = 17
                size = int(len(pkt))
                ts = float(getattr(pkt, "time", time.time()))
                self._put(
                    {
                        "timestamp": ts,
                        "timestamp_epoch": ts,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "proto": proto,
                        "packet_size": size,
                        "ttl": ttl,
                        "tcp_flags": flags,
                        "ip_id": ip_id,
                        "ip_frag_offset": ip_frag_offset,
                        "ip_mf": ip_mf,
                    }
                )
            except Exception:
                self.parse_errors += 1
                if self.debug:
                    try:
                        print("LIVE_MONITOR parse_error:", traceback.format_exc())
                    except Exception:
                        pass
                return

        sniff_timeout_s = float(self.config.sniff_timeout_s) if self.config.sniff_timeout_s else 1.0
        sniff_timeout_s = max(0.2, min(sniff_timeout_s, 5.0))
        while not self._stop.is_set():
            sniff(
                iface=self.config.interface,
                filter=self.config.bpf_filter,
                prn=handle,
                store=False,
                timeout=sniff_timeout_s,
            )

    def _run_replay(self, pcap_path: str) -> None:
        try:
            from scapy.utils import PcapReader
            from scapy.layers.inet import IP, TCP, UDP
        except Exception as exc:
            raise RuntimeError("scapy is required for pcap replay. Install: pip install scapy") from exc

        speed = float(self.config.replay_speed) if self.config.replay_speed is not None else 1.0
        max_sleep = float(self.config.replay_max_sleep_s) if self.config.replay_max_sleep_s is not None else 2.0
        loop = bool(self.config.replay_loop)

        def _sleep(delay_s: float) -> None:
            if delay_s <= 0:
                return
            if max_sleep > 0:
                time.sleep(min(delay_s, max_sleep))
            else:
                time.sleep(delay_s)

        while not self._stop.is_set():
            last_ts = None
            with PcapReader(pcap_path) as pcap:
                for pkt in pcap:
                    if self._stop.is_set():
                        break
                    try:
                        if IP not in pkt:
                            continue
                        ts = float(getattr(pkt, "time", time.time()))
                        if last_ts is not None:
                            if speed <= 0:
                                delay = 0.0
                            else:
                                delay = max(0.0, (ts - last_ts) / float(speed))
                            _sleep(delay)
                        last_ts = ts

                        ip = pkt[IP]
                        proto = int(ip.proto or 0)
                        src_ip = str(ip.src)
                        dst_ip = str(ip.dst)
                        ttl = int(getattr(ip, "ttl", 0) or 0)
                        ip_id = int(getattr(ip, "id", 0) or 0)
                        ip_frag_offset = int(getattr(ip, "frag", 0) or 0)
                        ip_mf = 0
                        try:
                            ip_mf = 1 if bool(getattr(getattr(ip, "flags", None), "MF", False)) else 0
                        except Exception:
                            ip_mf = 0
                        src_port = 0
                        dst_port = 0
                        flags = ""
                        if TCP in pkt:
                            tcp = pkt[TCP]
                            src_port = int(tcp.sport or 0)
                            dst_port = int(tcp.dport or 0)
                            flags = str(getattr(tcp, "flags", "") or "")
                            proto = 6
                        elif UDP in pkt:
                            udp = pkt[UDP]
                            src_port = int(udp.sport or 0)
                            dst_port = int(udp.dport or 0)
                            proto = 17

                        size = int(len(pkt))
                        self._put(
                            {
                                "timestamp": ts,
                                "timestamp_epoch": ts,
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "src_port": src_port,
                                "dst_port": dst_port,
                                "proto": proto,
                                "packet_size": size,
                                "ttl": ttl,
                                "tcp_flags": flags,
                                "ip_id": ip_id,
                                "ip_frag_offset": ip_frag_offset,
                                "ip_mf": ip_mf,
                            }
                        )
                    except Exception:
                        self.parse_errors += 1
                        if self.debug:
                            try:
                                print("LIVE_MONITOR replay_parse_error:", traceback.format_exc())
                            except Exception:
                                pass
                        continue
            if not loop:
                break


def install_signal_handlers(monitor: LivePacketMonitor) -> None:
    def handler(_sig, _frame):
        monitor.stop()

    try:
        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)
    except Exception:
        return
