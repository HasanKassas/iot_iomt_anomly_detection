import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


FlowKey = Tuple[str, str, int, int, int]


@dataclass
class LiveFlow:
    key: FlowKey
    started_at: float
    last_seen: float
    packets: List[Dict[str, Any]]
    packet_count: int = 0
    byte_count: int = 0
    forward_packet_count: int = 0
    backward_packet_count: int = 0
    forward_bytes: int = 0
    backward_bytes: int = 0
    tcp_syn_count: int = 0
    tcp_ack_count: int = 0
    tcp_fin_count: int = 0
    tcp_rst_count: int = 0
    completed_reason: str = ""


class LiveFlowBuilder:
    def __init__(
        self,
        flow_timeout_seconds: float = 15.0,
        max_packets_per_flow: int = 2000,
        max_active_flows: int = 50000,
    ):
        self.flow_timeout_seconds = float(flow_timeout_seconds)
        self.max_packets_per_flow = int(max_packets_per_flow)
        self.max_active_flows = int(max_active_flows)
        self._flows: Dict[FlowKey, LiveFlow] = {}
        self.dropped_flows = 0
        self.flows_created = 0
        self.flows_updated = 0
        self.flows_completed_timeout = 0
        self.flows_completed_maxpkts = 0
        self.flows_force_completed = 0
        self.flows_syn_only_completed = 0
        self.flows_evicted = 0

    def _flow_key(self, pkt: Dict[str, Any]) -> Optional[FlowKey]:
        try:
            src_ip = str(pkt.get("src_ip", "")).strip()
            dst_ip = str(pkt.get("dst_ip", "")).strip()
            src_port = int(pkt.get("src_port", 0) or 0)
            dst_port = int(pkt.get("dst_port", 0) or 0)
            proto = int(pkt.get("proto", 0) or 0)
            if not src_ip or not dst_ip:
                return None
            return (src_ip, dst_ip, src_port, dst_port, proto)
        except Exception:
            return None

    def _evict_if_needed(self) -> None:
        max_active = max(1, int(self.max_active_flows))
        if len(self._flows) <= max_active:
            return
        while len(self._flows) > max_active:
            oldest_key = None
            oldest_ts = None
            for k, f in self._flows.items():
                if oldest_ts is None or float(f.last_seen) < float(oldest_ts):
                    oldest_ts = float(f.last_seen)
                    oldest_key = k
            if oldest_key is None:
                break
            f = self._flows.pop(oldest_key, None)
            if f is not None:
                f.completed_reason = "evicted_max_active"
            self.dropped_flows += 1
            self.flows_evicted += 1

    def _update_counters(self, flow: LiveFlow, pkt: Dict[str, Any], direction: str) -> None:
        size = 0
        try:
            size = int(pkt.get("packet_size", 0) or 0)
        except Exception:
            size = 0
        size = max(0, size)

        flow.packet_count = int(flow.packet_count) + 1
        flow.byte_count = int(flow.byte_count) + size
        if direction == "fwd":
            flow.forward_packet_count = int(flow.forward_packet_count) + 1
            flow.forward_bytes = int(flow.forward_bytes) + size
        else:
            flow.backward_packet_count = int(flow.backward_packet_count) + 1
            flow.backward_bytes = int(flow.backward_bytes) + size

        proto = 0
        try:
            proto = int(pkt.get("proto", 0) or 0)
        except Exception:
            proto = 0
        if proto == 6:
            flags = str(pkt.get("tcp_flags", "") or "")
            if "S" in flags:
                flow.tcp_syn_count = int(flow.tcp_syn_count) + 1
            if "A" in flags:
                flow.tcp_ack_count = int(flow.tcp_ack_count) + 1
            if "F" in flags:
                flow.tcp_fin_count = int(flow.tcp_fin_count) + 1
            if "R" in flags:
                flow.tcp_rst_count = int(flow.tcp_rst_count) + 1

    def add_packet(self, pkt: Dict[str, Any], now: Optional[float] = None) -> List[LiveFlow]:
        now_ts = float(now if now is not None else time.time())
        key = self._flow_key(pkt)
        if key is None:
            return self.flush_expired(now_ts)

        rev = (key[1], key[0], key[3], key[2], key[4])
        direction = "fwd"

        flow = self._flows.get(key)
        if flow is None:
            flow = self._flows.get(rev)
            if flow is not None:
                key = rev
                direction = "bwd"

        if flow is None:
            flow = LiveFlow(key=key, started_at=now_ts, last_seen=now_ts, packets=[])
            self._flows[key] = flow
            self.flows_created += 1
        else:
            self.flows_updated += 1

        pkt2 = dict(pkt)
        pkt2.setdefault("timestamp", pkt2.get("timestamp_epoch", now_ts))
        pkt2.setdefault("timestamp_epoch", now_ts)
        pkt2["direction"] = direction
        flow.packets.append(pkt2)
        self._update_counters(flow, pkt2, direction)
        flow.last_seen = now_ts

        completed: List[LiveFlow] = []
        if len(flow.packets) >= self.max_packets_per_flow:
            flow.completed_reason = "max_packets_per_flow"
            completed.append(flow)
            self._flows.pop(flow.key, None)
            self.flows_completed_maxpkts += 1

        self._evict_if_needed()
        completed.extend(self.flush_expired(now_ts))
        return completed

    def flush_expired(self, now: Optional[float] = None) -> List[LiveFlow]:
        now_ts = float(now if now is not None else time.time())
        expired: List[LiveFlow] = []
        for k, f in list(self._flows.items()):
            if now_ts - float(f.last_seen) >= self.flow_timeout_seconds:
                f.completed_reason = "timeout"
                expired.append(f)
                self._flows.pop(k, None)
                self.flows_completed_timeout += 1
        return expired

    def force_complete_syn(self, min_syn: int = 1) -> List[LiveFlow]:
        min_syn = max(1, int(min_syn))
        out: List[LiveFlow] = []
        for k, f in list(self._flows.items()):
            try:
                proto = int(f.key[4] or 0)
            except Exception:
                proto = 0
            if proto != 6:
                continue
            syn = int(getattr(f, "tcp_syn_count", 0) or 0)
            ack = int(getattr(f, "tcp_ack_count", 0) or 0)
            if syn >= min_syn and ack == 0:
                f.completed_reason = "force_complete_syn"
                out.append(f)
                self._flows.pop(k, None)
                self.flows_force_completed += 1
                self.flows_syn_only_completed += 1
        return out

    def stats(self) -> Dict[str, int]:
        return {
            "active_flows": int(len(self._flows)),
            "flows_created": int(self.flows_created),
            "flows_updated": int(self.flows_updated),
            "flows_completed_timeout": int(self.flows_completed_timeout),
            "flows_completed_maxpkts": int(self.flows_completed_maxpkts),
            "flows_force_completed": int(self.flows_force_completed),
            "flows_syn_only_completed": int(self.flows_syn_only_completed),
            "flows_evicted": int(self.flows_evicted),
            "dropped_flows": int(self.dropped_flows),
        }

    def active_flows(self) -> int:
        return int(len(self._flows))
