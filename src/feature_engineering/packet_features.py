from typing import Dict, Any, List
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from .safety import (
    nan_to_num,
    safe_div,
    safe_float,
    safe_int,
)


class PacketFeatures:
    """Extracts packet-level features."""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        logger.info("PacketFeatures initialized")

    def extract(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from a single packet or flow-record-like dict."""
        features: Dict[str, Any] = {}
        
        if "packet_size" in packet:
            features["packet_size"] = safe_int(packet.get("packet_size"), default=0)
        elif "orig_ip_bytes" in packet or "resp_ip_bytes" in packet:
            features["packet_size"] = safe_int(packet.get("orig_ip_bytes"), default=0) + safe_int(packet.get("resp_ip_bytes"), default=0)
        elif "orig_bytes" in packet or "resp_bytes" in packet:
            features["packet_size"] = safe_int(packet.get("orig_bytes"), default=0) + safe_int(packet.get("resp_bytes"), default=0)
        else:
            features["packet_size"] = 0
        
        if "protocol" in packet:
            features["protocol"] = safe_int(packet.get("protocol"), default=0)
        elif "proto" in packet:
            features["protocol"] = safe_int(packet.get("proto"), default=0)
        
        if "ttl" in packet:
            features["ttl"] = safe_int(packet.get("ttl"), default=0)

        duration = safe_float(packet.get("duration"), default=0.0)
        features["flow_duration"] = nan_to_num(duration)

        orig_pkts = safe_int(packet.get("orig_pkts"), default=0)
        resp_pkts = safe_int(packet.get("resp_pkts"), default=0)
        total_pkts = orig_pkts + resp_pkts
        features["total_packets"] = total_pkts

        orig_bytes = safe_int(packet.get("orig_bytes"), default=0)
        resp_bytes = safe_int(packet.get("resp_bytes"), default=0)
        total_bytes = orig_bytes + resp_bytes
        features["total_bytes"] = total_bytes

        features["packets_per_second"] = nan_to_num(safe_div(float(total_pkts), float(duration), default=0.0))
        features["bytes_per_second"] = nan_to_num(safe_div(float(total_bytes), float(duration), default=0.0))
        features["avg_packet_size"] = nan_to_num(safe_div(float(total_bytes), float(total_pkts), default=0.0))
        features["min_packet_size"] = features["packet_size"]
        features["max_packet_size"] = features["packet_size"]
        features["packet_size_std"] = 0.0

        features["forward_packet_count"] = orig_pkts
        features["backward_packet_count"] = resp_pkts
        features["forward_bytes"] = orig_bytes
        features["backward_bytes"] = resp_bytes
        features["packet_direction_ratio"] = nan_to_num(safe_div(float(orig_pkts), float(resp_pkts), default=float(orig_pkts)))
        features["flow_symmetry_ratio"] = nan_to_num(safe_div(float(orig_bytes), float(resp_bytes), default=float(orig_bytes)))

        src_port = safe_int(packet.get("src_port"), default=safe_int(packet.get("id.orig_p"), default=0))
        dst_port = safe_int(packet.get("dst_port"), default=safe_int(packet.get("id.resp_p"), default=0))
        features["unique_src_ports"] = 1 if src_port > 0 else 0
        features["unique_dst_ports"] = 1 if dst_port > 0 else 0

        ttl = safe_int(packet.get("ttl"), default=0)
        features["ttl_mean"] = float(ttl) if ttl > 0 else 0.0
        features["ttl_std"] = 0.0

        features["ip_fragment_count"] = safe_int(packet.get("ip_fragment_count"), default=0)

        history = packet.get("history")
        history_s = str(history) if history is not None else ""
        conn_state = packet.get("conn_state")
        conn_state_s = str(conn_state) if conn_state is not None else ""
        features.update(_tcp_flags_from_history(history_s, conn_state_s))

        features["retransmission_estimate"] = 0.0

        features["packet_size_entropy"] = 0.0
        features["timing_entropy"] = 0.0
        features["burstiness_score"] = 0.0
        features["packet_rate_variance"] = 0.0
        features["byte_rate_variance"] = 0.0
        features["payload_variability_score"] = 0.0
        features["inter_arrival_mean"] = 0.0
        features["inter_arrival_std"] = 0.0
        features["flow_idle_time"] = 0.0
        features["flow_active_time"] = nan_to_num(duration)

        features["packet_size_randomization_score"] = 0.0
        features["timing_jitter_score"] = 0.0
        features["fragmentation_anomaly_score"] = 0.0
        features["ttl_randomization_score"] = 0.0
        features["tos_randomization_score"] = 0.0
        features["window_randomization_score"] = 0.0
        features["header_consistency_score"] = 1.0
        features["timing_irregularity_score"] = 0.0
        features["flow_uniformity_score"] = 1.0

        obf = packet.get("obfuscation")
        if isinstance(obf, dict):
            if obf.get("size_randomized", False):
                original = safe_int(obf.get("original_size"), default=0)
                current = safe_int(packet.get("packet_size"), default=0)
                delta_ratio = safe_div(float(abs(current - original)), float(original), default=1.0 if original == 0 else 0.0)
                features["packet_size_randomization_score"] = nan_to_num(delta_ratio, default=1.0)
                features["flow_uniformity_score"] = 0.0

            if obf.get("timing_jittered", False):
                jitter_ms = safe_float(obf.get("jitter_ms"), default=0.0)
                features["timing_jitter_score"] = nan_to_num(safe_div(float(jitter_ms), 100.0, default=1.0 if jitter_ms > 0 else 0.0))
                features["timing_irregularity_score"] = features["timing_jitter_score"]
                features["flow_uniformity_score"] = 0.0

            if obf.get("fragmented", False):
                total_frags = safe_int(obf.get("total_fragments"), default=1)
                features["fragmentation_anomaly_score"] = nan_to_num(safe_div(float(max(total_frags - 1, 0)), 4.0, default=1.0))
                features["ip_fragment_count"] = max(features.get("ip_fragment_count", 0), max(total_frags - 1, 0))
                features["flow_uniformity_score"] = 0.0

            if obf.get("ttl_randomized", False):
                features["ttl_randomization_score"] = 1.0
            if obf.get("tos_randomized", False):
                features["tos_randomization_score"] = 1.0
            if obf.get("window_randomized", False):
                features["window_randomization_score"] = 1.0

            header_flags = int(bool(obf.get("ttl_randomized", False))) + int(bool(obf.get("tos_randomized", False))) + int(bool(obf.get("window_randomized", False)))
            if header_flags > 0:
                features["header_consistency_score"] = 0.0
        
        return features

    def extract_batch(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract features from a list of packets."""
        return [self.extract(p) for p in packets]


def _tcp_flags_from_history(history: str, conn_state: str = "") -> Dict[str, Any]:
    h = history or ""
    if not h and conn_state:
        state = str(conn_state).strip().upper()
        h = state
    syn = h.count("S")
    ack = h.count("A")
    fin = h.count("F")
    rst = h.count("R")
    psh = h.count("P")
    urg = h.count("U")
    total = syn + ack + fin + rst + psh + urg
    return {
        "tcp_syn_count": syn,
        "tcp_ack_count": ack,
        "tcp_fin_count": fin,
        "tcp_rst_count": rst,
        "tcp_psh_count": psh,
        "tcp_urg_count": urg,
        "tcp_flag_total": total,
        "tcp_syn_ratio": nan_to_num(safe_div(float(syn), float(total), default=0.0)),
        "tcp_ack_ratio": nan_to_num(safe_div(float(ack), float(total), default=0.0)),
        "tcp_fin_ratio": nan_to_num(safe_div(float(fin), float(total), default=0.0)),
        "tcp_rst_ratio": nan_to_num(safe_div(float(rst), float(total), default=0.0)),
        "tcp_psh_ratio": nan_to_num(safe_div(float(psh), float(total), default=0.0)),
        "tcp_urg_ratio": nan_to_num(safe_div(float(urg), float(total), default=0.0)),
    }
