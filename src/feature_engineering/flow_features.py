from typing import Dict, Any, List, Optional, Tuple
import logging
import math

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from .safety import (
    nan_to_num,
    parse_timestamp,
    safe_div,
    safe_float,
    safe_int,
    shannon_entropy,
    mean,
    std,
    variance,
)


class FlowFeatures:
    """Extracts flow-level features from packet sequences."""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        logger.info("FlowFeatures initialized")

    def extract(self, flow_packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract features from a flow (list of packets)."""
        features: Dict[str, Any] = {}
        
        if not flow_packets:
            return features

        ts_list = [parse_timestamp(p.get("timestamp")) for p in flow_packets]
        ts_valid = [t for t in ts_list if t is not None]
        ts_valid_sorted = sorted(ts_valid)

        sizes = [safe_int(p.get("packet_size"), default=0) for p in flow_packets]
        sizes_f = [float(s) for s in sizes]

        features["flow_packet_count"] = len(flow_packets)
        features["flow_byte_count"] = int(sum(sizes))
        features["flow_avg_packet_size"] = nan_to_num(mean(sizes_f))
        features["flow_min_packet_size"] = float(min(sizes)) if sizes else 0.0
        features["flow_max_packet_size"] = float(max(sizes)) if sizes else 0.0
        features["flow_std_packet_size"] = nan_to_num(std(sizes_f))

        start_ts = ts_valid_sorted[0] if ts_valid_sorted else None
        end_ts = ts_valid_sorted[-1] if ts_valid_sorted else None
        duration = (end_ts - start_ts) if (start_ts is not None and end_ts is not None and end_ts >= start_ts) else 0.0

        features["flow_duration"] = nan_to_num(duration)
        features["total_packets"] = int(len(flow_packets))
        features["total_bytes"] = int(sum(sizes))
        features["packets_per_second"] = nan_to_num(safe_div(float(len(flow_packets)), float(duration), default=0.0))
        features["bytes_per_second"] = nan_to_num(safe_div(float(sum(sizes)), float(duration), default=0.0))
        features["avg_packet_size"] = features["flow_avg_packet_size"]
        features["min_packet_size"] = features["flow_min_packet_size"]
        features["max_packet_size"] = features["flow_max_packet_size"]
        features["packet_size_std"] = features["flow_std_packet_size"]

        inter_arrivals = []
        if len(ts_valid_sorted) >= 2:
            for a, b in zip(ts_valid_sorted[:-1], ts_valid_sorted[1:]):
                dt = b - a
                if dt >= 0 and math.isfinite(dt):
                    inter_arrivals.append(dt)
        features["inter_arrival_mean"] = nan_to_num(mean(inter_arrivals))
        features["inter_arrival_std"] = nan_to_num(std(inter_arrivals))

        src0 = flow_packets[0].get("src_ip")
        dst0 = flow_packets[0].get("dst_ip")

        fwd_count = 0
        bwd_count = 0
        fwd_bytes = 0
        bwd_bytes = 0
        src_ports = set()
        dst_ports = set()
        ttl_vals = []
        frag_count = 0
        history_chars = ""

        conn_state_chars = ""
        for p in flow_packets:
            s_ip = p.get("src_ip")
            d_ip = p.get("dst_ip")
            size = safe_int(p.get("packet_size"), default=0)
            if s_ip == src0 and d_ip == dst0:
                fwd_count += 1
                fwd_bytes += size
            elif s_ip == dst0 and d_ip == src0:
                bwd_count += 1
                bwd_bytes += size

            sp = safe_int(p.get("src_port"), default=0)
            dp = safe_int(p.get("dst_port"), default=0)
            if sp > 0:
                src_ports.add(sp)
            if dp > 0:
                dst_ports.add(dp)

            ttl = safe_int(p.get("ttl"), default=0)
            if ttl > 0:
                ttl_vals.append(float(ttl))

            frag_count += safe_int(p.get("ip_fragment_count"), default=0)

            h = p.get("history")
            if h is not None:
                history_chars += str(h)
            cs = p.get("conn_state")
            if cs is not None:
                conn_state_chars += str(cs)

        features["forward_packet_count"] = int(fwd_count)
        features["backward_packet_count"] = int(bwd_count)
        features["forward_bytes"] = int(fwd_bytes)
        features["backward_bytes"] = int(bwd_bytes)
        features["packet_direction_ratio"] = nan_to_num(safe_div(float(fwd_count), float(bwd_count), default=float(fwd_count)))
        features["flow_symmetry_ratio"] = nan_to_num(safe_div(float(fwd_bytes), float(bwd_bytes), default=float(fwd_bytes)))

        features["unique_dst_ports"] = int(len(dst_ports))
        features["unique_src_ports"] = int(len(src_ports))

        features["ttl_mean"] = nan_to_num(mean(ttl_vals))
        features["ttl_std"] = nan_to_num(std(ttl_vals))
        features["ip_fragment_count"] = int(frag_count)

        syn, ack, fin, rst, psh, urg, total_flags = _tcp_flag_counts(history_chars or conn_state_chars)
        features["tcp_syn_count"] = syn
        features["tcp_ack_count"] = ack
        features["tcp_fin_count"] = fin
        features["tcp_rst_count"] = rst
        features["tcp_psh_count"] = psh
        features["tcp_urg_count"] = urg
        features["tcp_flag_total"] = total_flags
        features["tcp_syn_ratio"] = nan_to_num(safe_div(float(syn), float(total_flags), default=0.0))
        features["tcp_ack_ratio"] = nan_to_num(safe_div(float(ack), float(total_flags), default=0.0))
        features["tcp_fin_ratio"] = nan_to_num(safe_div(float(fin), float(total_flags), default=0.0))
        features["tcp_rst_ratio"] = nan_to_num(safe_div(float(rst), float(total_flags), default=0.0))
        features["tcp_psh_ratio"] = nan_to_num(safe_div(float(psh), float(total_flags), default=0.0))
        features["tcp_urg_ratio"] = nan_to_num(safe_div(float(urg), float(total_flags), default=0.0))

        features["packet_size_entropy"] = nan_to_num(shannon_entropy([s for s in sizes if s > 0]))
        features["timing_entropy"] = nan_to_num(shannon_entropy([round(x, 6) for x in inter_arrivals]))
        features["burstiness_score"] = nan_to_num(safe_div(std(inter_arrivals), mean(inter_arrivals), default=0.0))
        features["packet_rate_variance"] = nan_to_num(variance(_rates_from_times(ts_valid_sorted, packet_increment=1.0)))
        features["byte_rate_variance"] = nan_to_num(variance(_rates_from_times(ts_valid_sorted, packet_increment=mean(sizes_f) if sizes_f else 0.0)))
        features["payload_variability_score"] = nan_to_num(safe_div(std(sizes_f), mean(sizes_f), default=0.0))

        features.update(_obfuscation_detection_features(flow_packets, sizes_f, inter_arrivals, ttl_vals, frag_count))

        features["flow_idle_time"] = nan_to_num(_idle_time(ts_valid_sorted))
        features["flow_active_time"] = nan_to_num(max(duration - features["flow_idle_time"], 0.0))

        return _sanitize_features(features)


def _tcp_flag_counts(history: str) -> Tuple[int, int, int, int, int, int, int]:
    h = history or ""
    syn = h.count("S")
    ack = h.count("A")
    fin = h.count("F")
    rst = h.count("R")
    psh = h.count("P")
    urg = h.count("U")
    total = syn + ack + fin + rst + psh + urg
    return syn, ack, fin, rst, psh, urg, total


def _rates_from_times(ts_sorted: List[float], packet_increment: float) -> List[float]:
    if len(ts_sorted) < 2:
        return []
    rates = []
    for a, b in zip(ts_sorted[:-1], ts_sorted[1:]):
        dt = b - a
        if dt > 0 and math.isfinite(dt):
            rates.append(packet_increment / dt)
    return rates


def _idle_time(ts_sorted: List[float], idle_threshold: float = 1.0) -> float:
    if len(ts_sorted) < 2:
        return 0.0
    idle = 0.0
    for a, b in zip(ts_sorted[:-1], ts_sorted[1:]):
        dt = b - a
        if dt > idle_threshold:
            idle += dt
    return idle


def _obfuscation_detection_features(
    flow_packets: List[Dict[str, Any]],
    sizes: List[float],
    inter_arrivals: List[float],
    ttl_vals: List[float],
    frag_count: int,
) -> Dict[str, Any]:
    size_cv = nan_to_num(safe_div(std(sizes), mean(sizes), default=0.0))
    timing_cv = nan_to_num(safe_div(std(inter_arrivals), mean(inter_arrivals), default=0.0))
    ttl_cv = nan_to_num(safe_div(std(ttl_vals), mean(ttl_vals), default=0.0))

    obf_flags = 0
    header_fields_present = 0
    for p in flow_packets:
        obf = p.get("obfuscation") or {}
        if isinstance(obf, dict):
            obf_flags += 1 if obf.get("size_randomized", False) else 0
            obf_flags += 1 if obf.get("timing_jittered", False) else 0
            obf_flags += 1 if obf.get("fragmented", False) else 0
            obf_flags += 1 if obf.get("ttl_randomized", False) else 0
            obf_flags += 1 if obf.get("tos_randomized", False) else 0
            obf_flags += 1 if obf.get("window_randomized", False) else 0
        header_fields_present += 1 if ("ttl" in p or "tos" in p or "window" in p) else 0

    header_consistency = nan_to_num(safe_div(float(header_fields_present), float(len(flow_packets)), default=0.0))
    uniformity = 1.0 - nan_to_num(safe_div(shannon_entropy([round(s, 0) for s in sizes if s > 0]), math.log(max(len(sizes), 2), 2), default=0.0))

    return {
        "packet_size_randomization_score": nan_to_num(size_cv),
        "timing_jitter_score": nan_to_num(timing_cv),
        "fragmentation_anomaly_score": nan_to_num(safe_div(float(frag_count), float(len(flow_packets)), default=0.0)),
        "ttl_randomization_score": nan_to_num(ttl_cv),
        "tos_randomization_score": 0.0,
        "window_randomization_score": 0.0,
        "header_consistency_score": nan_to_num(header_consistency),
        "timing_irregularity_score": nan_to_num(variance(inter_arrivals)),
        "flow_uniformity_score": nan_to_num(uniformity),
    }


def _sanitize_features(features: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in features.items():
        if isinstance(v, bool):
            out[k] = int(v)
        elif isinstance(v, int):
            out[k] = v
        else:
            out[k] = nan_to_num(v)
    return out
