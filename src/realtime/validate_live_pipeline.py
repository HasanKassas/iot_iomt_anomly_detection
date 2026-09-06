import os
import time
from typing import Any, Dict, List

import numpy as np

from src.realtime.fusion_engine import FusionEngine
from src.realtime.live_feature_extractor import LiveFeatureExtractor
from src.realtime.live_flow_builder import LiveFlowBuilder


def _pkt_to_dict(pkt) -> Dict[str, Any]:
    from scapy.layers.inet import IP, TCP, UDP

    if IP not in pkt:
        return {}
    ip = pkt[IP]
    proto = int(ip.proto or 0)
    src_ip = str(ip.src)
    dst_ip = str(ip.dst)
    ttl = int(getattr(ip, "ttl", 0) or 0)
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
    return {
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
    }


def main() -> int:
    pcap = os.getenv("LIVE_VALIDATE_PCAP", "").strip()
    if not pcap:
        print("FAILED: LIVE_VALIDATE_PCAP not set")
        return 2

    max_packets = int(os.getenv("LIVE_VALIDATE_MAX_PKTS", "200000"))
    flow_timeout = float(os.getenv("LIVE_VALIDATE_FLOW_TIMEOUT", "3"))
    max_pkts_per_flow = int(os.getenv("LIVE_VALIDATE_MAX_PKTS_PER_FLOW", "2000"))

    feats = LiveFeatureExtractor()
    fusion = FusionEngine()
    flows = LiveFlowBuilder(flow_timeout_seconds=flow_timeout, max_packets_per_flow=max_pkts_per_flow, max_active_flows=50000)

    schema_n = feats.schema_size()
    print("schema_size", schema_n)
    print("rf_model_loaded", fusion.rf_model is not None)
    print("ae_model_loaded", getattr(getattr(fusion, "ae", None), "model", None) is not None)

    total_pkts = 0
    total_flows = 0
    vec_ok = 0
    ae_finite = 0
    max_ae_err = 0.0
    max_fusion = 0.0
    min_fusion = 1.0
    rf_probs: List[float] = []
    ae_errs: List[float] = []

    from scapy.utils import PcapReader

    with PcapReader(pcap) as pr:
        for pkt in pr:
            total_pkts += 1
            if total_pkts > max_packets:
                break
            d = _pkt_to_dict(pkt)
            if not d:
                continue
            completed = flows.add_packet(d)
            for fl in completed:
                total_flows += 1
                raw, vec = feats.extract(fl.packets)
                ok_shape = bool(schema_n and hasattr(vec, "shape") and int(vec.shape[-1]) == int(schema_n))
                if ok_shape:
                    vec_ok += 1

                rf = fusion.rf_predict(raw)
                ae = fusion.ae.score(raw, top_k=0)
                det = fusion.process_event(
                    feature_vector=raw,
                    source_ip=str(fl.key[0]),
                    destination_ip=str(fl.key[1]),
                    predicted_attack="validate_live_pipeline",
                    obfuscation_detected=False,
                    extra={"flow_key": "|".join([str(x) for x in fl.key])},
                    enable_autoblock=False,
                    persist=False,
                )
                fp = float(rf.get("malicious_probability", 0.0) or 0.0)
                rf_probs.append(fp)

                err = float(ae.get("reconstruction_error", 0.0) or 0.0)
                if np.isfinite(err):
                    ae_finite += 1
                max_ae_err = max(max_ae_err, float(err if np.isfinite(err) else 0.0))
                ae_errs.append(err)

                fs = float(det.get("fusion_score", 0.0) or 0.0)
                if np.isfinite(fs):
                    max_fusion = max(max_fusion, fs)
                    min_fusion = min(min_fusion, fs)

    flows.flush_expired()

    def _pct(x):
        try:
            return float(np.percentile(np.array(x, dtype=np.float64), 50.0)) if x else 0.0
        except Exception:
            return 0.0

    print("packets", total_pkts)
    print("flows", total_flows)
    print("vector_shape_ok", vec_ok)
    print("ae_finite", ae_finite)
    print("rf_prob_median", _pct(rf_probs))
    print("ae_err_median", _pct(ae_errs))
    print("ae_err_max", max_ae_err)
    print("fusion_min", min_fusion if total_flows else 0.0)
    print("fusion_max", max_fusion if total_flows else 0.0)

    if not total_flows:
        print("FAILED: no flows completed (check flow timeout / traffic)")
        return 1
    if not vec_ok:
        print("FAILED: feature vector shape mismatch (schema alignment)")
        return 1
    if max_ae_err > 1e6 or not np.isfinite(max_ae_err):
        print("FAILED: AE reconstruction error still unstable")
        return 1
    if max_fusion > 1.0 + 1e-6 or min_fusion < -1e-6:
        print("FAILED: fusion score out of [0,1]")
        return 1

    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

