from typing import Dict, Any, Optional
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AlertEnricher:
    """Enriches alerts with metadata and context."""

    SEVERITY_MAP = {
        "CRITICAL": 0.9,
        "HIGH": 0.7,
        "MEDIUM": 0.5,
        "LOW": 0.0,
    }

    def __init__(self, config: Dict = None):
        self.config = config or {}
        logger.info("AlertEnricher initialized")

    def enrich(
        self,
        ip: str,
        packet: Dict[str, Any],
        score: float,
        explanation: Dict = None,
    ) -> Dict[str, Any]:
        """Create enriched alert object."""
        severity = "LOW"
        for level, threshold in sorted(self.SEVERITY_MAP.items(), key=lambda x: -x[1]):
            if score >= threshold:
                severity = level
                break
        
        alert = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": ip,
            "severity": severity,
            "anomaly_score": float(score),
            "packet": {
                "src_ip": packet.get("src_ip"),
                "dst_ip": packet.get("dst_ip"),
                "proto": packet.get("proto", packet.get("protocol")),
                "packet_size": packet.get("packet_size"),
            },
        }
        
        obfuscation = packet.get("obfuscation", {})
        if obfuscation:
            alert["obfuscation_detected"] = True
            alert["obfuscation_techniques"] = [
                k for k, v in obfuscation.items()
                if isinstance(v, bool) and v
            ]
        
        if explanation:
            alert["explanation"] = explanation
        
        return alert
