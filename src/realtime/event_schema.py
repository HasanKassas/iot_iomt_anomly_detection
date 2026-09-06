from typing import Dict, Any, Optional
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EventSchema:
    """Defines and validates real-time event schema."""

    REQUIRED_FIELDS = [
        "timestamp",
        "src_ip",
        "dst_ip",
        "proto",
        "packet_size",
        "prediction",
        "status",
    ]

    @staticmethod
    def validate(event: Dict[str, Any]) -> bool:
        """Validate event against schema."""
        for field in EventSchema.REQUIRED_FIELDS:
            if field not in event:
                return False
        return True

    @staticmethod
    def enrich(event: Dict[str, Any], score: float = None, details: Dict = None, explanation: Dict = None) -> Dict[str, Any]:
        """Enrich event with additional metadata."""
        enriched = event.copy()
        
        enriched["enriched_at"] = datetime.now().isoformat()
        
        if score is not None:
            enriched["anomaly_score"] = float(score)
        
        if details:
            enriched["model_details"] = details
        
        if explanation:
            enriched["explanation"] = explanation
        
        if "obfuscation" in event:
            enriched["obfuscation_indicators"] = event["obfuscation"]
        
        return enriched

    @staticmethod
    def to_api_format(event: Dict[str, Any]) -> Dict[str, Any]:
        """Convert event to API-compatible format."""
        api_event = {
            "timestamp": event.get("timestamp", datetime.now().isoformat()),
            "src_ip": str(event.get("src_ip", "")),
            "dst_ip": str(event.get("dst_ip", "")),
            "proto": int(event.get("proto", event.get("protocol", 0))),
            "packet_size": int(event.get("packet_size", 0)),
            "prediction": int(event.get("prediction", 0)),
            "status": str(event.get("status", "NORMAL")),
        }
        
        if "anomaly_score" in event:
            api_event["anomaly_score"] = float(event["anomaly_score"])
        
        if "obfuscation_indicators" in event:
            api_event["obfuscation"] = event["obfuscation_indicators"]
        
        if "explanation" in event:
            api_event["explanation"] = event["explanation"]
        
        return api_event
