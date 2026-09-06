import logging
from typing import Dict, Any, Optional, Tuple
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EventSchemaValidator:
    """Validates real-time event schema for API safety."""

    REQUIRED_FIELDS_API = [
        "timestamp",
        "src_ip",
        "dst_ip",
        "proto",
        "packet_size",
        "prediction",
        "status",
    ]

    @staticmethod
    def validate_api_event(event: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Validate an API event against schema.
        
        Returns:
            (is_valid, error_message)
        """
        try:
            if not isinstance(event, dict):
                return False, "Event must be a dictionary"
            
            for field in EventSchemaValidator.REQUIRED_FIELDS_API:
                if field not in event:
                    return False, f"Missing required API field: {field}"
            
            if "prediction" in event:
                try:
                    pred = int(event["prediction"])
                    if pred not in [0, 1]:
                        return False, f"prediction must be 0 or 1: {pred}"
                except (ValueError, TypeError):
                    return False, f"prediction must be a number: {event['prediction']}"
            
            status = str(event.get("status", "")).strip().upper()
            if status not in ["NORMAL", "ANOMALY", "SUSPICIOUS"]:
                return False, f"Invalid status: {status}"
            
            return True, None
            
        except Exception as e:
            logger.warning(f"Event validation exception: {e}")
            return False, f"Validation exception: {str(e)}"

    @staticmethod
    def safe_validate_api_event(event: Dict[str, Any]) -> bool:
        """Validate API event and return boolean only."""
        is_valid, _ = EventSchemaValidator.validate_api_event(event)
        return is_valid
