import logging
from typing import Dict, Any, Optional, Tuple
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PacketSchemaValidator:
    """Validates packet schema for safe pipeline processing."""

    REQUIRED_FIELDS = [
        "timestamp",
        "src_ip",
        "dst_ip",
    ]

    OPTIONAL_FIELDS = [
        "proto",
        "packet_size",
        "prediction",
        "status",
        "obfuscation",
        "obfuscation_level",
    ]

    @staticmethod
    def validate(packet: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Validate a packet against schema.
        
        Returns:
            (is_valid, error_message)
        """
        try:
            if not isinstance(packet, dict):
                return False, "Packet must be a dictionary"
            
            for field in PacketSchemaValidator.REQUIRED_FIELDS:
                if field not in packet:
                    return False, f"Missing required field: {field}"
                if packet[field] is None:
                    return False, f"Required field cannot be None: {field}"
            
            src_ip = str(packet.get("src_ip", "")).strip()
            if not src_ip:
                return False, "src_ip cannot be empty"
            
            dst_ip = str(packet.get("dst_ip", "")).strip()
            if not dst_ip:
                return False, "dst_ip cannot be empty"
            
            if "packet_size" in packet:
                try:
                    size = int(packet["packet_size"])
                    if size < 0:
                        return False, f"packet_size cannot be negative: {size}"
                except (ValueError, TypeError):
                    return False, f"packet_size must be a number: {packet['packet_size']}"
            
            if "proto" in packet:
                try:
                    proto = int(packet["proto"])
                    if proto < 0:
                        return False, f"proto cannot be negative: {proto}"
                except (ValueError, TypeError):
                    return False, f"proto must be a number: {packet['proto']}"
            
            if "prediction" in packet:
                try:
                    pred = int(packet["prediction"])
                    if pred not in [0, 1]:
                        return False, f"prediction must be 0 or 1: {pred}"
                except (ValueError, TypeError):
                    return False, f"prediction must be a number: {packet['prediction']}"
            
            return True, None
            
        except Exception as e:
            logger.warning(f"Packet validation exception: {e}")
            return False, f"Validation exception: {str(e)}"

    @staticmethod
    def safe_validate(packet: Dict[str, Any]) -> bool:
        """Validate and return boolean only, no exceptions."""
        is_valid, _ = PacketSchemaValidator.validate(packet)
        return is_valid
