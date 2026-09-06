import logging
from typing import List, Dict, Any, Optional, Tuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FlowSchemaValidator:
    """Validates flow schema for safe pipeline processing."""

    @staticmethod
    def validate(flow: List[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
        """
        Validate a flow (list of packets) against schema.
        
        Returns:
            (is_valid, error_message)
        """
        try:
            if not isinstance(flow, list):
                return False, "Flow must be a list of packets"
            
            if len(flow) == 0:
                return False, "Flow cannot be empty"
            
            from .packet_schema_validator import PacketSchemaValidator
            
            for i, packet in enumerate(flow):
                is_valid, error = PacketSchemaValidator.validate(packet)
                if not is_valid:
                    return False, f"Packet {i} invalid: {error}"
            
            return True, None
            
        except Exception as e:
            logger.warning(f"Flow validation exception: {e}")
            return False, f"Validation exception: {str(e)}"

    @staticmethod
    def safe_validate(flow: List[Dict[str, Any]]) -> bool:
        """Validate and return boolean only, no exceptions."""
        is_valid, _ = FlowSchemaValidator.validate(flow)
        return is_valid
