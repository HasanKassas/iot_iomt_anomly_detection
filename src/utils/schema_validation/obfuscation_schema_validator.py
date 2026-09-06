import logging
from typing import Dict, Any, Optional, Tuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ObfuscationSchemaValidator:
    """Validates obfuscation metadata schema."""

    VALID_OBFUSCATION_FLAGS = [
        "size_randomized",
        "timing_jittered",
        "fragmented",
        "ttl_randomized",
        "tos_randomized",
        "window_randomized",
    ]

    VALID_SEVERITY_LEVELS = ["low", "medium", "high"]

    @staticmethod
    def validate(obfuscation_data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Validate obfuscation metadata against schema.
        
        Returns:
            (is_valid, error_message)
        """
        try:
            if obfuscation_data is None:
                return True, None
            
            if not isinstance(obfuscation_data, dict):
                return False, "Obfuscation data must be a dictionary"
            
            for key, value in obfuscation_data.items():
                if key in ObfuscationSchemaValidator.VALID_OBFUSCATION_FLAGS:
                    if not isinstance(value, bool):
                        return False, f"Obfuscation flag {key} must be boolean"
            
            if "obfuscation_level" in obfuscation_data:
                level = str(obfuscation_data["obfuscation_level"]).lower()
                if level not in ObfuscationSchemaValidator.VALID_SEVERITY_LEVELS:
                    return False, f"Invalid obfuscation level: {level}"
            
            if "jitter_ms" in obfuscation_data:
                try:
                    jitter = float(obfuscation_data["jitter_ms"])
                    if jitter < 0:
                        return False, f"jitter_ms cannot be negative: {jitter}"
                except (ValueError, TypeError):
                    return False, f"jitter_ms must be a number: {obfuscation_data['jitter_ms']}"
            
            if "original_size" in obfuscation_data:
                try:
                    size = int(obfuscation_data["original_size"])
                    if size < 0:
                        return False, f"original_size cannot be negative: {size}"
                except (ValueError, TypeError):
                    return False, f"original_size must be a number: {obfuscation_data['original_size']}"
            
            return True, None
            
        except Exception as e:
            logger.warning(f"Obfuscation validation exception: {e}")
            return False, f"Validation exception: {str(e)}"

    @staticmethod
    def safe_validate(obfuscation_data: Dict[str, Any]) -> bool:
        """Validate obfuscation data and return boolean only."""
        is_valid, _ = ObfuscationSchemaValidator.validate(obfuscation_data)
        return is_valid
