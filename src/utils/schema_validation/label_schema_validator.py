import logging
from typing import Any, Tuple, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LabelSchemaValidator:
    """Validates label schema for safe pipeline processing."""

    VALID_BINARY_LABELS = [0, 1, "0", "1", "normal", "malicious", "benign", "attack"]
    VALID_STRING_NORMAL = ["normal", "benign", "0"]
    VALID_STRING_MALICIOUS = ["malicious", "attack", "1"]

    @staticmethod
    def validate(label: Any) -> Tuple[bool, Optional[str]]:
        """
        Validate a label against schema.
        
        Returns:
            (is_valid, error_message)
        """
        try:
            if label is None:
                return False, "Label cannot be None"
            
            if isinstance(label, str):
                label_lower = label.strip().lower()
                if label_lower not in LabelSchemaValidator.VALID_BINARY_LABELS:
                    return False, f"Invalid string label: {label}"
            elif isinstance(label, int):
                if label not in [0, 1]:
                    return False, f"Invalid integer label: {label} (must be 0 or 1)"
            else:
                return False, f"Label must be string or integer: {type(label)}"
            
            return True, None
            
        except Exception as e:
            logger.warning(f"Label validation exception: {e}")
            return False, f"Validation exception: {str(e)}"

    @staticmethod
    def safe_normalize(label: Any) -> int:
        """
        Safely normalize label to 0 (normal) or 1 (malicious).
        Never raises exception - defaults to 0 if invalid.
        """
        try:
            is_valid, _ = LabelSchemaValidator.validate(label)
            if not is_valid:
                logger.warning(f"Invalid label, defaulting to 0: {label}")
                return 0
            
            if isinstance(label, str):
                label_lower = label.strip().lower()
                if label_lower in LabelSchemaValidator.VALID_STRING_MALICIOUS:
                    return 1
                return 0
            elif isinstance(label, int):
                return label
            
            return 0
            
        except Exception as e:
            logger.warning(f"Label normalization exception, defaulting to 0: {e}")
            return 0
