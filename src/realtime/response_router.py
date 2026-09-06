from typing import Dict, Any, Optional
import logging
import yaml
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ResponseRouter:
    """Routes security responses based on alert severity."""

    def __init__(self, config_path: str = "config/realtime.yaml"):
        self.config = {}
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                self.config = yaml.safe_load(f)
        
        alerting_config = self.config.get("realtime", {}).get("alerting", {})
        self.severity_levels = alerting_config.get("severity_levels", {})
        logger.info("ResponseRouter initialized")

    def get_actions(self, severity: str) -> list:
        """Get response actions for a given severity."""
        level_config = self.severity_levels.get(severity.lower(), {})
        return level_config.get("actions", ["log"])

    def should_respond(self, alert: Dict[str, Any]) -> bool:
        """Determine if response should be triggered."""
        return alert.get("severity", "LOW") in ["HIGH", "CRITICAL"]
