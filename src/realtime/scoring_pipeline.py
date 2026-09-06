from typing import Dict, Any, Optional, Tuple
import logging
import yaml
import os

from ..models.inference import AnomalyScorer
from ..realtime.feature_extraction import extract_features
from ..explainability.anomaly_reasoning import AnomalyReasoner

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ScoringPipeline:
    """Real-time scoring pipeline for incoming packets."""

    def __init__(self, config_path: str = "config/models.yaml"):
        self.config = {}
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                self.config = yaml.safe_load(f)
        
        self.scorer = AnomalyScorer(self.config)
        self.reasoner = AnomalyReasoner(self.config)
        logger.info("ScoringPipeline initialized")

    def process(self, packet: Dict[str, Any]) -> Tuple[float, str, Dict[str, Any]]:
        """Process a single packet through the full pipeline."""
        try:
            features = extract_features(packet)
            obfuscation_data = packet.get("obfuscation", {})
            score, status, details = self.scorer.score(features, obfuscation_data)
            
            explanation = None
            if score > 0.5:
                explanation = self.reasoner.reason(packet, score, details)
            
            return score, status, {"details": details, "explanation": explanation}
        
        except Exception as e:
            logger.error(f"Scoring pipeline error: {e}")
            return 0.0, "NORMAL", {"error": str(e)}
