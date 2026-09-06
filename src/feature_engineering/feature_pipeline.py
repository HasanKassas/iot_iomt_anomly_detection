from typing import Dict, Any, List
import logging
import pandas as pd
import yaml

from .packet_features import PacketFeatures
from .flow_features import FlowFeatures
from .obfuscation_features import ObfuscationFeatures

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FeaturePipeline:
    """Combined feature extraction pipeline."""

    def __init__(self, config: Dict = None, config_path: str = None):
        if config_path:
            with open(config_path, "r") as f:
                self.config = yaml.safe_load(f)
        else:
            self.config = config or {}
        
        features_config = self.config.get("features", {})
        
        self.packet_extractor = PacketFeatures(features_config)
        self.flow_extractor = FlowFeatures(features_config)
        self.obfuscation_extractor = ObfuscationFeatures(features_config)
        
        logger.info("FeaturePipeline initialized")

    def extract_packet_features(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """Extract all features from a single packet."""
        features = {}
        
        features.update(self.packet_extractor.extract(packet))
        features.update(self.obfuscation_extractor.extract(packet))
        
        return features

    def extract_flow_features(self, flow_packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract all features from a flow."""
        features = {}
        
        features.update(self.flow_extractor.extract(flow_packets))
        features.update(self.obfuscation_extractor.extract_batch(flow_packets))
        
        return features

    def to_dataframe(self, features_list: List[Dict[str, Any]]) -> pd.DataFrame:
        """Convert list of feature dicts to DataFrame."""
        return pd.DataFrame(features_list)
