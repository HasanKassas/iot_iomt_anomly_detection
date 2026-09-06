from typing import Dict, Any, List
import logging
import numpy as np

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from .safety import nan_to_num, safe_div, safe_float, safe_int


class ObfuscationFeatures:
    """Extracts obfuscation-related features from packets/flows."""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        logger.info("ObfuscationFeatures initialized")

    def extract(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """Extract obfuscation features from a single packet."""
        features: Dict[str, Any] = {}
        
        obfuscation_data = packet.get("obfuscation", {})
        
        features["obf_size_randomized"] = 1 if obfuscation_data.get("size_randomized", False) else 0
        features["obf_timing_jittered"] = 1 if obfuscation_data.get("timing_jittered", False) else 0
        features["obf_fragmented"] = 1 if obfuscation_data.get("fragmented", False) else 0
        features["obf_ttl_randomized"] = 1 if obfuscation_data.get("ttl_randomized", False) else 0
        features["obf_tos_randomized"] = 1 if obfuscation_data.get("tos_randomized", False) else 0
        features["obf_window_randomized"] = 1 if obfuscation_data.get("window_randomized", False) else 0
        
        if "jitter_ms" in obfuscation_data:
            features["obf_jitter_ms"] = nan_to_num(safe_float(obfuscation_data.get("jitter_ms"), default=0.0))
        
        if "fragment_index" in obfuscation_data:
            features["obf_fragment_index"] = safe_int(obfuscation_data.get("fragment_index"), default=0)
        
        if "total_fragments" in obfuscation_data:
            features["obf_total_fragments"] = safe_int(obfuscation_data.get("total_fragments"), default=0)
        
        return features

    def extract_batch(self, packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract aggregated obfuscation features from a batch of packets."""
        features: Dict[str, Any] = {}
        
        if not packets:
            return features
        
        all_obf_flags = []
        jitter_values = []
        
        for p in packets:
            obf = p.get("obfuscation", {})
            flags = sum([
                obf.get("size_randomized", False),
                obf.get("timing_jittered", False),
                obf.get("fragmented", False),
                obf.get("ttl_randomized", False),
                obf.get("tos_randomized", False),
                obf.get("window_randomized", False),
            ])
            all_obf_flags.append(flags)
            if "jitter_ms" in obf:
                jitter_values.append(safe_float(obf.get("jitter_ms"), default=0.0))
        
        features["obf_count"] = sum(all_obf_flags)
        features["obf_mean_flags"] = nan_to_num(np.mean(all_obf_flags)) if all_obf_flags else 0.0
        features["obf_max_flags"] = nan_to_num(np.max(all_obf_flags)) if all_obf_flags else 0.0
        features["obf_mean_jitter"] = nan_to_num(np.mean(jitter_values)) if jitter_values else 0.0

        features["obf_presence_ratio"] = nan_to_num(safe_div(float(sum(1 for x in all_obf_flags if x > 0)), float(len(all_obf_flags)), default=0.0))
        
        return features
