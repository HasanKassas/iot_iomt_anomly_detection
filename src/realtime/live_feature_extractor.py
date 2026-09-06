import os
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd

from src.feature_engineering.feature_pipeline import FeaturePipeline
from src.utils.schema_validation.flow_schema_validator import FlowSchemaValidator


class LiveFeatureExtractor:
    def __init__(
        self,
        feature_config_path: str = "config/features.yaml",
        rf_feature_columns_path: str = "models/feature_columns.pkl",
        rf_scaler_path: str = "models/scaler.pkl",
    ):
        self.pipeline = FeaturePipeline(config_path=feature_config_path if os.path.isfile(feature_config_path) else None)

        self.rf_feature_columns = None
        if os.path.isfile(rf_feature_columns_path):
            try:
                self.rf_feature_columns = list(joblib.load(rf_feature_columns_path))
            except Exception:
                self.rf_feature_columns = None

        self.rf_scaler = None
        if os.path.isfile(rf_scaler_path):
            try:
                self.rf_scaler = joblib.load(rf_scaler_path)
            except Exception:
                self.rf_scaler = None

    def _sanitize_flow(self, flow_packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        cleaned: List[Dict[str, Any]] = []
        for p in flow_packets or []:
            if not isinstance(p, dict):
                continue
            pkt = dict(p)
            if "timestamp" not in pkt:
                pkt["timestamp"] = pkt.get("timestamp_epoch")
            if pkt.get("timestamp") is None:
                pkt["timestamp"] = 0.0
            if "packet_size" in pkt:
                try:
                    pkt["packet_size"] = int(pkt.get("packet_size", 0) or 0)
                except Exception:
                    pkt["packet_size"] = 0
            cleaned.append(pkt)
        return cleaned

    def extract_raw_features(self, flow_packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        flow_packets = self._sanitize_flow(flow_packets)
        if not FlowSchemaValidator.safe_validate(flow_packets):
            cols = self.rf_feature_columns or []
            return {c: 0.0 for c in cols} if cols else {}

        feats = self.pipeline.extract_flow_features(flow_packets)
        for k, v in list(feats.items()):
            if v is None:
                feats[k] = 0.0
        return feats

    def align_schema(self, raw_features: Dict[str, Any]) -> Dict[str, Any]:
        cols = self.rf_feature_columns or []
        if not cols:
            return dict(raw_features or {})
        clip = 1e6
        try:
            clip = float(os.getenv("LIVE_FEATURE_CLIP", "1000000"))
        except Exception:
            clip = 1e6
        clip = max(1.0, min(float(clip), 1e9))
        out: Dict[str, Any] = {}
        for c in cols:
            v = raw_features.get(c, 0.0) if isinstance(raw_features, dict) else 0.0
            if v is None:
                v = 0.0
            try:
                vf = float(v)
                if not np.isfinite(vf):
                    vf = 0.0
            except Exception:
                vf = 0.0
            if vf > clip:
                vf = clip
            elif vf < -clip:
                vf = -clip
            out[c] = vf
        return out

    def to_rf_vector(self, raw_features: Dict[str, Any]) -> np.ndarray:
        cols = self.rf_feature_columns
        if cols:
            df = pd.DataFrame([{c: raw_features.get(c, 0.0) for c in cols}])
        else:
            df = pd.DataFrame([raw_features])

        df = df.replace([np.inf, -np.inf], np.nan).fillna(0.0)
        x = df.to_numpy(dtype=np.float32)
        x = np.nan_to_num(x, nan=0.0, posinf=0.0, neginf=0.0)
        if self.rf_scaler is not None:
            try:
                x = self.rf_scaler.transform(x)
            except Exception:
                pass
        x = np.nan_to_num(x, nan=0.0, posinf=0.0, neginf=0.0).astype(np.float32)
        return x.reshape(1, -1)

    def extract(self, flow_packets: List[Dict[str, Any]]) -> Tuple[Dict[str, Any], np.ndarray]:
        raw = self.extract_raw_features(flow_packets)
        aligned = self.align_schema(raw)
        vec = self.to_rf_vector(aligned)
        return aligned, vec

    def schema_size(self) -> int:
        return int(len(self.rf_feature_columns or []))
