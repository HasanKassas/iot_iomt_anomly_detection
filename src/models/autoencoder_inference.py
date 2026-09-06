import json
import os
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np


class AutoencoderInference:
    """
    Autoencoder inference wrapper.

    Produces ensemble-compatible outputs without modifying existing real-time flow.
    """

    def __init__(
        self,
        model_path: str = "models/autoencoder_optimized.keras",
        scaler_path: str = "models/autoencoder_scaler.pkl",
        threshold_path: str = "models/autoencoder_threshold.json",
        feature_columns_path: str = "models/feature_columns.pkl",
        thresholds_percentiles_path: str = "models/ae_thresholds.json",
    ):
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.threshold_path = threshold_path
        self.feature_columns_path = feature_columns_path
        self.thresholds_percentiles_path = thresholds_percentiles_path

        self.model = None
        self.scaler = None
        self.feature_columns: Optional[List[str]] = None
        self.threshold_value: float = 0.0
        self.threshold_method: str = "unknown"
        self.thresholds_percentiles: Dict[str, float] = {}
        self._percentile_threshold: float = 0.0

        self._load_artifacts()

    def _load_artifacts(self) -> None:
        self.feature_columns = None
        if os.path.isfile(self.feature_columns_path):
            try:
                self.feature_columns = list(joblib.load(self.feature_columns_path))
            except Exception:
                self.feature_columns = None

        if os.path.isfile(self.scaler_path):
            try:
                self.scaler = joblib.load(self.scaler_path)
            except Exception:
                self.scaler = None

        if os.path.isfile(self.threshold_path):
            try:
                with open(self.threshold_path, "r", encoding="utf-8") as f:
                    payload = json.load(f) or {}
                self.threshold_value = float(payload.get("threshold", 0.0) or 0.0)
                self.threshold_method = str(payload.get("method", "unknown"))
                cand = payload.get("candidates") or {}
                if isinstance(cand, dict):
                    pct = cand.get("percentile") or {}
                    if isinstance(pct, dict):
                        self._percentile_threshold = float(pct.get("threshold", 0.0) or 0.0)
            except Exception:
                self.threshold_value = 0.0
                self.threshold_method = "unknown"
                self._percentile_threshold = 0.0

        self.thresholds_percentiles = {}
        if os.path.isfile(self.thresholds_percentiles_path):
            try:
                with open(self.thresholds_percentiles_path, "r", encoding="utf-8") as f:
                    payload = json.load(f) or {}
                if isinstance(payload, dict):
                    p = payload.get("percentiles") or {}
                    if isinstance(p, dict):
                        for k, v in p.items():
                            try:
                                self.thresholds_percentiles[str(k)] = float(v)
                            except Exception:
                                continue
            except Exception:
                self.thresholds_percentiles = {}

        self.model = None
        if os.path.isfile(self.model_path):
            try:
                import tensorflow as tf

                self.model = tf.keras.models.load_model(self.model_path)
            except Exception:
                self.model = None

        if not self.thresholds_percentiles and self.model is not None and self.scaler is not None:
            try:
                import pandas as pd

                train_p = os.path.join("data", "processed", "final", "baseline_clean_train.csv")
                test_p = os.path.join("data", "processed", "final", "baseline_clean_test.csv")
                src = train_p if os.path.isfile(train_p) else test_p
                if os.path.isfile(src) and self.feature_columns:
                    df = pd.read_csv(src)
                    if "label_binary" in df.columns:
                        df = df[df["label_binary"].astype(int) == 0]
                    if len(df) > 5000:
                        df = df.sample(n=5000, random_state=42)
                    X = df[self.feature_columns].replace([np.inf, -np.inf], np.nan).fillna(0.0).to_numpy(dtype=np.float32)
                    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0).astype(np.float32)
                    Xs = self.scaler.transform(X)
                    Xs = np.nan_to_num(Xs, nan=0.0, posinf=1e6, neginf=-1e6).astype(np.float32)
                    Xs = np.clip(Xs, -1e6, 1e6).astype(np.float32)
                    recon = self.model.predict(Xs, verbose=0)
                    recon = np.nan_to_num(recon, nan=0.0, posinf=0.0, neginf=0.0).astype(np.float32)
                    errs = np.mean(np.square(Xs - recon), axis=1)
                    errs = np.nan_to_num(errs, nan=0.0, posinf=0.0, neginf=0.0)
                    self.thresholds_percentiles = {
                        "p95": float(np.percentile(errs, 95.0)) if errs.size else 0.0,
                        "p99": float(np.percentile(errs, 99.0)) if errs.size else 0.0,
                        "p999": float(np.percentile(errs, 99.9)) if errs.size else 0.0,
                    }
                    try:
                        with open(self.thresholds_percentiles_path, "w", encoding="utf-8") as f:
                            json.dump({"percentiles": self.thresholds_percentiles, "source": src}, f, indent=2)
                    except Exception:
                        pass
            except Exception:
                self.thresholds_percentiles = {}

    def _to_vector(self, feature_vector: Any) -> Tuple[np.ndarray, List[str]]:
        cols = self.feature_columns or []

        if isinstance(feature_vector, dict):
            if cols:
                arr = np.array([float(feature_vector.get(c, 0.0) or 0.0) for c in cols], dtype=np.float32)
                return arr, cols
            keys = sorted(feature_vector.keys())
            arr = np.array([float(feature_vector.get(k, 0.0) or 0.0) for k in keys], dtype=np.float32)
            return arr, keys

        if isinstance(feature_vector, (list, tuple, np.ndarray)):
            arr = np.asarray(feature_vector, dtype=np.float32).reshape(-1)
            if cols and len(cols) == arr.shape[0]:
                return arr, cols
            return arr, cols if cols else [f"f{i}" for i in range(arr.shape[0])]

        return np.zeros((len(cols) if cols else 0,), dtype=np.float32), cols

    def score(self, feature_vector: Any, top_k: int = 5) -> Dict[str, Any]:
        vec, cols = self._to_vector(feature_vector)
        if vec.size == 0:
            return {
                "model": "autoencoder",
                "anomaly_score": 0.0,
                "reconstruction_error": 0.0,
                "threshold": float(self.threshold_value),
                "prediction": 0,
                "confidence": 0.0,
                "top_contributing_features": [],
                "error": "empty_feature_vector",
            }

        vec = np.nan_to_num(vec, nan=0.0, posinf=0.0, neginf=0.0).astype(np.float32)
        X = vec.reshape(1, -1)

        if self.scaler is not None:
            try:
                X = self.scaler.transform(X)
            except Exception:
                X = vec.reshape(1, -1)

        X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6).astype(np.float32)
        X = np.clip(X, -1e6, 1e6).astype(np.float32)

        if self.model is None:
            return {
                "model": "autoencoder",
                "anomaly_score": 0.0,
                "reconstruction_error": 0.0,
                "threshold": float(self.threshold_value),
                "prediction": 0,
                "confidence": 0.0,
                "top_contributing_features": [],
                "error": "model_not_loaded",
            }

        try:
            recon = self.model.predict(X, verbose=0)
            recon = np.nan_to_num(recon, nan=0.0, posinf=0.0, neginf=0.0).astype(np.float32)
            per_feat = np.square(X - recon).reshape(-1)
            per_feat = np.nan_to_num(per_feat, nan=0.0, posinf=1e6, neginf=0.0)
            mse = float(np.mean(per_feat)) if per_feat.size else 0.0
            if not np.isfinite(mse):
                mse = 0.0
        except Exception as exc:
            return {
                "model": "autoencoder",
                "anomaly_score": 0.0,
                "reconstruction_error": 0.0,
                "threshold": float(self.threshold_value),
                "prediction": 0,
                "confidence": 0.0,
                "top_contributing_features": [],
                "error": f"inference_failed:{exc}",
            }

        p99 = float(self.thresholds_percentiles.get("p99", 0.0) or 0.0)
        p95 = float(self.thresholds_percentiles.get("p95", 0.0) or 0.0)
        p999 = float(self.thresholds_percentiles.get("p999", 0.0) or 0.0)

        if p99 > 0:
            threshold_used = float(p99)
            threshold_method = "p99"
        elif float(self._percentile_threshold) > 0:
            threshold_used = float(self._percentile_threshold)
            threshold_method = "percentile"
        else:
            threshold_used = float(self.threshold_value)
            threshold_method = self.threshold_method

        pred = 1 if mse > float(threshold_used) else 0
        denom = abs(float(threshold_used)) if float(threshold_used) != 0 else 1.0
        anomaly_score = float(min(max(mse / denom, 0.0), 10.0))

        if p95 > 0 and p99 > p95:
            if mse <= p95:
                confidence = 0.0
            elif mse >= p999 and p999 > 0:
                confidence = 1.0
            else:
                confidence = float(min(max((mse - p95) / max(1e-12, (p99 - p95)), 0.0), 1.0))
        else:
            confidence = float(min(max(abs(mse - float(threshold_used)) / denom, 0.0), 1.0))

        top_k = int(top_k) if top_k is not None else 5
        top_k = max(0, min(top_k, per_feat.size))
        idx = np.argsort(-per_feat)[:top_k] if top_k > 0 else []
        top = [{"feature": cols[int(i)] if int(i) < len(cols) else f"f{i}", "contribution": float(per_feat[int(i)])} for i in idx]

        return {
            "model": "autoencoder",
            "anomaly_score": anomaly_score,
            "reconstruction_error": float(mse),
            "threshold": float(threshold_used),
            "prediction": int(pred),
            "confidence": confidence,
            "top_contributing_features": top,
            "threshold_method": threshold_method,
        }
