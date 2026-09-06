import os
import time
from typing import Any, Dict, Optional

import joblib
import numpy as np

from src.models.autoencoder_inference import AutoencoderInference
from src.realtime.active_response import ActiveResponse
from src.realtime.device_mapper import DeviceMapper
from src.realtime.event_store import EventStore


def _safe_float(x: Any, default: float = 0.0) -> float:
    try:
        v = float(x)
        if not np.isfinite(v):
            return default
        return v
    except Exception:
        return default


class FusionEngine:
    def __init__(
        self,
        rf_model_path: str = "models/anomaly_model.pkl",
        weights: Optional[Dict[str, float]] = None,
        device_registry_path: str = "config/device_registry.json",
    ):
        self.rf_model = None
        if os.path.isfile(rf_model_path):
            try:
                self.rf_model = joblib.load(rf_model_path)
            except Exception:
                self.rf_model = None

        self.rf_feature_columns = None
        self.rf_scaler = None
        if os.path.isfile("models/feature_columns.pkl"):
            try:
                self.rf_feature_columns = list(joblib.load("models/feature_columns.pkl"))
            except Exception:
                self.rf_feature_columns = None
        if os.path.isfile("models/scaler.pkl"):
            try:
                self.rf_scaler = joblib.load("models/scaler.pkl")
            except Exception:
                self.rf_scaler = None

        self.ae = AutoencoderInference()
        self.weights = weights or {"random_forest": 0.7, "autoencoder": 0.3}
        self.device_mapper = DeviceMapper(device_registry_path)
        self.store = EventStore()
        self.response = ActiveResponse()

        self._src_windows: Dict[str, Dict[str, Any]] = {}
        self._src_fusion_ema: Dict[str, float] = {}
        self._ema_alpha = 0.25
        self._stats: Dict[str, int] = {"rf_predictions": 0, "ae_predictions": 0, "fusion_events": 0}

    def stats(self) -> Dict[str, int]:
        return dict(self._stats)

    def _to_rf_matrix(self, feature_vector: Any) -> np.ndarray:
        cols = self.rf_feature_columns or []

        if isinstance(feature_vector, dict):
            if cols:
                x = np.asarray([[float(feature_vector.get(c, 0.0) or 0.0) for c in cols]], dtype=np.float32)
            else:
                keys = sorted(feature_vector.keys())
                x = np.asarray([[float(feature_vector.get(k, 0.0) or 0.0) for k in keys]], dtype=np.float32)
        else:
            x = np.asarray(feature_vector, dtype=np.float32)
            if x.ndim == 1:
                x = x.reshape(1, -1)

        x = np.nan_to_num(x, nan=0.0, posinf=0.0, neginf=0.0).astype(np.float32)
        if self.rf_scaler is not None:
            try:
                x = self.rf_scaler.transform(x)
            except Exception:
                pass
        return x

    def rf_predict(self, X: Any) -> Dict[str, Any]:
        self._stats["rf_predictions"] = int(self._stats.get("rf_predictions", 0)) + 1
        if self.rf_model is None:
            return {"predicted_label": 0, "malicious_probability": 0.0, "confidence": 0.0}
        try:
            x = self._to_rf_matrix(X)
            pred = int(self.rf_model.predict(x)[0])
            prob = 0.0
            if hasattr(self.rf_model, "predict_proba"):
                prob = float(self.rf_model.predict_proba(x)[0][1])
            else:
                prob = float(pred)
            conf = float(max(prob, 1.0 - prob))
            return {"predicted_label": pred, "malicious_probability": prob, "confidence": conf}
        except Exception:
            return {"predicted_label": 0, "malicious_probability": 0.0, "confidence": 0.0}

    def _severity(self, fusion_score: float, obfuscation_detected: bool, repeats: int, criticality: str) -> str:
        s = float(fusion_score)
        base = "low"
        if s > 1.0:
            base = "critical"
        elif s >= 0.7:
            base = "high"
        elif s >= 0.4:
            base = "medium"
        else:
            base = "low"

        if obfuscation_detected and base == "medium":
            base = "high"
        if repeats >= 3 and base == "high" and s >= 0.8:
            base = "critical"
        if str(criticality).lower() == "critical" and base == "high" and s >= 0.8:
            base = "critical"
        return base.upper()

    def _recommended_action(self, severity: str, already_blocked: bool) -> str:
        sev = (severity or "").upper()
        if sev in {"CRITICAL", "HIGH"}:
            return "BLOCK_IP" if not already_blocked else "ALREADY_BLOCKED"
        if sev == "MEDIUM":
            return "INVESTIGATE"
        return "MONITOR"

    def _normalize_ae(self, ae_score: float) -> float:
        s = _safe_float(ae_score, 0.0)
        s = max(0.0, min(10.0, s))
        return s / 10.0

    def _clamp01(self, x: float) -> float:
        v = _safe_float(x, 0.0)
        return float(max(0.0, min(1.0, v)))

    def _repeats_in_window(self, src_ip: str, now_s: float, window_s: float = 60.0) -> int:
        if not src_ip:
            return 0
        w = self._src_windows.get(src_ip)
        if w is None:
            w = {"ts": []}
            self._src_windows[src_ip] = w
        ts_list = w.get("ts") or []
        ts_list = [t for t in ts_list if (now_s - float(t)) <= float(window_s)]
        ts_list.append(float(now_s))
        w["ts"] = ts_list[-200:]
        return int(len(ts_list))

    def process_event(
        self,
        feature_vector: Any,
        source_ip: str,
        destination_ip: str,
        timestamp: Optional[str] = None,
        predicted_attack: str = "Unknown",
        obfuscation_detected: bool = False,
        extra: Optional[Dict[str, Any]] = None,
        enable_autoblock: bool = True,
        autoblock_fusion_threshold: Optional[float] = None,
        persist: bool = True,
    ) -> Dict[str, Any]:
        self._stats["fusion_events"] = int(self._stats.get("fusion_events", 0)) + 1
        ts = timestamp or time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        now_s = time.time()
        src_ip = (source_ip or "").strip()
        dst_ip = (destination_ip or "").strip()

        rf = self.rf_predict(feature_vector)
        self._stats["ae_predictions"] = int(self._stats.get("ae_predictions", 0)) + 1
        ae_out = self.ae.score(feature_vector, top_k=5)

        rf_prob = self._clamp01(_safe_float(rf.get("malicious_probability", 0.0)))
        ae_score_raw = _safe_float(ae_out.get("anomaly_score", 0.0))
        ae_score = self._normalize_ae(ae_score_raw)
        w_rf = _safe_float(self.weights.get("random_forest", 0.7), 0.7)
        w_ae = _safe_float(self.weights.get("autoencoder", 0.3), 0.3)
        w_obf = 0.0
        obf_norm = 0.0
        if obfuscation_detected:
            w_obf = 0.1
            obf_norm = 1.0

        denom = (w_rf + w_ae + w_obf) if (w_rf + w_ae + w_obf) > 0 else 1.0
        fusion_raw = float((rf_prob * w_rf + ae_score * w_ae + obf_norm * w_obf) / denom)
        fusion_raw = self._clamp01(fusion_raw)

        ema_prev = self._src_fusion_ema.get(src_ip, fusion_raw)
        fusion_score = float((self._ema_alpha * fusion_raw) + ((1.0 - self._ema_alpha) * float(ema_prev)))
        fusion_score = self._clamp01(fusion_score)
        if src_ip:
            self._src_fusion_ema[src_ip] = fusion_score

        repeats = self._repeats_in_window(src_ip, now_s, window_s=60.0)

        base_event = {
            "timestamp": ts,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "predicted_attack": predicted_attack,
            "random_forest_confidence": _safe_float(rf.get("confidence", 0.0)),
            "random_forest_probability": rf_prob,
            "autoencoder_score": ae_score,
            "reconstruction_error": _safe_float(ae_out.get("reconstruction_error", 0.0)),
            "fusion_score": fusion_score,
            "obfuscation_detected": bool(obfuscation_detected),
            "top_contributing_features": ae_out.get("top_contributing_features", []),
        }

        base_event = self.device_mapper.enrich(base_event, dst_ip_field="destination_ip")
        if src_ip:
            try:
                src_meta = self.device_mapper.lookup(src_ip)
                if str(src_meta.get("match_kind", "")) == "exact":
                    base_event.setdefault("source_device_name", src_meta.get("device_name"))
                    base_event.setdefault("source_department", src_meta.get("department"))
                    base_event.setdefault("source_room", src_meta.get("room"))
                    base_event.setdefault("source_criticality", src_meta.get("criticality"))
                    base_event.setdefault("source_device_type", src_meta.get("device_type"))
                    base_event.setdefault("source_vendor", src_meta.get("vendor"))
            except Exception:
                pass
        severity = self._severity(
            fusion_score=fusion_score,
            obfuscation_detected=bool(obfuscation_detected),
            repeats=repeats,
            criticality=base_event.get("criticality", "unknown"),
        )

        already_blocked = self.response.is_blocked(src_ip) if src_ip else False
        action = self._recommended_action(severity, already_blocked)
        base_event["severity"] = severity
        if not enable_autoblock and action == "BLOCK_IP":
            base_event["recommended_action"] = "INVESTIGATE"
        else:
            base_event["recommended_action"] = action

        if extra:
            for k, v in extra.items():
                if k not in base_event:
                    base_event[k] = v

        blocked_result = None
        allow_block = bool(enable_autoblock)
        if autoblock_fusion_threshold is not None:
            try:
                allow_block = allow_block and float(fusion_score) >= float(autoblock_fusion_threshold)
            except Exception:
                allow_block = allow_block

        if action == "BLOCK_IP" and src_ip and allow_block:
            blocked_result = self.response.block_ip(src_ip, duration_seconds=3600, reason=f"severity={severity}")
            base_event["auto_blocked"] = bool(blocked_result.get("ok"))
        else:
            base_event["auto_blocked"] = False

        if persist:
            self.store.append("detections", base_event)
            if base_event.get("severity") in {"HIGH", "CRITICAL"}:
                self.store.append("alerts", base_event)
            if blocked_result and blocked_result.get("ok"):
                self.store.append("blocked", {"ip": src_ip, "ts": ts, "reason": blocked_result.get("reason", "")})

        return base_event
