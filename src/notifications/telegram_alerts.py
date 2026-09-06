import os
import time
from typing import Any, Dict, Optional

import requests


class TelegramAlerter:
    @staticmethod
    def _env_first(*names: str) -> str:
        for n in names:
            v = (os.getenv(n) or "").strip()
            if v:
                return v
        
        # Fallback to reading .env file manually
        try:
            if os.path.exists(".env"):
                with open(".env", "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "=" in line:
                            k, v = line.split("=", 1)
                            if k.strip() in names:
                                return v.strip().strip("'").strip('"')
        except Exception:
            pass
            
        return ""

    def __init__(
        self,
        bot_token: Optional[str] = None,
        chat_id: Optional[str] = None,
        min_interval_seconds: int = 10,
        dedupe_window_seconds: int = 300,
        timeout_seconds: int = 8,
        max_retries: int = 3,
    ):
        self.bot_token = (bot_token or "").strip() or self._env_first("TELEGRAM_BOT_TOKEN", "TG_BOT_TOKEN", "TELEGRAM_TOKEN", "BOT_TOKEN")
        self.chat_id = (chat_id or "").strip() or self._env_first("TELEGRAM_CHAT_ID", "TG_CHAT_ID", "TELEGRAM_CHAT", "CHAT_ID")
        try:
            min_interval_seconds = int(os.getenv("TELEGRAM_MIN_INTERVAL_SECONDS", str(int(min_interval_seconds))))
        except Exception:
            min_interval_seconds = int(min_interval_seconds)
        try:
            dedupe_window_seconds = int(os.getenv("TELEGRAM_DEDUPE_SECONDS", str(int(dedupe_window_seconds))))
        except Exception:
            dedupe_window_seconds = int(dedupe_window_seconds)
        try:
            timeout_seconds = int(os.getenv("TELEGRAM_TIMEOUT_SECONDS", str(int(timeout_seconds))))
        except Exception:
            timeout_seconds = int(timeout_seconds)
        try:
            max_retries = int(os.getenv("TELEGRAM_MAX_RETRIES", str(int(max_retries))))
        except Exception:
            max_retries = int(max_retries)

        self.min_interval_seconds = int(min_interval_seconds)
        self.dedupe_window_seconds = int(dedupe_window_seconds)
        self.timeout_seconds = int(timeout_seconds)
        self.max_retries = int(max_retries)

        self._last_sent_at = 0.0
        self._dedupe: Dict[str, float] = {}

    def _key(self, payload: Dict[str, Any]) -> str:
        src = str(payload.get("source_ip", "")).strip()
        return src

    def _format_message(self, payload: Dict[str, Any]) -> str:
        sev = str(payload.get("severity", "UNKNOWN")).upper()
        attack = str(payload.get("predicted_attack", "Unknown"))
        src = str(payload.get("source_ip", ""))
        dst = str(payload.get("destination_ip", ""))
        dev = str(payload.get("device_name", "Unknown Device"))
        dept = str(payload.get("department", "Unknown"))
        room = str(payload.get("room", "Unknown"))
        fusion = payload.get("fusion_score", None)
        conf = payload.get("random_forest_confidence", None)
        blocked = bool(payload.get("auto_blocked", False))

        fusion_pct = ""
        if fusion is not None:
            try:
                fusion_pct = f"{float(fusion) * 100:.1f}%"
            except Exception:
                fusion_pct = ""

        conf_pct = ""
        if conf is not None:
            try:
                conf_pct = f"{float(conf) * 100:.1f}%"
            except Exception:
                conf_pct = ""

        action = "IP BLOCKED" if blocked else str(payload.get("recommended_action", "INVESTIGATE"))

        lines = [
            f"🚨 {sev} ALERT",
            f"Attack: {attack}",
            f"Source: {src}",
            f"Destination: {dst}",
            f"Target Device: {dev}",
            f"Department: {dept}",
            f"Room: {room}",
        ]
        if fusion_pct:
            lines.append(f"Fusion Confidence: {fusion_pct}")
        if conf_pct:
            lines.append(f"RF Confidence: {conf_pct}")
        lines.append(f"Action Taken: {action}")
        return "\n".join(lines)

    def send(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not self.bot_token:
            self.bot_token = self._env_first("TELEGRAM_BOT_TOKEN", "TG_BOT_TOKEN", "TELEGRAM_TOKEN", "BOT_TOKEN")
        if not self.chat_id:
            self.chat_id = self._env_first("TELEGRAM_CHAT_ID", "TG_CHAT_ID", "TELEGRAM_CHAT", "CHAT_ID")
        if not self.bot_token or not self.chat_id:
            return {"ok": False, "error": "telegram_env_missing"}

        now = time.time()
        if now - self._last_sent_at < self.min_interval_seconds:
            return {"ok": False, "error": "rate_limited"}

        k = self._key(payload)
        if not k:
            return {"ok": False, "error": "missing_source_ip"}
        prev = self._dedupe.get(k)
        if prev is not None and now - prev < self.dedupe_window_seconds:
            return {"ok": False, "error": "duplicate_suppressed"}

        if len(self._dedupe) > 5000:
            try:
                cutoff = now - float(self.dedupe_window_seconds)
                self._dedupe = {kk: vv for kk, vv in self._dedupe.items() if float(vv) >= cutoff}
            except Exception:
                self._dedupe = {}

        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        text = self._format_message(payload)
        data = {"chat_id": self.chat_id, "text": text}

        last_err = None
        for attempt in range(max(1, self.max_retries)):
            try:
                r = requests.post(url, data=data, timeout=self.timeout_seconds)
                if r.status_code == 200:
                    self._last_sent_at = now
                    self._dedupe[k] = now
                    return {"ok": True}
                last_err = f"http_{r.status_code}:{r.text}"
            except Exception as exc:
                last_err = str(exc)
            time.sleep(0.5 * (attempt + 1))

        return {"ok": False, "error": last_err or "send_failed"}
