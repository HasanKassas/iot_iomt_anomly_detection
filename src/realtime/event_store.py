import json
import os
import threading
import time
from typing import Any, Dict, List, Optional


class EventStore:
    def __init__(self, path: str = "logs/event_store.json", max_events: int = 5000):
        self.path = path
        self.max_events = int(max_events)
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)

    def _read(self) -> Dict[str, Any]:
        if not os.path.isfile(self.path):
            return {"detections": [], "alerts": [], "blocked": [], "false_positives": []}
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f) or {}
            for k in ["detections", "alerts", "blocked", "false_positives"]:
                if k not in data or not isinstance(data[k], list):
                    data[k] = []
            return data
        except Exception:
            return {"detections": [], "alerts": [], "blocked": [], "false_positives": []}

    def _write(self, data: Dict[str, Any]) -> None:
        tmp = f"{self.path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self.path)

    def append(self, kind: str, item: Dict[str, Any]) -> None:
        kind = str(kind)
        if kind not in {"detections", "alerts", "blocked", "false_positives"}:
            return
        with self._lock:
            data = self._read()
            payload = dict(item or {})
            payload.setdefault("stored_at", time.time())
            data[kind].append(payload)
            if len(data[kind]) > self.max_events:
                data[kind] = data[kind][-self.max_events :]
            self._write(data)

    def get(self, kind: str, limit: int = 200) -> List[Dict[str, Any]]:
        kind = str(kind)
        if kind not in {"detections", "alerts", "blocked", "false_positives"}:
            return []
        limit = max(1, min(int(limit), self.max_events))
        with self._lock:
            data = self._read()
            arr = data.get(kind, [])
            return list(arr[-limit:])

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return self._read()

