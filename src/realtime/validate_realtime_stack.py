import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple

import requests
import websocket


def _api_url() -> str:
    return os.getenv("IOMT_API_URL", "http://localhost:3001").rstrip("/")


def _ws_url(api_url: str) -> str:
    u = (api_url or "").strip()
    if u.startswith("https://"):
        u = "wss://" + u[len("https://") :]
    elif u.startswith("http://"):
        u = "ws://" + u[len("http://") :]
    return u.rstrip("/") + "/ws"


def _wait_for(ws, want_types: Tuple[str, ...], timeout_s: float = 4.0) -> Optional[Dict[str, Any]]:
    end = time.time() + float(timeout_s)
    while time.time() < end:
        try:
            raw = ws.recv()
        except websocket.WebSocketTimeoutException:
            continue
        if not raw:
            continue7
        try:
            msg = json.loads(raw)
        except Exception:
            continue
        if isinstance(msg, dict) and msg.get("type") in want_types:
            return msg
    return None


def _post(url: str, path: str, payload: Dict[str, Any], timeout_s: float = 2.0) -> Tuple[bool, int, str, float]:
    t0 = time.perf_counter()
    try:
        r = requests.post(f"{url}{path}", json=payload, timeout=timeout_s)
        ms = (time.perf_counter() - t0) * 1000.0
        txt = ""
        try:
            txt = r.text[:200]
        except Exception:
            txt = ""
        return bool(r.ok), int(r.status_code), txt, float(ms)
    except Exception as exc:
        ms = (time.perf_counter() - t0) * 1000.0
        return False, 0, str(exc), float(ms)


def main() -> int:
    api = _api_url()
    ws_u = _ws_url(api)
    rows: List[Tuple[str, str]] = []

    try:
        r = requests.get(f"{api}/health", timeout=1.5)
        rows.append(("API /health", "PASS" if r.ok else f"FAIL status={r.status_code}"))
        if not r.ok:
            print("\n".join([f"{k}: {v}" for k, v in rows]))
            return 2
    except Exception as exc:
        rows.append(("API /health", f"FAIL {exc}"))
        print("\n".join([f"{k}: {v}" for k, v in rows]))
        return 2

    ws = None
    try:
        ws = websocket.create_connection(ws_u, timeout=3)
        ws.settimeout(1)
        init = _wait_for(ws, ("init",), timeout_s=4.0)
        rows.append(("Websocket connect", "PASS" if init else "FAIL no_init"))
        if not init:
            print("\n".join([f"{k}: {v}" for k, v in rows]))
            return 2
    except Exception as exc:
        rows.append(("Websocket connect", f"FAIL {exc}"))
        print("\n".join([f"{k}: {v}" for k, v in rows]))
        return 2

    ok, code, txt, ms = _post(
        api,
        "/live/settings",
        {
            "autoblock_enabled": False,
            "telegram_enabled": False,
            "alert_fusion_threshold": 0.92,
            "autoblock_fusion_threshold": 0.98,
            "alert_threshold": 0.92,
            "autoblock_threshold": 0.98,
        },
        timeout_s=2.0,
    )
    rows.append(("POST /live/settings", "PASS" if ok else f"FAIL status={code} {txt}"))
    msg = _wait_for(ws, ("settings",), timeout_s=3.0)
    rows.append(("WS settings broadcast", "PASS" if msg else "FAIL"))

    ok, code, txt, ms = _post(api, "/live/heartbeat", {"engine_online": True, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())}, timeout_s=2.0)
    rows.append(("POST /live/heartbeat", "PASS" if ok else f"FAIL status={code} {txt}"))
    msg = _wait_for(ws, ("heartbeat",), timeout_s=3.0)
    rows.append(("WS heartbeat broadcast", "PASS" if msg else "FAIL"))

    det = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
        "source_ip": "192.168.100.50",
        "destination_ip": "192.168.100.10",
        "predicted_attack": "validate_realtime_stack",
        "random_forest_confidence": 0.8,
        "autoencoder_score": 0.7,
        "fusion_score": 0.9,
        "severity": "HIGH",
        "obfuscation_detected": False,
        "recommended_action": "INVESTIGATE",
        "auto_blocked": False,
    }
    ok, code, txt, ms = _post(api, "/api/detections", det, timeout_s=2.0)
    rows.append(("POST /api/detections", "PASS" if ok else f"FAIL status={code} {txt}"))
    msg = _wait_for(ws, ("detection",), timeout_s=3.0)
    rows.append(("WS detection broadcast", "PASS" if msg else "FAIL"))

    tlm = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()), "packets_per_sec": 0, "flows_per_sec": 0}
    ok, code, txt, ms = _post(api, "/live/telemetry", tlm, timeout_s=2.0)
    rows.append(("POST /live/telemetry", "PASS" if ok else f"FAIL status={code} {txt}"))
    msg = _wait_for(ws, ("telemetry",), timeout_s=3.0)
    rows.append(("WS telemetry broadcast", "PASS" if msg else "FAIL"))

    try:
        ws.close()
    except Exception:
        pass

    width = max(len(k) for k, _ in rows) if rows else 10
    for k, v in rows:
        print(k.ljust(width), v)

    all_pass = all(v.startswith("PASS") for _k, v in rows)
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())

