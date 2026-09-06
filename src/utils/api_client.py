import os
import time
import requests


def _base_url():
    return os.getenv("IOMT_API_URL", "http://localhost:3001").rstrip("/")


def post_json(path, payload, timeout_s=2):
    url = f"{_base_url()}{path}"
    try:
        requests.post(url, json=payload, timeout=timeout_s)
    except Exception:
        return


def post_json_verbose(path, payload, timeout_s=2):
    url = f"{_base_url()}{path}"
    t0 = time.perf_counter()
    try:
        resp = requests.post(url, json=payload, timeout=timeout_s)
        ms = (time.perf_counter() - t0) * 1000.0
        txt = ""
        try:
            txt = resp.text[:500]
        except Exception:
            txt = ""
        return {"ok": bool(resp.ok), "status_code": int(resp.status_code), "response_text": txt, "latency_ms": float(ms)}
    except Exception as exc:
        ms = (time.perf_counter() - t0) * 1000.0
        return {"ok": False, "status_code": 0, "response_text": str(exc), "latency_ms": float(ms)}


def get_json(path, timeout_s=2):
    url = f"{_base_url()}{path}"
    resp = requests.get(url, timeout=timeout_s)
    resp.raise_for_status()
    return resp.json()


def get_json_verbose(path, timeout_s=2):
    url = f"{_base_url()}{path}"
    t0 = time.perf_counter()
    try:
        resp = requests.get(url, timeout=timeout_s)
        ms = (time.perf_counter() - t0) * 1000.0
        txt = ""
        try:
            txt = resp.text[:500]
        except Exception:
            txt = ""
        data = None
        try:
            data = resp.json()
        except Exception:
            data = None
        return {"ok": bool(resp.ok), "status_code": int(resp.status_code), "response_text": txt, "latency_ms": float(ms), "json": data}
    except Exception as exc:
        ms = (time.perf_counter() - t0) * 1000.0
        return {"ok": False, "status_code": 0, "response_text": str(exc), "latency_ms": float(ms), "json": None}
