import json
import os
import subprocess
import time
import logging
import multiprocessing as mp
import queue as _queue
import ipaddress
import socket
from typing import Any, Dict, Optional


logger = logging.getLogger(__name__)
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s - %(message)s")


def _autoblock_worker_main(req_q: Any, blocked_path: str, history_path: str) -> None:
    try:
        ar = ActiveResponse(blocked_path=blocked_path, history_path=history_path, isolate_process=False)
        while True:
            try:
                msg = req_q.get(timeout=0.25)
            except Exception:
                continue
            if msg is None:
                return
            if not isinstance(msg, dict):
                continue
            op = str(msg.get("op") or "")
            ip = str(msg.get("ip") or "")
            if op == "block":
                try:
                    ar.block_ip(ip, duration_seconds=msg.get("duration_seconds"), reason=str(msg.get("reason") or ""))
                except Exception:
                    logger.exception("autoblock_subprocess_crashed")
            elif op == "unblock":
                try:
                    ar.unblock_ip(ip, operator=str(msg.get("operator") or ""), notes=str(msg.get("notes") or ""))
                except Exception:
                    logger.exception("autoblock_subprocess_crashed")
    except Exception:
        logger.exception("autoblock_subprocess_crashed")


class ActiveResponse:
    def __init__(
        self,
        blocked_path: str = "logs/blocked_ips.json",
        history_path: str = "logs/response_history.json",
        isolate_process: Optional[bool] = None,
    ):
        self.blocked_path = blocked_path
        self.history_path = history_path
        os.makedirs(os.path.dirname(self.blocked_path) or ".", exist_ok=True)
        os.makedirs(os.path.dirname(self.history_path) or ".", exist_ok=True)
        if isolate_process is None:
            isolate_process = os.getenv("LIVE_AUTOBLOCK_ISOLATE_PROCESS", "1") == "1"
        self._isolate_process = bool(isolate_process)
        self._mp_ctx = None
        self._mp_q = None
        self._mp_proc = None

    def _ensure_worker(self) -> None:
        if self._mp_proc is not None and getattr(self._mp_proc, "is_alive", lambda: False)():
            return
        try:
            self._mp_ctx = mp.get_context("spawn") if os.name == "nt" else mp.get_context()
        except Exception:
            self._mp_ctx = mp
        try:
            self._mp_q = self._mp_ctx.Queue(maxsize=int(os.getenv("LIVE_AUTOBLOCK_QUEUE_MAX", "2000")))
        except Exception:
            self._mp_q = self._mp_ctx.Queue()
        self._mp_proc = self._mp_ctx.Process(
            target=_autoblock_worker_main,
            args=(self._mp_q, self.blocked_path, self.history_path),
            daemon=True,
            name="autoblock_subprocess",
        )
        self._mp_proc.start()
        try:
            logger.info("runtime_identity component=autoblock_subprocess pid=%d", int(getattr(self._mp_proc, "pid", 0) or 0))
        except Exception:
            pass

    def _read_json(self, path: str, default: Any) -> Any:
        if not os.path.isfile(path):
            return default
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return default

    def _write_json(self, path: str, data: Any) -> None:
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)

    def _rule_name(self, ip: str) -> str:
        return f"IOMT_BLOCK_{ip}"

    def _is_windows(self) -> bool:
        return os.name == "nt"

    def _is_protected_ip(self, ip: str) -> bool:
        ip = str(ip or "").strip()
        if not ip:
            return True
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_loopback:
                return True
            if addr.is_multicast or addr.is_unspecified or addr.is_reserved or addr.is_link_local:
                return True
        except Exception:
            return True

        protect = set()
        protect.add("127.0.0.1")
        try:
            host = socket.gethostname()
            for v in socket.gethostbyname_ex(host)[2]:
                protect.add(str(v))
        except Exception:
            pass
        try:
            api_url = str(os.getenv("IOMT_API_URL", "") or "").strip()
            if api_url:
                h = api_url.replace("https://", "").replace("http://", "").split("/", 1)[0]
                h = h.split(":", 1)[0].strip()
                if h:
                    protect.add(str(socket.gethostbyname(h)))
        except Exception:
            pass

        if ip in protect:
            return True
        return False

    def _block_windows_firewall(self, ip: str) -> Dict[str, Any]:
        rule = self._rule_name(ip)
        timeout_s = 3.0
        try:
            timeout_s = float(os.getenv("LIVE_AUTOBLOCK_CMD_TIMEOUT_S", "3.0") or 3.0)
        except Exception:
            timeout_s = 3.0
        timeout_s = max(0.5, min(timeout_s, 30.0))
        cmd = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule}",
            "dir=in",
            "action=block",
            f"remoteip={ip}",
        ]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=float(timeout_s))
            return {"ok": p.returncode == 0, "stdout": p.stdout, "stderr": p.stderr, "rule": rule, "timeout_s": float(timeout_s)}
        except subprocess.TimeoutExpired:
            return {"ok": False, "stdout": "", "stderr": "timeout", "rule": rule, "timeout_s": float(timeout_s)}

    def _unblock_windows_firewall(self, ip: str) -> Dict[str, Any]:
        rule = self._rule_name(ip)
        timeout_s = 3.0
        try:
            timeout_s = float(os.getenv("LIVE_AUTOBLOCK_CMD_TIMEOUT_S", "3.0") or 3.0)
        except Exception:
            timeout_s = 3.0
        timeout_s = max(0.5, min(timeout_s, 30.0))
        cmd = [
            "netsh",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            f"name={rule}",
        ]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=float(timeout_s))
            return {"ok": p.returncode == 0, "stdout": p.stdout, "stderr": p.stderr, "rule": rule, "timeout_s": float(timeout_s)}
        except subprocess.TimeoutExpired:
            return {"ok": False, "stdout": "", "stderr": "timeout", "rule": rule, "timeout_s": float(timeout_s)}

    def _append_history(self, entry: Dict[str, Any]) -> None:
        hist = self._read_json(self.history_path, [])
        if not isinstance(hist, list):
            hist = []
        hist.append(entry)
        if len(hist) > 10000:
            hist = hist[-5000:]
        self._write_json(self.history_path, hist)

    def is_blocked(self, ip: str) -> bool:
        ip = (ip or "").strip()
        data = self._read_json(self.blocked_path, {})
        if not isinstance(data, dict):
            return False
        entry = data.get(ip)
        if not isinstance(entry, dict):
            return False
        exp = entry.get("expires_at")
        if exp is None:
            return True
        try:
            return float(exp) > time.time()
        except Exception:
            return True

    def block_ip(self, ip: str, duration_seconds: Optional[int] = None, reason: str = "") -> Dict[str, Any]:
        ip = (ip or "").strip()
        if not ip:
            return {"ok": False, "error": "ip_required"}
        if self._is_protected_ip(ip):
            return {"ok": False, "error": "protected_ip", "ip": ip}
        if self._isolate_process:
            try:
                self._ensure_worker()
                self._mp_q.put_nowait({"op": "block", "ip": ip, "duration_seconds": duration_seconds, "reason": reason})
                return {"ok": True, "queued": True, "ip": ip, "worker_pid": int(getattr(self._mp_proc, "pid", 0) or 0)}
            except _queue.Full:
                return {"ok": False, "error": "autoblock_queue_full", "ip": ip}
            except Exception as exc:
                return {"ok": False, "error": str(exc), "ip": ip}
        now = time.time()
        expires_at = None
        if duration_seconds is not None:
            try:
                expires_at = now + max(1, int(duration_seconds))
            except Exception:
                expires_at = None

        blocked = self._read_json(self.blocked_path, {})
        if not isinstance(blocked, dict):
            blocked = {}

        if ip in blocked and self.is_blocked(ip):
            return {"ok": True, "already_blocked": True, "ip": ip}

        fw = {"ok": True, "backend": "noop"}
        if self._is_windows():
            try:
                fw = self._block_windows_firewall(ip)
                fw["backend"] = "windows_firewall"
            except Exception as exc:
                fw = {"ok": False, "backend": "windows_firewall", "error": str(exc)}

        blocked[ip] = {
            "ip": ip,
            "blocked_at": now,
            "expires_at": expires_at,
            "reason": reason,
            "firewall": fw,
        }
        self._write_json(self.blocked_path, blocked)
        self._append_history({"action": "block", "ip": ip, "ts": now, "reason": reason, "result": fw})
        return {"ok": True, "ip": ip, "expires_at": expires_at, "firewall": fw}

    def unblock_ip(self, ip: str, operator: str = "", notes: str = "") -> Dict[str, Any]:
        ip = (ip or "").strip()
        if not ip:
            return {"ok": False, "error": "ip_required"}
        if self._isolate_process:
            try:
                self._ensure_worker()
                self._mp_q.put_nowait({"op": "unblock", "ip": ip, "operator": operator, "notes": notes})
                return {"ok": True, "queued": True, "ip": ip, "worker_pid": int(getattr(self._mp_proc, "pid", 0) or 0)}
            except _queue.Full:
                return {"ok": False, "error": "autoblock_queue_full", "ip": ip}
            except Exception as exc:
                return {"ok": False, "error": str(exc), "ip": ip}
        now = time.time()

        blocked = self._read_json(self.blocked_path, {})
        if not isinstance(blocked, dict):
            blocked = {}

        fw = {"ok": True, "backend": "noop"}
        if self._is_windows():
            try:
                fw = self._unblock_windows_firewall(ip)
                fw["backend"] = "windows_firewall"
            except Exception as exc:
                fw = {"ok": False, "backend": "windows_firewall", "error": str(exc)}

        existed = ip in blocked
        if existed:
            blocked.pop(ip, None)
            self._write_json(self.blocked_path, blocked)

        self._append_history(
            {
                "action": "unblock",
                "ip": ip,
                "ts": now,
                "operator": operator,
                "notes": notes,
                "result": fw,
                "marked_false_positive": True,
            }
        )
        return {"ok": True, "ip": ip, "existed": existed, "firewall": fw}
