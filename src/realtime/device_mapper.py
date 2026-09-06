import json
import os
import ipaddress
import logging
from typing import Any, Dict, Optional


logger = logging.getLogger(__name__)


class DeviceMapper:
    def __init__(self, registry_path: str = "config/device_registry.json"):
        self.registry_path = registry_path
        self._registry: Dict[str, Dict[str, Any]] = {}
        self._subnet_index: Dict[str, Dict[str, Any]] = {}
        self.reload()

    def reload(self) -> None:
        self._registry = {}
        self._subnet_index = {}
        if not os.path.isfile(self.registry_path):
            return
        try:
            with open(self.registry_path, "r", encoding="utf-8") as f:
                data = json.load(f) or {}
            if isinstance(data, dict):
                for ip, meta in data.items():
                    if not isinstance(ip, str):
                        continue
                    if not isinstance(meta, dict):
                        continue
                    ip_n = self._normalize_ip(ip)
                    if ip_n:
                        self._registry[ip_n] = meta
            self._build_subnet_index()
        except Exception:
            self._registry = {}
            self._subnet_index = {}

    def _build_subnet_index(self) -> None:
        idx: Dict[str, Dict[str, Any]] = {}
        for ip, meta in (self._registry or {}).items():
            try:
                addr = ipaddress.ip_address(ip)
            except Exception:
                continue
            if not addr.is_private:
                continue
            try:
                net = ipaddress.ip_network(f"{ip}/24", strict=False)
            except Exception:
                continue
            key = str(net)
            if key not in idx:
                idx[key] = {
                    "device_name": "Unregistered Hospital Device",
                    "department": meta.get("department", "Hospital"),
                    "room": "-",
                    "criticality": "medium",
                }
        self._subnet_index = idx

    def registered_ips(self) -> Dict[str, Dict[str, Any]]:
        return dict(self._registry or {})

    def _normalize_ip(self, ip: str) -> str:
        s = (ip or "").strip()
        if not s:
            return ""
        try:
            return str(ipaddress.ip_address(s))
        except Exception:
            return s

    def lookup(self, ip: str) -> Dict[str, Any]:
        ip_n = self._normalize_ip(ip)
        meta = self._registry.get(ip_n) or self._registry.get((ip or "").strip()) or {}
        match_kind = "exact" if meta else ""

        if not meta:
            try:
                addr = ipaddress.ip_address(ip_n)
                if addr.is_private:
                    for net_s, m in (self._subnet_index or {}).items():
                        try:
                            net = ipaddress.ip_network(net_s, strict=False)
                        except Exception:
                            continue
                        if addr in net:
                            meta = m or {}
                            match_kind = "subnet_fallback"
                            break
            except Exception:
                meta = {}

        device_type = meta.get("device_type") or meta.get("type")
        if not device_type:
            if match_kind == "exact":
                device_type = "Registered Hospital Device"
            elif match_kind == "subnet_fallback":
                device_type = "Unknown Internal Device"
            else:
                device_type = "External Device"
        vendor = meta.get("vendor") or meta.get("manufacturer") or ""

        out = {
            "device_name": meta.get("device_name", "External Device" if match_kind == "" else "Unknown Internal Device"),
            "department": meta.get("department", "Unknown"),
            "room": meta.get("room", "Unknown"),
            "criticality": meta.get("criticality", "unknown"),
            "device_type": device_type,
            "vendor": vendor,
            "match_kind": match_kind or "none",
        }
        if os.getenv("DEBUG_LIVE", "0") == "1" or os.getenv("DEBUG_DEVICE_MAP", "0") == "1":
            if match_kind == "exact":
                logger.info("device_match_success ip=%s name=%s", str(ip_n), str(out.get("device_name")))
            elif match_kind == "subnet_fallback":
                logger.info("device_match_fallback ip=%s name=%s", str(ip_n), str(out.get("device_name")))
            else:
                logger.info("device_match_failed ip=%s", str(ip_n))
        return out

    def enrich(self, event: Dict[str, Any], dst_ip_field: str = "destination_ip") -> Dict[str, Any]:
        out = dict(event or {})
        dst_ip = out.get(dst_ip_field) or out.get("dst_ip") or out.get("destination_ip") or ""
        meta = self.lookup(str(dst_ip))
        out.setdefault("device_name", meta["device_name"])
        out.setdefault("department", meta["department"])
        out.setdefault("room", meta["room"])
        out.setdefault("criticality", meta["criticality"])
        out.setdefault("device_type", meta.get("device_type"))
        out.setdefault("vendor", meta.get("vendor"))
        out.setdefault("device_match_kind", meta.get("match_kind"))
        return out
