import os
import time
import logging
import ipaddress
import traceback
import queue
import threading
import sys
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import uuid

try:
    import numpy as np
    import requests
except Exception as exc:
    sys.stderr.write(
        "Missing Python dependencies for the detector.\n"
        "Create a virtual environment and install requirements:\n"
        "  python -m venv .venv\n"
        "  .\\.venv\\Scripts\\Activate.ps1\n"
        "  pip install -r requirements.txt\n"
        f"Error: {exc}\n"
    )
    raise SystemExit(1)

from src.notifications.telegram_alerts import TelegramAlerter
from src.realtime.fusion_engine import FusionEngine
from src.realtime.live_feature_extractor import LiveFeatureExtractor
from src.realtime.live_flow_builder import LiveFlowBuilder
from src.realtime.live_monitor import LiveMonitorConfig, LivePacketMonitor, install_signal_handlers
from src.utils.api_client import get_json, get_json_verbose, post_json_verbose


logger = logging.getLogger(__name__)
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s - %(message)s")


@dataclass
class LiveEngineConfig:
    flow_timeout_seconds: float = 10.0
    max_packets_per_flow: int = 2000
    max_active_flows: int = 50000
    flush_interval_seconds: float = 1.0
    enable_telegram: bool = True
    enable_autoblock: bool = True
    autoblock_fusion_threshold: float = 0.98
    alert_fusion_threshold: float = 0.92
    ws_telemetry_interval_seconds: float = 1.0
    settings_refresh_seconds: float = 2.0
    packet_batch_size: int = 512
    restrict_to_device_network: bool = True
    min_packets_for_model: int = 3
    min_bytes_for_model: int = 200
    detection_publish_threshold: float = 0.5
    per_ip_alert_cooldown_seconds: float = 20.0
    per_ip_block_cooldown_seconds: float = 120.0
    queue_high_watermark_ratio: float = 0.9
    attack_test_mode: bool = False
    heuristic_window_seconds: float = 10.0
    syn_scan_unique_ports_threshold: int = 15
    lab_mode: bool = False
    low_severity_publish: bool = False
    low_suppression_fusion_max: float = 0.55
    heartbeat_interval_seconds: float = 5.0


class LiveDetectionEngine:
    def __init__(self, monitor: LivePacketMonitor, config: LiveEngineConfig):
        self.monitor = monitor
        self.config = config
        self.flow_builder = LiveFlowBuilder(
            flow_timeout_seconds=float(config.flow_timeout_seconds),
            max_packets_per_flow=int(config.max_packets_per_flow),
            max_active_flows=int(config.max_active_flows),
        )
        self.features = LiveFeatureExtractor()
        self.fusion = FusionEngine()
        try:
            def _env_first(*names: str) -> str:
                for n in names:
                    v = (os.getenv(n) or "").strip()
                    if v:
                        return v
                try:
                    if os.path.exists(".env"):
                        with open(".env", "r", encoding="utf-8") as f:
                            for line in f:
                                line = line.strip()
                                if not line or line.startswith("#"): continue
                                if "=" in line:
                                    k, v = line.split("=", 1)
                                    if k.strip() in names:
                                        return v.strip().strip("'").strip('"')
                except Exception:
                    pass
                return ""

            tg_token = _env_first("TELEGRAM_BOT_TOKEN", "TG_BOT_TOKEN", "TELEGRAM_TOKEN", "BOT_TOKEN")
            tg_chat = _env_first("TELEGRAM_CHAT_ID", "TG_CHAT_ID", "TELEGRAM_CHAT", "CHAT_ID")
            self.alerter = TelegramAlerter(bot_token=tg_token or None, chat_id=tg_chat or None)

            if os.getenv("LIVE_TELEGRAM", "1") == "1" and tg_token and tg_chat:
                self.config.enable_telegram = True
        except Exception:
            self.alerter = TelegramAlerter()
            pass
        try:
            self._telegram_forced = bool(
                os.getenv("LIVE_TELEGRAM", "1") == "1"
                and bool((getattr(self.alerter, "bot_token", "") or "").strip())
                and bool((getattr(self.alerter, "chat_id", "") or "").strip())
            )
        except Exception:
            self._telegram_forced = False

        self.debug = os.getenv("DEBUG_LIVE", "0") == "1"
        self.debug_sample_every = max(1, int(os.getenv("DEBUG_LIVE_SAMPLE_EVERY", "50")))

        self.packets_seen = 0
        self.flows_completed = 0
        self.dropped_packets = 0
        self._last_telemetry_ts = time.time()
        self._last_pps = 0.0
        self._last_settings_fetch = 0.0
        self._last_counts: Tuple[int, int, int] = (0, 0, 0)
        self._lat_ms_ema = 0.0
        self._lat_ms_alpha = 0.15
        self._ip_state: Dict[str, Dict[str, Any]] = {}

        dev = self.fusion.device_mapper.registered_ips()
        self._device_ips = set(dev.keys())
        self._device_nets: List[ipaddress.IPv4Network] = []
        for ip in list(self._device_ips):
            try:
                addr = ipaddress.ip_address(ip)
            except Exception:
                continue
            if not addr.is_private:
                continue
            try:
                self._device_nets.append(ipaddress.ip_network(f"{ip}/24", strict=False))
            except Exception:
                continue

        self._ignored_non_device = 0
        self._ignored_small_flow = 0
        self._suppressed_cooldown = 0
        self._published_detections = 0
        self._published_alerts = 0
        self._published_blocks = 0
        self._last_stats_log = time.time()
        self._last_packet_seen_ts = time.time()

        self.counters: Dict[str, int] = {
            "packets_seen": 0,
            "packets_filtered": 0,
            "flows_created": 0,
            "flows_completed": 0,
            "feature_vectors_generated": 0,
            "rf_predictions": 0,
            "ae_predictions": 0,
            "fusion_events": 0,
            "detections_written": 0,
        }

        self._api_online = True
        self._api_last_health_ok = 0.0
        self._api_post_ok = 0
        self._api_post_failed = 0
        self._api_post_latency_ms_ema = 0.0
        self._api_post_latency_alpha = 0.2
        self._api_backlog: "deque[Dict[str, Any]]" = deque(maxlen=int(os.getenv("LIVE_API_BACKLOG_MAX", "2000")))

        self._post_q: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=int(os.getenv("LIVE_POST_QUEUE_MAX", "5000")))
        self._post_q_max = int(os.getenv("LIVE_POST_QUEUE_MAX", "5000"))
        self._telegram_q: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=int(os.getenv("LIVE_TG_QUEUE_MAX", "2000")))
        self._telegram_q_max = int(os.getenv("LIVE_TG_QUEUE_MAX", "2000"))
        self._block_q: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=int(os.getenv("LIVE_BLOCK_QUEUE_MAX", "2000")))
        self._block_q_max = int(os.getenv("LIVE_BLOCK_QUEUE_MAX", "2000"))

        self._workers_stop = threading.Event()
        self._executor = ThreadPoolExecutor(max_workers=int(os.getenv("LIVE_WORKERS", "4")))

        self.session_id = str(uuid.uuid4())
        self._start_time_s = time.time()

        self._hb_last_sent_s = 0.0
        self._hb_last_ack_s = 0.0
        self._hb_failures = 0
        self._hb_backoff_s = 1.0
        self._hb_interval_s = float(getattr(self.config, "heartbeat_interval_seconds", 5.0))
        self._hb_interval_s = max(1.0, min(self._hb_interval_s, 30.0))

        self._settings_version_remote = None
        self._settings_last_updated_remote = ""
        self._settings_last_applied_version = None
        self._settings_last_apply_s = 0.0
        self._settings_sync_failures = 0

        self._suppressed_total = 0

        self._replay_mode = os.getenv("LIVE_MODE", "").strip().lower() == "replay"
        self._replay_force_flush = os.getenv("LIVE_REPLAY_FORCE_FLUSH", "0") == "1"
        self._replay_force_complete_syn = os.getenv("LIVE_REPLAY_FORCE_COMPLETE_SYN", "0") == "1"
        self._replay_syn_threshold = max(1, int(os.getenv("LIVE_REPLAY_SYN_THRESHOLD", "1")))
        self._replay_last_ts = 0.0
        self._replay_flows_flushed = 0
        self._replay_force_completed = 0
        self._replay_syn_only_flows = 0
        self._replay_packets_loaded = 0
        self._replay_packets_enqueued = 0
        self._replay_packets_processed = 0
        self._replay_packets_dropped = 0
        self._replay_done = False
        self._replay_thread = None
        self._replay_pcap_path = (os.getenv("LIVE_REPLAY_PCAP") or "").strip()
        self._replay_speed = float(os.getenv("LIVE_REPLAY_SPEED", "1.0") or 1.0)
        self._replay_loop = os.getenv("LIVE_REPLAY_LOOP", "0") == "1"
        self._replay_max_sleep = float(os.getenv("LIVE_REPLAY_MAX_SLEEP", "2.0") or 2.0)
        self._replay_last_packet_ts = 0.0
        self._replay_last_processed_wall = 0.0
        self._replay_last_processed_count = 0
        self._replay_last_queue_nonempty = time.time()
        self._replay_start_wall = time.time()
        self._run_started = threading.Event()
        self._replay_self_test_thread = None
        self._replay_self_test_done = False
        self._consumer_thread_ident = None
        self._watchdog_thread = None
        self._stall_since_s = 0.0

        self._post_thread = threading.Thread(target=self._api_post_worker, name="api_post_worker", daemon=True)
        self._tg_thread = threading.Thread(target=self._telegram_worker, name="telegram_worker", daemon=True)
        self._blk_thread = threading.Thread(target=self._block_worker, name="autoblock_worker", daemon=True)
        self._health_thread = threading.Thread(target=self._health_worker, name="api_health_worker", daemon=True)
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_worker, name="heartbeat_worker", daemon=True)
        self._post_thread.start()
        self._tg_thread.start()
        self._blk_thread.start()
        self._health_thread.start()
        self._heartbeat_thread.start()

        self.sync_runtime_settings_to_api()
        if self._replay_mode:
            if os.getenv("LIVE_CLEAR_HISTORY_ON_START", "0") == "1":
                logger.info("replay_clear_history_on_start")
                self._enqueue_post("/live/settings", {"clear_history": True}, timeout_s=2.0, label="clear_history")
                try:
                    self._ip_state = {}
                except Exception:
                    pass
            self._start_replay_injector()
            self._start_replay_self_test()

    def _severity_from_score(self, fusion_score: float) -> str:
        try:
            s = float(fusion_score)
        except Exception:
            s = 0.0
        if not np.isfinite(s):
            s = 0.0
        if s > 1.0:
            return "CRITICAL"
        if s >= 0.7:
            return "HIGH"
        if s >= 0.4:
            return "MEDIUM"
        return "LOW"

    def _attack_kind_from_signals(self, obf: bool, heuristic_reason: str, obf_scores: Optional[Dict[str, Any]] = None) -> str:
        r = str(heuristic_reason or "").lower()
        if "syn_scan" in r:
            return "SYN_SCAN"
        if "fragmentation" in r:
            return "FRAGMENTATION"
        if "timing_jitter" in r:
            return "TIMING_JITTER"
        try:
            fs = float((obf_scores or {}).get("fragmentation_anomaly_score", 0.0) or 0.0)
        except Exception:
            fs = 0.0
        try:
            js = float((obf_scores or {}).get("timing_jitter_score", 0.0) or 0.0)
        except Exception:
            js = 0.0
        if fs >= 0.2:
            return "FRAGMENTATION"
        if js >= 0.8:
            return "TIMING_JITTER"
        if bool(obf):
            return "OBFUSCATION"
        if r:
            return "HEURISTIC"
        return "RF/AE Fusion"

    def sync_runtime_settings_to_api(self) -> None:
        payload = {
            "alert_fusion_threshold": float(self.config.alert_fusion_threshold),
            "autoblock_fusion_threshold": float(self.config.autoblock_fusion_threshold),
            "telegram_enabled": bool(self.config.enable_telegram),
            "autoblock_enabled": bool(self.config.enable_autoblock),
            "restrict_to_device_network": bool(self.config.restrict_to_device_network),
            "alert_threshold": float(self.config.alert_fusion_threshold),
            "autoblock_threshold": float(self.config.autoblock_fusion_threshold),
            "detector_session_id": self.session_id,
            "detector_last_updated": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
        }
        self._enqueue_post("/live/settings", payload, timeout_s=2.0, label="settings_sync")

    def _start_replay_injector(self) -> None:
        if self._replay_thread is not None and getattr(self._replay_thread, "is_alive", lambda: False)():
            return
        if not self._replay_pcap_path:
            logger.error("replay_fatal LIVE_REPLAY_PCAP not set")
            self.monitor.stop()
            self._replay_done = True
            return
        pcap_path = str(self._replay_pcap_path)
        try:
            if not os.path.exists(pcap_path):
                logger.error("replay_fatal pcap_missing path=%s", pcap_path)
                self._replay_done = True
                return
            size_b = int(os.path.getsize(pcap_path))
            if size_b <= 0:
                logger.error("replay_fatal pcap_size_zero path=%s", pcap_path)
                self._replay_done = True
                return
            with open(pcap_path, "rb") as f:
                _ = f.read(1)
            logger.info("replay_pcap_preflight_ok path=%s size_bytes=%d", pcap_path, int(size_b))
        except Exception:
            logger.exception("replay_fatal pcap_unreadable")
            self._replay_done = True
            return
        self._replay_thread = threading.Thread(target=self._replay_injector_worker, name="replay_injector", daemon=True)
        try:
            logger.info("packet_queue_identity role=injector id=%d", int(id(self.monitor.q)))
        except Exception:
            pass
        logger.info("replay_thread_started pcap=%s speed=%.3f loop=%s", str(self._replay_pcap_path), float(self._replay_speed), str(bool(self._replay_loop)))
        self._replay_thread.start()

    def _replay_injector_worker(self) -> None:
        try:
            logger.info("runtime_identity component=replay_injector pid=%d thread=%s", int(os.getpid()), threading.current_thread().name)
        except Exception:
            pass
        try:
            from scapy.utils import PcapReader
            from scapy.layers.inet import IP, TCP, UDP
        except Exception:
            logger.exception("replay_thread_crashed")
            self._replay_done = True
            return

        pcap_path = str(self._replay_pcap_path)
        speed = float(self._replay_speed)
        loop = bool(self._replay_loop)
        max_sleep = float(self._replay_max_sleep)

        def _sleep(delay_s: float) -> None:
            try:
                if delay_s <= 0:
                    return
                if max_sleep > 0:
                    time.sleep(min(delay_s, max_sleep))
                else:
                    time.sleep(delay_s)
            except Exception:
                logger.exception("replay_thread_crashed")
                raise

        try:
            while not self.monitor._stop.is_set():
                raw_pkts = []
                try:
                    with PcapReader(pcap_path) as pr:
                        for pkt in pr:
                            raw_pkts.append(pkt)
                except Exception:
                    logger.exception("replay_thread_crashed")
                    self._replay_done = True
                    return

                items: List[Dict[str, Any]] = []
                first_summary = None
                for pkt in raw_pkts:
                    if self.monitor._stop.is_set():
                        break
                    try:
                        if IP not in pkt:
                            continue
                        ip = pkt[IP]
                        proto = int(ip.proto or 0)
                        src_ip = str(ip.src)
                        dst_ip = str(ip.dst)
                        ttl = int(getattr(ip, "ttl", 0) or 0)
                        ip_id = int(getattr(ip, "id", 0) or 0)
                        ip_frag_offset = int(getattr(ip, "frag", 0) or 0)
                        ip_mf = 0
                        try:
                            ip_mf = 1 if bool(getattr(getattr(ip, "flags", None), "MF", False)) else 0
                        except Exception:
                            ip_mf = 0
                        src_port = 0
                        dst_port = 0
                        flags = ""
                        if TCP in pkt:
                            tcp = pkt[TCP]
                            src_port = int(tcp.sport or 0)
                            dst_port = int(tcp.dport or 0)
                            flags = str(getattr(tcp, "flags", "") or "")
                            proto = 6
                        elif UDP in pkt:
                            udp = pkt[UDP]
                            src_port = int(udp.sport or 0)
                            dst_port = int(udp.dport or 0)
                            proto = 17
                        size = int(len(pkt))
                        ts = float(getattr(pkt, "time", time.time()))
                        self._replay_last_packet_ts = float(ts)
                        item = {
                            "timestamp": ts,
                            "timestamp_epoch": ts,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "proto": proto,
                            "packet_size": size,
                            "ttl": ttl,
                            "tcp_flags": flags,
                            "ip_id": ip_id,
                            "ip_frag_offset": ip_frag_offset,
                            "ip_mf": ip_mf,
                        }
                        items.append(item)
                        if first_summary is None:
                            first_summary = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} proto={proto} flags={flags} size={size}"
                    except Exception:
                        logger.exception("replay_thread_crashed")
                        continue

                self._replay_packets_loaded = int(len(items))
                logger.info("replay_packets_loaded=%d pcap=%s", int(self._replay_packets_loaded), str(pcap_path))
                if int(self._replay_packets_loaded) <= 0:
                    self._replay_packets_processed = 0
                    logger.error("replay_fatal replay_packets_loaded=0 pcap=%s", str(pcap_path))
                    logger.error("replay_fatal replay_packets_processed=0 telemetry_live=false")
                    self._replay_done = True
                    return
                if first_summary:
                    logger.info("replay_first_packet_summary=%s", str(first_summary))
                try:
                    if items and not items[0].get("trace_id"):
                        items[0]["trace_id"] = "replay_trace_1"
                except Exception:
                    pass

                last_ts = None
                for item in items:
                    if self.monitor._stop.is_set():
                        break
                    ts = 0.0
                    try:
                        ts = float(item.get("timestamp_epoch", item.get("timestamp", 0.0)) or 0.0)
                    except Exception:
                        ts = 0.0
                    if ts > 0:
                        if last_ts is not None:
                            try:
                                if speed <= 0:
                                    delay = 0.0
                                else:
                                    delay = max(0.0, (ts - float(last_ts)) / float(speed))
                                _sleep(delay)
                            except Exception:
                                self._replay_done = True
                                return
                        last_ts = float(ts)

                    try:
                        self.monitor.q.put_nowait(item)
                        self._replay_packets_enqueued += 1
                        if int(self._replay_packets_enqueued) <= 5 or (int(self._replay_packets_enqueued) % 1000) == 0:
                            logger.info(
                                "replay_packet_enqueued=%d q=%d queue_id=%d trace_id=%s",
                                int(self._replay_packets_enqueued),
                                int(self.monitor.q.qsize()),
                                int(id(self.monitor.q)),
                                str(item.get("trace_id") or ""),
                            )
                    except Exception:
                        self.dropped_packets = int(getattr(self.monitor, "dropped_packets", 0)) + 1
                        self._replay_packets_dropped += 1
                        logger.exception("replay_thread_crashed")
                        continue

                if not loop:
                    break
        except Exception:
            logger.exception("replay_thread_crashed")
            self._replay_done = True
            return

        self._replay_done = True
        logger.info(
            "replay_thread_finished loaded=%d enqueued=%d dropped=%d",
            int(self._replay_packets_loaded),
            int(self._replay_packets_enqueued),
            int(self._replay_packets_dropped),
        )

    def _start_replay_self_test(self) -> None:
        if self._replay_self_test_thread is not None and getattr(self._replay_self_test_thread, "is_alive", lambda: False)():
            return
        t = threading.Thread(target=self._replay_self_test_worker, name="replay_self_test", daemon=True)
        self._replay_self_test_thread = t
        t.start()

    def _replay_self_test_worker(self) -> None:
        try:
            ok = self._run_started.wait(timeout=10.0)
            if not ok:
                logger.error("processing_pipeline_dead")
                return
            baseline = int(self.packets_seen)
            ts = time.time()
            pkt = {
                "timestamp": float(ts),
                "timestamp_epoch": float(ts),
                "src_ip": "127.0.0.1",
                "dst_ip": "127.0.0.1",
                "src_port": 1,
                "dst_port": 1,
                "proto": 6,
                "packet_size": 64,
                "ttl": 64,
                "tcp_flags": "S",
            }
            try:
                self.monitor.q.put_nowait(pkt)
            except Exception:
                logger.exception("processing_pipeline_dead")
                return
            t0 = time.time()
            while (time.time() - t0) < 5.0:
                if int(self.packets_seen) > int(baseline):
                    t1 = time.time()
                    while (time.time() - t1) < 5.0:
                        if float(getattr(self, "_last_pps", 0.0) or 0.0) > 0.0:
                            self._replay_self_test_done = True
                            return
                        time.sleep(0.05)
                    logger.error("processing_pipeline_dead")
                    return
                time.sleep(0.05)
            logger.error("processing_pipeline_dead")
        except Exception:
            logger.exception("processing_pipeline_dead")

    def _inject_startup_packets(self) -> None:
        try:
            base_ts = time.time()
            injected = 0
            for i in range(10):
                ts = float(base_ts + (i * 0.0001))
                pkt = {
                    "timestamp": ts,
                    "timestamp_epoch": ts,
                    "src_ip": "192.168.100.10",
                    "dst_ip": "192.168.100.20",
                    "src_port": int(40000 + i),
                    "dst_port": int(80 + (i % 3)),
                    "proto": 6,
                    "packet_size": 64,
                    "ttl": 64,
                    "tcp_flags": "S",
                    "trace_id": f"startup_trace_{i+1}",
                }
                try:
                    self.monitor.q.put_nowait(pkt)
                    injected += 1
                    logger.info("startup_packet_injected n=%d q=%d trace_id=%s", int(injected), int(self.monitor.q.qsize()), str(pkt.get("trace_id")))
                except Exception:
                    logger.exception("startup_packet_injection_failed")
                    break
        except Exception:
            logger.exception("startup_packet_injection_failed")

    def _processing_watchdog(self) -> None:
        try:
            logger.info("runtime_identity component=processing_watchdog pid=%d thread=%s", int(os.getpid()), threading.current_thread().name)
        except Exception:
            pass
        while not self._workers_stop.is_set():
            try:
                time.sleep(1.0)
                if not self._replay_mode:
                    continue
                if int(self._replay_packets_enqueued) > int(self._replay_packets_processed):
                    if not float(self._stall_since_s):
                        self._stall_since_s = float(time.time())
                    if (time.time() - float(self._stall_since_s)) < 3.0:
                        continue

                    qsz = 0
                    try:
                        qsz = int(self.monitor.q.qsize())
                    except Exception:
                        qsz = -1

                    consumer_alive = False
                    try:
                        ident = int(self._consumer_thread_ident or 0)
                        for t in threading.enumerate():
                            if int(t.ident or 0) == ident:
                                consumer_alive = bool(t.is_alive())
                                break
                    except Exception:
                        consumer_alive = False

                    logger.error(
                        "processing_consumer_stalled enqueued=%d processed=%d queue_size=%d consumer_alive=%s",
                        int(self._replay_packets_enqueued),
                        int(self._replay_packets_processed),
                        int(qsz),
                        str(bool(consumer_alive)),
                    )

                    try:
                        ident = int(self._consumer_thread_ident or 0)
                        frames = sys._current_frames()
                        fr = frames.get(ident)
                        if fr is not None:
                            logger.error("consumer_thread_stacktrace:\n%s", "".join(traceback.format_stack(fr)))
                        else:
                            logger.error("consumer_thread_stacktrace missing_frame_for_ident=%d", int(ident))
                    except Exception:
                        logger.exception("consumer_thread_stacktrace_failed")
            except Exception:
                logger.exception("processing_watchdog_crashed")
                return

    def _enqueue_post(self, path: str, payload: Any, timeout_s: float = 2.0, label: str = "") -> None:
        item = {"path": str(path), "payload": payload, "timeout_s": float(timeout_s), "label": str(label or "")}
        if not self._api_online and path in {"/api/detections", "/api/alerts", "/api/blocked"}:
            self._api_backlog.append(item)
            return
        try:
            self._post_q.put_nowait(item)
        except Exception:
            self._api_post_failed += 1

    def _api_post_worker(self) -> None:
        try:
            logger.info("runtime_identity component=websocket_broadcaster pid=%d thread=%s", int(os.getpid()), threading.current_thread().name)
        except Exception:
            pass
        while not self._workers_stop.is_set():
            try:
                item = self._post_q.get(timeout=0.25)
            except Exception:
                continue
            try:
                res = post_json_verbose(item.get("path", "/"), item.get("payload"), timeout_s=float(item.get("timeout_s", 2.0)))
                ok = bool(res.get("ok"))
                ms = float(res.get("latency_ms", 0.0) or 0.0)
                if np.isfinite(ms):
                    self._api_post_latency_ms_ema = (self._api_post_latency_alpha * ms) + ((1.0 - self._api_post_latency_alpha) * float(self._api_post_latency_ms_ema))
                if ok:
                    self._api_post_ok += 1
                else:
                    self._api_post_failed += 1
                    if str(item.get("path") or "") == "/live/settings":
                        self._settings_sync_failures += 1
                    if not self._api_online and item.get("path") in {"/api/detections", "/api/alerts", "/api/blocked"}:
                        self._api_backlog.append(item)
                if self.debug or (not ok):
                    logger.info(
                        "POST_%s label=%s path=%s status=%s latency_ms=%.1f resp=%s",
                        "OK" if ok else "FAILED",
                        str(item.get("label") or ""),
                        str(item.get("path") or ""),
                        str(res.get("status_code") or 0),
                        float(ms),
                        str(res.get("response_text") or "")[:160],
                    )
            except Exception:
                self._api_post_failed += 1
                if self.debug:
                    logger.error("api_post_worker error:\n%s", traceback.format_exc())

    def _telegram_worker(self) -> None:
        try:
            logger.info("runtime_identity component=telegram_worker pid=%d thread=%s", int(os.getpid()), threading.current_thread().name)
        except Exception:
            pass
        last_warn_s = 0.0
        while not self._workers_stop.is_set():
            try:
                det = self._telegram_q.get(timeout=0.25)
            except Exception:
                continue
            try:
                res = self.alerter.send(det)
                if not bool(res.get("ok")):
                    now = time.time()
                    if (now - float(last_warn_s)) > 5.0:
                        last_warn_s = float(now)
                        logger.warning("telegram_send_failed error=%s", str(res.get("error") or "send_failed"))
            except Exception:
                now = time.time()
                if (now - float(last_warn_s)) > 5.0:
                    last_warn_s = float(now)
                    logger.warning("telegram_send_failed error=exception")

    def _block_worker(self) -> None:
        try:
            logger.info("runtime_identity component=autoblock_worker pid=%d thread=%s", int(os.getpid()), threading.current_thread().name)
        except Exception:
            pass
        while not self._workers_stop.is_set():
            try:
                job = self._block_q.get(timeout=0.25)
            except Exception:
                continue
            try:
                src_ip = str(job.get("src_ip") or "").strip()
                if not src_ip:
                    continue
                res = self.fusion.response.block_ip(
                    src_ip,
                    duration_seconds=3600,
                    reason=str(job.get("reason") or "fusion_autoblock"),
                )
                if res and bool(res.get("ok")):
                    self._enqueue_post("/api/blocked", {"ip": src_ip, "reason": "fusion_autoblock"}, timeout_s=1.5, label="blocked")
            except Exception:
                if self.debug:
                    logger.error("autoblock_worker error:\n%s", traceback.format_exc())

    def _health_worker(self) -> None:
        interval = float(os.getenv("LIVE_API_HEALTH_INTERVAL", "2.0"))
        interval = max(0.5, min(interval, 30.0))
        while not self._workers_stop.is_set():
            res = get_json_verbose("/health", timeout_s=1.0)
            ok = bool(res.get("ok"))
            if ok:
                self._api_last_health_ok = time.time()
            self._api_online = ok
            if ok and self._api_backlog:
                to_flush = []
                while self._api_backlog:
                    try:
                        to_flush.append(self._api_backlog.popleft())
                    except Exception:
                        break
                for it in to_flush:
                    try:
                        self._post_q.put_nowait(it)
                    except Exception:
                        break

            if ok and self._settings_sync_failures > 0:
                self.sync_runtime_settings_to_api()
            time.sleep(interval)

    def _heartbeat_worker(self) -> None:
        while not self._workers_stop.is_set():
            payload = {
                "engine_online": True,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
                "session_id": self.session_id,
                "uptime_seconds": float(max(0.0, time.time() - float(self._start_time_s))),
                "detector_applied_settings_ack": {
                    "settings_version": self._settings_last_applied_version,
                    "applied_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) if self._settings_last_apply_s else "",
                },
            }
            self._hb_last_sent_s = time.time()
            if self.debug:
                logger.info("heartbeat_sent session_id=%s", self.session_id)
            ok = False
            try:
                url = os.getenv("IOMT_API_URL", "http://localhost:3001").rstrip("/") + "/live/heartbeat"
                r = requests.post(url, json=payload, timeout=1.5)
                ok = bool(r.ok)
            except Exception:
                ok = False

            if ok:
                prev_fail = self._hb_failures
                self._hb_failures = 0
                self._hb_backoff_s = 1.0
                self._hb_last_ack_s = time.time()
                if self.debug:
                    logger.info("heartbeat_ack session_id=%s", self.session_id)
                if prev_fail > 0:
                    logger.info("detector_reconnected session_id=%s", self.session_id)
                time.sleep(float(self._hb_interval_s))
                continue

            self._hb_failures += 1
            if self.debug:
                logger.warning("heartbeat_failed session_id=%s failures=%d backoff=%.1fs", self.session_id, int(self._hb_failures), float(self._hb_backoff_s))
            time.sleep(float(self._hb_backoff_s))
            self._hb_backoff_s = min(30.0, float(self._hb_backoff_s) * 2.0)

    def _refresh_settings(self) -> None:
        if bool(getattr(self, "_replay_mode", False)) or bool(getattr(self.config, "lab_mode", False)):
            return
        now = time.time()
        if now - float(self._last_settings_fetch) < float(self.config.settings_refresh_seconds):
            return
        self._last_settings_fetch = now
        try:
            settings = get_json("/live/settings", timeout_s=1.5)
        except Exception:
            return
        if not isinstance(settings, dict):
            return

        remote_version = settings.get("settings_version")
        remote_updated = str(settings.get("last_updated") or "")
        self._settings_version_remote = remote_version
        self._settings_last_updated_remote = remote_updated

        if bool(getattr(self, "_telegram_forced", False)):
            self.config.enable_telegram = True
        elif "telegram_enabled" in settings:
            self.config.enable_telegram = bool(settings.get("telegram_enabled"))
        if "autoblock_enabled" in settings:
            self.config.enable_autoblock = bool(settings.get("autoblock_enabled"))
        if "autoblock_fusion_threshold" in settings:
            try:
                self.config.autoblock_fusion_threshold = float(settings.get("autoblock_fusion_threshold"))
            except Exception:
                pass
        if "alert_fusion_threshold" in settings:
            try:
                self.config.alert_fusion_threshold = float(settings.get("alert_fusion_threshold"))
            except Exception:
                pass
        if "restrict_to_device_network" in settings:
            self.config.restrict_to_device_network = bool(settings.get("restrict_to_device_network"))

        if remote_version is not None and remote_version != self._settings_last_applied_version:
            self._settings_last_applied_version = remote_version
            self._settings_last_apply_s = time.time()
            if self.debug:
                logger.info("detector_applied_settings_ack session_id=%s version=%s updated=%s", self.session_id, str(remote_version), str(remote_updated))

    def _post_detection(self, det: Dict[str, Any]) -> None:
        try:
            logger.info(
                "event_published id=%s flow_key=%s severity=%s fusion=%.4f trace_id=%s",
                str(det.get("id", "")),
                str(det.get("flow_key", det.get("flow_key", ""))),
                str(det.get("severity", "")),
                float(det.get("fusion_score", 0.0) or 0.0),
                str(det.get("trace_id") or ""),
            )
        except Exception:
            pass

        sync_detections = os.getenv("LIVE_SYNC_DETECTIONS", "1") == "1"
        should_sync_for_telegram = False
        try:
            if bool(self.config.enable_telegram):
                src_ip = str(det.get("source_ip", "") or "").strip()
                sev = str(det.get("severity", "LOW") or "LOW").upper()
                min_sev = str(os.getenv("TELEGRAM_MIN_SEVERITY", "MEDIUM") or "MEDIUM").upper()
                order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
                should_sync_for_telegram = bool(src_ip) and (int(order.get(sev, 0)) >= int(order.get(min_sev, 0)))
        except Exception:
            should_sync_for_telegram = False

        posted_ok = False
        if sync_detections and should_sync_for_telegram:
            try:
                res = post_json_verbose("/api/detections", det, timeout_s=2.0)
                posted_ok = bool(res.get("ok"))
            except Exception:
                posted_ok = False
        if not posted_ok:
            self._enqueue_post("/api/detections", det, timeout_s=2.0, label="detections")
        self._published_detections += 1
        self.counters["detections_written"] = int(self.counters.get("detections_written", 0)) + 1

        allow_alert = bool(det.get("_allow_alert", True))
        if allow_alert and float(det.get("fusion_score", 0.0) or 0.0) >= float(self.config.alert_fusion_threshold):
            self._enqueue_post("/api/alerts", det, timeout_s=2.0, label="alerts")
            self._published_alerts += 1

        if det.get("auto_blocked") and det.get("source_ip"):
            self._enqueue_post("/api/blocked", {"ip": det.get("source_ip"), "reason": "fusion_autoblock"}, timeout_s=1.5, label="blocked")
            self._published_blocks += 1

        try:
            pred = 1 if str(det.get("severity", "")).upper() in {"MEDIUM", "HIGH", "CRITICAL"} else 0
            obf = bool(det.get("obfuscation_detected"))
            self._enqueue_post(
                "/api/traffic",
                {
                    "timestamp": det.get("timestamp"),
                    "src_ip": det.get("source_ip", ""),
                    "dst_ip": det.get("destination_ip", ""),
                    "proto": 0,
                    "packet_size": int(det.get("flow_bytes", 0) or 0),
                    "prediction": int(pred),
                    "status": "ANOMALY" if pred == 1 else "NORMAL",
                    "anomaly_score": float(det.get("fusion_score", 0.0) or 0.0),
                    **({"obfuscation": True} if obf else {}),
                },
                timeout_s=1.0,
                label="traffic",
            )
        except Exception:
            if self.debug:
                logger.error("post_json /api/traffic failed:\n%s", traceback.format_exc())
            pass

    def _maybe_telegram(self, det: Dict[str, Any]) -> None:
        if not self.config.enable_telegram:
            return
        src_ip = str(det.get("source_ip", "") or "").strip()
        if not src_ip:
            return
        sev = str(det.get("severity", "LOW") or "LOW").upper()
        min_sev = str(os.getenv("TELEGRAM_MIN_SEVERITY", "MEDIUM") or "MEDIUM").upper()
        order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        if int(order.get(sev, 0)) < int(order.get(min_sev, 0)):
            return
        if bool(getattr(self, "_replay_mode", False)):
            try:
                res = self.alerter.send(det)
                if not bool(res.get("ok")):
                    logger.warning("telegram_send_failed error=%s", str(res.get("error") or "send_failed"))
            except Exception:
                logger.warning("telegram_send_failed error=exception")
            return
        try:
            self._telegram_q.put_nowait(det)
        except Exception:
            if self.debug:
                logger.error("telegram queue full; dropping message")
            return

    def _clamp01(self, x: float) -> float:
        try:
            v = float(x)
        except Exception:
            v = 0.0
        if not np.isfinite(v):
            v = 0.0
        return float(max(0.0, min(1.0, v)))

    def _in_device_network(self, ip_s: str) -> bool:
        ip_s = str(ip_s or "").strip()
        if not ip_s:
            return False
        if ip_s in self._device_ips:
            return True
        try:
            addr = ipaddress.ip_address(ip_s)
        except Exception:
            return False
        for net in self._device_nets:
            if addr in net:
                return True
        return False

    def _should_consider_flow(self, src_ip: str, dst_ip: str) -> bool:
        if not bool(self.config.restrict_to_device_network):
            return True
        return self._in_device_network(src_ip) or self._in_device_network(dst_ip)

    def _ip_bucket(self, src_ip: str) -> Dict[str, Any]:
        b = self._ip_state.get(src_ip)
        if b is None:
            b = {
                "last_alert": 0.0,
                "last_block": 0.0,
                "suspicious": 0,
                "last_seen": 0.0,
                "ports": [],
                "syn_only_flows": 0,
                "frag_flows": 0,
            }
            self._ip_state[src_ip] = b
        return b

    def _maybe_queue_relief(self) -> None:
        try:
            qsize = int(self.monitor.q.qsize())
            qmax = int(getattr(self.monitor.config, "queue_maxsize", 0) or 0)
        except Exception:
            return
        if qmax <= 0:
            return
        if qsize < int(float(self.config.queue_high_watermark_ratio) * qmax):
            return
        drain = min(qsize, int(0.25 * qmax))
        for _ in range(max(0, drain)):
            try:
                self.monitor.q.get_nowait()
            except Exception:
                break
        self.dropped_packets = int(getattr(self.monitor, "dropped_packets", 0)) + int(drain)

    def _gate_alert_and_block(self, src_ip: str, fusion_score: float, obf: bool) -> Tuple[bool, bool, str]:
        if bool(self.config.attack_test_mode):
            return True, True, "attack_test_mode"
        now = time.time()
        bucket = self._ip_bucket(src_ip)

        f = self._clamp01(fusion_score)
        suspicious = int(bucket.get("suspicious", 0))

        reasons: List[str] = []
        allow_alert = True
        allow_block = True

        if f < float(self.config.alert_fusion_threshold) and not obf:
            allow_alert = False
            allow_block = False
            reasons.append("below_alert_threshold")

        if suspicious < 3 and not obf:
            allow_alert = False
            allow_block = False
            reasons.append("insufficient_repeats")

        if now - float(bucket.get("last_alert", 0.0)) < float(self.config.per_ip_alert_cooldown_seconds):
            allow_alert = False
            reasons.append("alert_cooldown")

        if f < float(self.config.autoblock_fusion_threshold) and not obf:
            allow_block = False
            reasons.append("below_autoblock_threshold")

        if suspicious < 5 and not obf:
            allow_block = False
            reasons.append("insufficient_repeats_for_block")

        if now - float(bucket.get("last_block", 0.0)) < float(self.config.per_ip_block_cooldown_seconds):
            allow_block = False
            reasons.append("block_cooldown")

        return allow_alert, allow_block, ",".join(reasons) if reasons else "ok"

    def _apply_heuristics(self, src_ip: str, dst_port: int, proto: int, flow: Any, raw_feats: Dict[str, Any]) -> Tuple[float, bool, str]:
        now = 0.0
        try:
            now = float(getattr(flow, "last_seen", 0.0) or 0.0)
        except Exception:
            now = 0.0
        if now <= 0.0:
            now = time.time()
        b = self._ip_bucket(src_ip)
        window_s = float(self.config.heuristic_window_seconds)
        window_s = max(1.0, min(window_s, 120.0))

        ports = b.get("ports") or []
        ports = [(int(p), float(ts)) for (p, ts) in ports if (now - float(ts)) <= window_s]
        if dst_port > 0:
            ports.append((int(dst_port), float(now)))
        b["ports"] = ports[-500:]

        syn = int(getattr(flow, "tcp_syn_count", 0) or 0)
        ack = int(getattr(flow, "tcp_ack_count", 0) or 0)
        frag = int(raw_feats.get("ip_fragment_count", 0) or 0) if isinstance(raw_feats, dict) else 0
        if frag <= 0:
            try:
                frag = 0
                for p in list(getattr(flow, "packets", []) or []):
                    if not isinstance(p, dict):
                        continue
                    off = 0
                    mf = 0
                    try:
                        off = int(p.get("ip_frag_offset", 0) or 0)
                    except Exception:
                        off = 0
                    try:
                        mf = int(p.get("ip_mf", 0) or 0)
                    except Exception:
                        mf = 0
                    if off > 0 or mf == 1:
                        frag += 1
            except Exception:
                frag = int(raw_feats.get("ip_fragment_count", 0) or 0) if isinstance(raw_feats, dict) else 0
        uniq_ports = len(set([p for (p, _ts) in ports if p > 0]))

        triggered = False
        reasons: List[str] = []
        boost = 0.0

        if int(proto) == 6 and syn > 0 and ack == 0:
            b["syn_only_flows"] = int(b.get("syn_only_flows", 0)) + 1
        if frag > 0:
            b["frag_flows"] = int(b.get("frag_flows", 0)) + 1

        if int(proto) == 6 and syn > 0 and ack == 0 and uniq_ports >= int(self.config.syn_scan_unique_ports_threshold):
            triggered = True
            reasons.append(f"syn_scan_ports={uniq_ports}")
            boost = max(boost, 0.35)

        frag_score = 0.0
        try:
            frag_score = float(raw_feats.get("fragmentation_anomaly_score", 0.0) or 0.0)
        except Exception:
            frag_score = 0.0
        if frag > 0 or frag_score >= 0.2:
            triggered = True
            reasons.append("fragmentation")
            boost = max(boost, 0.35)
            if frag_score >= 0.5 or frag >= 5:
                boost = max(boost, 0.5)
            try:
                dst_ip = ""
                try:
                    dst_ip = str(getattr(flow, "key", ["", ""])[1] or "")
                except Exception:
                    dst_ip = ""
                meta = self.fusion.device_mapper.lookup(dst_ip) if dst_ip else {}
                crit = str((meta or {}).get("criticality") or "").strip().lower()
                if crit == "critical":
                    boost = max(boost, 0.5)
            except Exception:
                pass

        jitter = 0.0
        try:
            jitter = float(raw_feats.get("timing_jitter_score", 0.0) or 0.0)
        except Exception:
            jitter = 0.0
        if jitter <= 0.0:
            try:
                ts_list: List[float] = []
                for p in list(getattr(flow, "packets", []) or []):
                    if not isinstance(p, dict):
                        continue
                    try:
                        ts_list.append(float(p.get("timestamp_epoch", p.get("timestamp", 0.0)) or 0.0))
                    except Exception:
                        continue
                ts_list = sorted([t for t in ts_list if t > 0])
                if len(ts_list) >= 6:
                    deltas = [max(0.0, ts_list[i] - ts_list[i - 1]) for i in range(1, len(ts_list))]
                    if len(deltas) >= 5:
                        mean = float(np.mean(deltas))
                        std = float(np.std(deltas))
                        if mean > 0:
                            cv = std / mean
                            jitter = float(max(0.0, min(1.0, cv)))
            except Exception:
                jitter = float(raw_feats.get("timing_jitter_score", 0.0) or 0.0) if isinstance(raw_feats, dict) else 0.0
        if jitter >= 0.8:
            triggered = True
            reasons.append("timing_jitter")
            boost = max(boost, 0.45)
        elif jitter >= 0.6:
            triggered = True
            reasons.append("timing_jitter")
            boost = max(boost, 0.35)
        if "timing_jitter" in reasons:
            try:
                dst_ip = ""
                try:
                    dst_ip = str(getattr(flow, "key", ["", ""])[1] or "")
                except Exception:
                    dst_ip = ""
                meta = self.fusion.device_mapper.lookup(dst_ip) if dst_ip else {}
                crit = str((meta or {}).get("criticality") or "").strip().lower()
                if crit == "critical":
                    boost = max(boost, 0.5)
            except Exception:
                pass

        return float(boost), bool(triggered), ",".join(reasons) if reasons else ""

    def _should_suppress_noise(self, det: Dict[str, Any], flow: Any, raw_feats: Dict[str, Any]) -> Tuple[bool, str]:
        if bool(self.config.lab_mode) or bool(self.config.attack_test_mode):
            return False, ""

        sev = str(det.get("severity") or "").upper()
        obf = bool(det.get("obfuscation_detected"))
        heur = bool(det.get("heuristic_triggered"))
        if obf or heur:
            return False, ""

        try:
            f = float(det.get("fusion_score", 0.0) or 0.0)
        except Exception:
            f = 0.0

        try:
            proto = int(flow.key[4] or 0)
            src_port = int(flow.key[2] or 0)
            dst_port = int(flow.key[3] or 0)
        except Exception:
            proto = 0
            src_port = 0
            dst_port = 0

        pkt_count = int(getattr(flow, "packet_count", len(getattr(flow, "packets", []) or [])) or 0)
        dur = 0.0
        try:
            dur = float(raw_feats.get("flow_duration", 0.0) or 0.0)
        except Exception:
            dur = 0.0

        syn = int(getattr(flow, "tcp_syn_count", 0) or 0)
        ack = int(getattr(flow, "tcp_ack_count", 0) or 0)

        low_max = float(self.config.low_suppression_fusion_max)
        low_max = max(0.0, min(low_max, 0.95))

        if sev == "LOW" and not bool(self.config.low_severity_publish):
            return True, "low_severity_suppressed"
        if sev == "LOW" and f <= low_max:
            return True, "low_score_suppressed"

        if proto == 17 and (src_port == 53 or dst_port == 53) and pkt_count <= 20 and f <= 0.7:
            return True, "dns_noise"

        if proto == 6 and (dst_port in {80, 443} or src_port in {80, 443}) and pkt_count <= 30 and dur <= 5.0 and f <= 0.75:
            return True, "https_noise"

        if proto == 6 and syn == 0 and ack > 0 and pkt_count <= 6 and dur <= 2.0 and f <= 0.7:
            return True, "ack_only_short"

        if (dst_port in {5353, 1900, 137, 138, 139} or src_port in {5353, 1900, 137, 138, 139}) and pkt_count <= 25 and f <= 0.75:
            return True, "windows_background"

        return False, ""

    def _post_telemetry(self) -> None:
        now = time.time()
        if now - float(self._last_telemetry_ts) < float(self.config.ws_telemetry_interval_seconds):
            return
        last_p, last_f, last_d = self._last_counts
        cur_p, cur_f, cur_d = int(self.packets_seen), int(self.flows_completed), int(self.dropped_packets)
        dt = max(1e-6, now - float(self._last_telemetry_ts))
        pps = (cur_p - last_p) / dt
        fps = (cur_f - last_f) / dt
        dps = (cur_d - last_d) / dt
        try:
            self._last_pps = float(max(0.0, pps))
        except Exception:
            self._last_pps = 0.0
        try:
            fusion_stats = self.fusion.stats()
        except Exception:
            fusion_stats = {}

        if isinstance(fusion_stats, dict):
            if "rf_predictions" in fusion_stats:
                self.counters["rf_predictions"] = int(fusion_stats.get("rf_predictions", 0) or 0)
            if "ae_predictions" in fusion_stats:
                self.counters["ae_predictions"] = int(fusion_stats.get("ae_predictions", 0) or 0)
            if "fusion_events" in fusion_stats:
                self.counters["fusion_events"] = int(fusion_stats.get("fusion_events", 0) or 0)

        payload = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
            "packets_per_sec": float(max(0.0, pps)),
            "flows_per_sec": float(max(0.0, fps)),
            "telemetry_live": bool((cur_p - last_p) > 0),
            "packets_processed_total": int(self.packets_seen),
            "flows_completed_total": int(self.flows_completed),
            "dropped_packets_total": int(cur_d),
            "dropped_packets_per_sec": float(max(0.0, dps)),
            "queue_size": int(self.monitor.q.qsize()) if hasattr(self.monitor, "q") else 0,
            "active_flows": int(self.flow_builder.active_flows()),
            "dropped_flows_total": int(getattr(self.flow_builder, "dropped_flows", 0)),
            "inference_latency_ms_ema": float(self._lat_ms_ema),
            "detector_uptime_seconds": float(max(0.0, time.time() - float(self._start_time_s))),
            "last_heartbeat_ack_s": float(time.time() - float(self._hb_last_ack_s)) if float(self._hb_last_ack_s) > 0 else None,
            "last_heartbeat_sent_s": float(time.time() - float(self._hb_last_sent_s)) if float(self._hb_last_sent_s) > 0 else None,
            "detector_session_id": self.session_id,
            "settings_version": self._settings_version_remote,
            "settings_last_updated": self._settings_last_updated_remote,
            "api_online": bool(self._api_online),
            "api_last_health_ok_s": float(time.time() - float(self._api_last_health_ok)) if float(self._api_last_health_ok) > 0 else None,
            "api_post_ok_total": int(self._api_post_ok),
            "api_post_failed_total": int(self._api_post_failed),
            "api_post_latency_ms_ema": float(self._api_post_latency_ms_ema),
            "api_post_queue_size": int(self._post_q.qsize()),
            "api_backlog_size": int(len(self._api_backlog)),
            "telegram_queue_size": int(self._telegram_q.qsize()),
            "autoblock_queue_size": int(self._block_q.qsize()),
            "suppressed_events_total": int(self._suppressed_total),
            "detections_generated_total": int(self._published_detections),
            "replay_mode": bool(self._replay_mode),
            "replay_flows_flushed": int(self._replay_flows_flushed),
            "replay_force_completed": int(self._replay_force_completed),
            "replay_syn_only_flows": int(self._replay_syn_only_flows),
            "replay_packets_loaded": int(self._replay_packets_loaded),
            "replay_packets_enqueued": int(self._replay_packets_enqueued),
            "replay_packets_processed": int(self._replay_packets_processed),
            "replay_packets_dropped": int(self._replay_packets_dropped),
            "replay_active": bool(self._replay_mode and (self._replay_thread is not None) and self._replay_thread.is_alive()),
            "replay_last_packet_ts": float(self._replay_last_packet_ts) if self._replay_last_packet_ts else None,
            "replay_packets_per_second": float(max(0.0, (self._replay_packets_processed - self._replay_last_processed_count) / dt)) if self._replay_mode else None,
            "replay_queue_size": int(self.monitor.q.qsize()) if hasattr(self.monitor, "q") else 0,
            "queue_backpressure_percent": float(
                max(
                    float(int(self._post_q.qsize())) / float(max(1, int(self._post_q_max))),
                    float(int(self._telegram_q.qsize())) / float(max(1, int(self._telegram_q_max))),
                    float(int(self._block_q.qsize())) / float(max(1, int(self._block_q_max))),
                )
                * 100.0
            ),
            "ignored_non_device_total": int(self._ignored_non_device),
            "ignored_small_flow_total": int(self._ignored_small_flow),
            "suppressed_cooldown_total": int(self._suppressed_cooldown),
            "published_detections_total": int(self._published_detections),
            "published_alerts_total": int(self._published_alerts),
            "published_blocks_total": int(self._published_blocks),
            "debug_counters": dict(self.counters),
            "flow_builder": self.flow_builder.stats(),
            "fusion_engine": fusion_stats,
        }
        self._enqueue_post("/live/telemetry", payload, timeout_s=1.0, label="telemetry")
        self._last_counts = (cur_p, cur_f, cur_d)
        self._last_telemetry_ts = now
        if self._replay_mode:
            self._replay_last_processed_count = int(self._replay_packets_processed)

    def _obfuscation_flag(self, feats: Dict[str, Any], flow_packets: Optional[List[Dict[str, Any]]] = None) -> Tuple[bool, Dict[str, Any]]:
        def _f(name: str) -> float:
            try:
                v = float(feats.get(name, 0.0) or 0.0)
                return v if np.isfinite(v) else 0.0
            except Exception:
                return 0.0

        scores = {
            "timing_jitter_score": _f("timing_jitter_score"),
            "fragmentation_anomaly_score": _f("fragmentation_anomaly_score"),
            "header_consistency_score": _f("header_consistency_score"),
            "flow_uniformity_score": _f("flow_uniformity_score"),
        }
        try:
            if flow_packets:
                frag_n = 0
                ts_list: List[float] = []
                for p in list(flow_packets):
                    if not isinstance(p, dict):
                        continue
                    try:
                        ts_list.append(float(p.get("timestamp_epoch", p.get("timestamp", 0.0)) or 0.0))
                    except Exception:
                        pass
                    off = 0
                    mf = 0
                    try:
                        off = int(p.get("ip_frag_offset", 0) or 0)
                    except Exception:
                        off = 0
                    try:
                        mf = int(p.get("ip_mf", 0) or 0)
                    except Exception:
                        mf = 0
                    if off > 0 or mf == 1:
                        frag_n += 1
                if frag_n > 0 and float(scores.get("fragmentation_anomaly_score", 0.0) or 0.0) <= 0.0:
                    scores["fragmentation_anomaly_score"] = 0.6

                if float(scores.get("timing_jitter_score", 0.0) or 0.0) <= 0.0 and len(ts_list) >= 6:
                    ts_list = sorted([t for t in ts_list if t > 0])
                    if len(ts_list) >= 6:
                        deltas = [max(0.0, ts_list[i] - ts_list[i - 1]) for i in range(1, len(ts_list))]
                        if len(deltas) >= 5:
                            mean = float(np.mean(deltas))
                            std = float(np.std(deltas))
                            if mean > 0:
                                cv = std / mean
                                scores["timing_jitter_score"] = float(max(0.0, min(1.0, cv)))
        except Exception:
            pass
        detected = bool(scores["timing_jitter_score"] >= 0.8 or scores["fragmentation_anomaly_score"] >= 0.2 or scores["header_consistency_score"] <= 0.4)
        return detected, scores

    def run_forever(self) -> None:
        install_signal_handlers(self.monitor)
        if not self._replay_mode:
            self.monitor.start()
        logger.setLevel(logging.INFO)
        try:
            self._run_started.set()
        except Exception:
            pass
        try:
            self._consumer_thread_ident = int(threading.get_ident())
        except Exception:
            self._consumer_thread_ident = None
        try:
            logger.info("runtime_identity component=queue_consumer pid=%d thread=%s", int(os.getpid()), threading.current_thread().name)
        except Exception:
            pass
        try:
            threads = []
            for t in threading.enumerate():
                try:
                    threads.append({"name": t.name, "alive": bool(t.is_alive()), "daemon": bool(t.daemon), "ident": int(t.ident or 0)})
                except Exception:
                    continue
            logger.info("thread_dump %s", str(threads))
        except Exception:
            pass
        try:
            logger.info("packet_queue_identity role=consumer id=%d", int(id(self.monitor.q)))
        except Exception:
            pass
        if self._watchdog_thread is None:
            self._watchdog_thread = threading.Thread(target=self._processing_watchdog, name="processing_watchdog", daemon=True)
            self._watchdog_thread.start()
        if self._replay_mode:
            self._inject_startup_packets()
        try:
            logger.info("packet_queue_identity role=consumer id=%d", int(id(self.monitor.q)))
        except Exception:
            pass
        last_flush = time.time()
        last_debug_print = time.time()

        if self.debug:
            schema_n = int(self.features.schema_size())
            logger.info("DEBUG_LIVE=1 schema_size=%d rf_model_loaded=%s ae_model_loaded=%s device_ips=%d device_nets=%d",
                        schema_n,
                        str(self.fusion.rf_model is not None),
                        str(getattr(getattr(self.fusion, "ae", None), "model", None) is not None),
                        int(len(self._device_ips)),
                        int(len(self._device_nets)))

        while True:
            if self.monitor._stop.is_set():
                break
            if self._replay_mode:
                qsz = int(self.monitor.q.qsize()) if hasattr(self.monitor, "q") else 0
                if qsz > 0:
                    self._replay_last_queue_nonempty = time.time()
                if (time.time() - float(self._replay_start_wall)) > 5.0:
                    if (
                        bool(self._replay_mode)
                        and (self._replay_thread is not None)
                        and self._replay_thread.is_alive()
                        and int(self._replay_packets_loaded) > 0
                        and int(self._replay_packets_processed) <= 0
                    ):
                        logger.error("replay_pipeline_stalled")
                    if (
                        (not self._replay_done)
                        and (self._replay_thread is not None)
                        and self._replay_thread.is_alive()
                        and (time.time() - float(self._replay_last_queue_nonempty)) > 5.0
                        and (self._replay_packets_enqueued > self._replay_packets_processed)
                    ):
                        logger.error(
                            "replay_fatal replay_queue_empty_for_5s enqueued=%d processed=%d",
                            int(self._replay_packets_enqueued),
                            int(self._replay_packets_processed),
                        )
                if self._replay_thread is not None and (not self._replay_thread.is_alive()) and bool(self._replay_loop) and (not self._replay_done):
                    logger.error("replay_fatal replay_thread_exited_unexpectedly")
            if self._replay_mode and self._replay_done:
                if self.monitor.q.qsize() == 0 and self.flow_builder.active_flows() == 0:
                    logger.info("replay_complete")
                    break
            if (not self._replay_mode) and (not self.monitor._thread or not self.monitor._thread.is_alive()):
                try:
                    self.monitor.start()
                except Exception:
                    if self.debug:
                        logger.error("monitor.start failed:\n%s", traceback.format_exc())
                    time.sleep(0.5)

            self._refresh_settings()
            self._maybe_queue_relief()
            try:
                batch = self.monitor.get_batch(max_items=int(self.config.packet_batch_size), timeout_s=0.25)
            except Exception:
                if self.debug:
                    logger.error("monitor.get_batch failed:\n%s", traceback.format_exc())
                batch = []

            completed_flows: List[Any] = []
            for pkt in batch:
                self.packets_seen += 1
                self.counters["packets_seen"] = int(self.counters.get("packets_seen", 0)) + 1
                self._last_packet_seen_ts = time.time()
                self.dropped_packets = int(getattr(self.monitor, "dropped_packets", 0))
                if self._replay_mode:
                    n = int(self.packets_seen)
                    if n <= 5 or (n % 1000) == 0:
                        try:
                            logger.info(
                                "packet_received_from_queue n=%d q=%d queue_id=%d trace_id=%s",
                                int(n),
                                int(self.monitor.q.qsize()),
                                int(id(self.monitor.q)),
                                str(pkt.get("trace_id") or ""),
                            )
                        except Exception:
                            pass
                if self._replay_mode:
                    self._replay_packets_processed += 1
                    if int(self._replay_packets_processed) <= 5 or (int(self._replay_packets_processed) % 1000) == 0:
                        logger.info("replay_packet_processed=%d q=%d trace_id=%s", int(self._replay_packets_processed), int(self.monitor.q.qsize()), str(pkt.get("trace_id") or ""))

                pkt_ts = None
                try:
                    pkt_ts = float(pkt.get("timestamp_epoch", pkt.get("timestamp", 0.0)) or 0.0)
                except Exception:
                    pkt_ts = 0.0
                if pkt_ts and self._replay_mode:
                    self._replay_last_ts = float(pkt_ts)

                if self.debug:
                    try:
                        logger.info(
                            "pkt src=%s:%s dst=%s:%s proto=%s size=%s ttl=%s flags=%s ts=%.6f q=%d",
                            str(pkt.get("src_ip", "")),
                            str(pkt.get("src_port", "")),
                            str(pkt.get("dst_ip", "")),
                            str(pkt.get("dst_port", "")),
                            str(pkt.get("proto", "")),
                            str(pkt.get("packet_size", "")),
                            str(pkt.get("ttl", "")),
                            str(pkt.get("tcp_flags", "")),
                            float(pkt.get("timestamp_epoch", 0.0) or 0.0),
                            int(self.monitor.q.qsize()) if hasattr(self.monitor, "q") else 0,
                        )
                    except Exception:
                        logger.error("pkt debug print failed:\n%s", traceback.format_exc())

                try:
                    before_created = int(getattr(self.flow_builder, "flows_created", 0))
                    before_updated = int(getattr(self.flow_builder, "flows_updated", 0))
                    completed_flows.extend(self.flow_builder.add_packet(pkt, now=pkt_ts if pkt_ts else None))

                    if self._replay_mode and self._replay_force_complete_syn:
                        syn_completed = self.flow_builder.force_complete_syn(min_syn=int(self._replay_syn_threshold))
                        if syn_completed:
                            self._replay_force_completed += int(len(syn_completed))
                            self._replay_syn_only_flows += int(len(syn_completed))
                            completed_flows.extend(syn_completed)
                            logger.info("replay_force_complete_syn count=%d", int(len(syn_completed)))

                    if self._replay_mode and self._replay_force_flush:
                        flushed = self.flow_builder.flush_expired(now=pkt_ts if pkt_ts else None)
                        if flushed:
                            self._replay_flows_flushed += int(len(flushed))
                            completed_flows.extend(flushed)
                            logger.info("replay_flow_flushed count=%d", int(len(flushed)))

                    after_created = int(getattr(self.flow_builder, "flows_created", 0))
                    after_updated = int(getattr(self.flow_builder, "flows_updated", 0))
                    self.counters["flows_created"] = int(after_created)
                    if self._replay_mode:
                        try:
                            key = (
                                str(pkt.get("src_ip", "")).strip(),
                                str(pkt.get("dst_ip", "")).strip(),
                                int(pkt.get("src_port", 0) or 0),
                                int(pkt.get("dst_port", 0) or 0),
                                int(pkt.get("proto", 0) or 0),
                            )
                            if after_created > before_created:
                                logger.info("flow_created key=%s trace_id=%s", str(key), str(pkt.get("trace_id") or ""))
                        except Exception:
                            pass
                    if self.debug:
                        try:
                            key = (str(pkt.get("src_ip", "")).strip(), str(pkt.get("dst_ip", "")).strip(),
                                   int(pkt.get("src_port", 0) or 0), int(pkt.get("dst_port", 0) or 0), int(pkt.get("proto", 0) or 0))
                            if after_created > before_created:
                                logger.info("flow_created key=%s active=%d", str(key), int(self.flow_builder.active_flows()))
                            elif after_updated > before_updated:
                                logger.info("flow_updated key=%s active=%d", str(key), int(self.flow_builder.active_flows()))
                            else:
                                self.counters["packets_filtered"] = int(self.counters.get("packets_filtered", 0)) + 1
                                logger.info("packet_ignored reason=no_flow_key_or_not_tracked key=%s", str(key))
                        except Exception:
                            logger.error("flow key debug failed:\n%s", traceback.format_exc())
                except Exception:
                    if self.debug:
                        logger.error("flow_builder.add_packet failed:\n%s", traceback.format_exc())
                    continue

            if self._replay_mode and self._replay_force_flush and not batch and self._replay_last_ts:
                try:
                    now_ts = float(self._replay_last_ts) + float(self.flow_builder.flow_timeout_seconds) + 0.001
                    flushed = self.flow_builder.flush_expired(now=now_ts)
                    if flushed:
                        self._replay_flows_flushed += int(len(flushed))
                        completed_flows.extend(flushed)
                        logger.info("replay_flow_flushed count=%d", int(len(flushed)))
                    if self._replay_force_complete_syn:
                        syn_completed = self.flow_builder.force_complete_syn(min_syn=int(self._replay_syn_threshold))
                        if syn_completed:
                            self._replay_force_completed += int(len(syn_completed))
                            self._replay_syn_only_flows += int(len(syn_completed))
                            completed_flows.extend(syn_completed)
                            logger.info("replay_force_complete_syn count=%d", int(len(syn_completed)))
                except Exception:
                    if self.debug:
                        logger.error("replay flush failed:\n%s", traceback.format_exc())

            for flow in completed_flows:
                self.flows_completed += 1
                self.counters["flows_completed"] = int(self.counters.get("flows_completed", 0)) + 1
                t0 = time.perf_counter()
                try:
                    trace_id = ""
                    try:
                        for p in list(getattr(flow, "packets", []) or []):
                            if isinstance(p, dict) and p.get("trace_id"):
                                trace_id = str(p.get("trace_id") or "")
                                break
                    except Exception:
                        trace_id = ""
                    if self._replay_mode:
                        logger.info("flow_completed key=%s reason=%s trace_id=%s", str(getattr(flow, "key", "") or ""), str(getattr(flow, "completed_reason", "") or ""), str(trace_id or ""))
                    if self._replay_mode and (self._replay_force_flush or self._replay_force_complete_syn):
                        logger.info(
                            "replay_flow_completed reason=%s key=%s",
                            str(getattr(flow, "completed_reason", "") or ""),
                            str(getattr(flow, "key", "") or ""),
                        )
                    src_ip = flow.key[0]
                    dst_ip = flow.key[1]
                    if not self._should_consider_flow(src_ip, dst_ip):
                        self._ignored_non_device += 1
                        self.counters["packets_filtered"] = int(self.counters.get("packets_filtered", 0)) + int(getattr(flow, "packet_count", 0) or 0)
                        if self.debug:
                            logger.info("flow_discard reason=non_device_network key=%s pkts=%d bytes=%d", str(flow.key), int(getattr(flow, "packet_count", 0) or 0), int(getattr(flow, "byte_count", 0) or 0))
                        continue

                    pkt_count = int(getattr(flow, "packet_count", len(flow.packets)))
                    byte_count = int(getattr(flow, "byte_count", 0))
                    if pkt_count < 1:
                        if self.debug:
                            logger.info("flow_discard reason=empty_flow key=%s", str(flow.key))
                        continue

                    if self.debug:
                        logger.info("flow_completed key=%s reason=%s pkts=%d bytes=%d duration=%.3f",
                                    str(flow.key),
                                    str(getattr(flow, "completed_reason", "") or ""),
                                    int(pkt_count),
                                    int(byte_count),
                                    float(float(getattr(flow, "last_seen", 0.0)) - float(getattr(flow, "started_at", 0.0))))

                    raw_feats, rf_vec = self.features.extract(flow.packets)
                    obf, obf_scores = self._obfuscation_flag(raw_feats, flow_packets=list(getattr(flow, "packets", []) or []))
                    if self._replay_mode:
                        try:
                            logger.info("feature_extracted key=%s trace_id=%s", str(getattr(flow, "key", "") or ""), str(trace_id or ""))
                        except Exception:
                            pass

                    syn_only_replay = False
                    try:
                        proto = int(flow.key[4] or 0)
                    except Exception:
                        proto = 0
                    if self._replay_mode and self._replay_force_complete_syn and proto == 6:
                        syn = int(getattr(flow, "tcp_syn_count", 0) or 0)
                        ack = int(getattr(flow, "tcp_ack_count", 0) or 0)
                        if syn > 0 and ack == 0:
                            syn_only_replay = True
                            self._replay_syn_only_flows += 1
                            if self.debug:
                                logger.info("replay_syn_only_flow key=%s syn=%d ack=%d", str(flow.key), int(syn), int(ack))

                    if (pkt_count < int(self.config.min_packets_for_model) or byte_count < int(self.config.min_bytes_for_model)) and not obf and not syn_only_replay:
                        self._ignored_small_flow += 1
                        if self.debug:
                            logger.info("flow_discard reason=below_min_thresholds key=%s pkts=%d bytes=%d obf=%s", str(flow.key), int(pkt_count), int(byte_count), str(obf))
                        continue

                    bucket = self._ip_bucket(src_ip)
                    now = time.time()
                    bucket["last_seen"] = now
                    if obf:
                        bucket["suspicious"] = int(bucket.get("suspicious", 0)) + 2

                    extra_payload = {
                        "packets_in_flow": int(getattr(flow, "packet_count", len(flow.packets))),
                        "flow_bytes": int(getattr(flow, "byte_count", 0)),
                        "flow_key": "|".join([str(x) for x in flow.key]),
                        **obf_scores,
                    }

                    self.counters["feature_vectors_generated"] = int(self.counters.get("feature_vectors_generated", 0)) + 1
                    if self.debug:
                        schema_n = int(self.features.schema_size())
                        feat_n = int(len(raw_feats.keys())) if isinstance(raw_feats, dict) else 0
                        try:
                            vec_shape = tuple(getattr(rf_vec, "shape", ()))
                        except Exception:
                            vec_shape = ()
                        nonfinite = 0
                        try:
                            nonfinite = int(np.size(rf_vec) - int(np.isfinite(rf_vec).sum()))
                        except Exception:
                            nonfinite = 0
                        if schema_n and feat_n != schema_n:
                            logger.error("feature_schema_mismatch expected=%d got=%d key=%s", schema_n, feat_n, str(flow.key))
                        if schema_n and vec_shape and int(vec_shape[-1]) != int(schema_n):
                            logger.error("vector_shape_mismatch expected=%d got=%s key=%s", int(schema_n), str(vec_shape), str(flow.key))
                        if nonfinite > 0:
                            logger.error("vector_nonfinite count=%d key=%s", int(nonfinite), str(flow.key))
                        else:
                            logger.info("feature_ok key=%s n=%d vec_shape=%s nonfinite=%d", str(flow.key), int(feat_n), str(vec_shape), int(nonfinite))

                        if (self.counters["flows_completed"] % int(self.debug_sample_every)) == 0:
                            try:
                                sample_keys = list(raw_feats.keys())[:10]
                                sample = {k: raw_feats.get(k) for k in sample_keys}
                                logger.info("feature_sample key=%s sample_keys=%s sample=%s", str(flow.key), str(sample_keys), str(sample))
                            except Exception:
                                logger.error("feature_sample failed:\n%s", traceback.format_exc())

                    det = self.fusion.process_event(
                        feature_vector=raw_feats,
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        predicted_attack="RF/AE Fusion",
                        obfuscation_detected=obf,
                        extra=extra_payload,
                        enable_autoblock=False,
                        autoblock_fusion_threshold=float(self.config.autoblock_fusion_threshold),
                        persist=False,
                    )
                    self.counters["fusion_events"] = int(self.counters.get("fusion_events", 0)) + 1
                    f = self._clamp01(float(det.get("fusion_score", 0.0) or 0.0))
                    det["fusion_score"] = f
                    if self._replay_mode:
                        try:
                            logger.info(
                                "model_inference_done key=%s severity=%s fusion=%.4f trace_id=%s",
                                str(getattr(flow, "key", "") or ""),
                                str(det.get("severity", "")),
                                float(det.get("fusion_score", 0.0) or 0.0),
                                str(trace_id or ""),
                            )
                        except Exception:
                            pass
                    if trace_id:
                        det["trace_id"] = str(trace_id)

                    try:
                        proto = int(flow.key[4] or 0)
                    except Exception:
                        proto = 0
                    try:
                        dst_port = int(flow.key[3] or 0)
                    except Exception:
                        dst_port = 0

                    boost, trig, h_reason = self._apply_heuristics(src_ip, dst_port, proto, flow, raw_feats)
                    if trig and boost > 0:
                        det["heuristic_triggered"] = True
                        det["heuristic_reason"] = str(h_reason)
                        det["heuristic_boost"] = float(boost)
                        det["fusion_score"] = self._clamp01(float(det.get("fusion_score", 0.0) or 0.0) + float(boost))
                        f = float(det["fusion_score"])
                    else:
                        det["heuristic_triggered"] = False
                    if (self._replay_mode or bool(self.config.lab_mode)) and trig:
                        try:
                            hr = str(h_reason or "").lower()
                            if ("timing_jitter" in hr) or ("fragmentation" in hr) or ("syn_scan" in hr) or ("port_scan" in hr):
                                det["fusion_score"] = float(max(float(det.get("fusion_score", 0.0) or 0.0), 0.4))
                                f = float(det["fusion_score"])
                        except Exception:
                            pass
                    try:
                        det["severity"] = self._severity_from_score(float(det.get("fusion_score", 0.0) or 0.0))
                    except Exception:
                        pass
                    try:
                        det["predicted_attack"] = self._attack_kind_from_signals(bool(obf), str(h_reason) if trig else "", obf_scores=obf_scores)
                    except Exception:
                        pass

                    if f < float(self.config.detection_publish_threshold) and not obf:
                        if self.debug:
                            logger.info("detection_discard reason=below_publish_threshold score=%.4f threshold=%.4f key=%s", float(f), float(self.config.detection_publish_threshold), str(flow.key))
                        continue

                    if f >= 0.7 or obf:
                        bucket["suspicious"] = int(bucket.get("suspicious", 0)) + 1
                    else:
                        bucket["suspicious"] = max(0, int(bucket.get("suspicious", 0)) - 1)

                    allow_alert, allow_block, reason = self._gate_alert_and_block(src_ip, f, obf)
                    det["_allow_alert"] = bool(allow_alert)
                    det["_decision_reason"] = str(reason)
                    if not allow_alert and f >= float(self.config.alert_fusion_threshold):
                        self._suppressed_cooldown += 1
                    if allow_alert:
                        bucket["last_alert"] = now

                    if not bool(self.config.enable_autoblock):
                        allow_block = False
                    if allow_block:
                        det["auto_blocked"] = False
                        det["block_pending"] = True
                        try:
                            self._block_q.put_nowait(
                                {
                                    "raw_feats": raw_feats,
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "predicted_attack": str(det.get("predicted_attack") or "RF/AE Fusion"),
                                    "obf": bool(obf),
                                    "extra": extra_payload,
                                    "autoblock_threshold": float(self.config.autoblock_fusion_threshold),
                                }
                            )
                            bucket["last_block"] = now
                        except Exception:
                            det["block_pending"] = False
                    else:
                        det["auto_blocked"] = False
                        det["block_pending"] = False
                        if det.get("recommended_action") == "BLOCK_IP":
                            det["recommended_action"] = "INVESTIGATE"

                    if self.debug:
                        try:
                            rf_out = self.fusion.rf_predict(raw_feats)
                            ae_out = self.fusion.ae.score(raw_feats, top_k=2)
                            self.counters["rf_predictions"] = int(self.counters.get("rf_predictions", 0)) + 1
                            self.counters["ae_predictions"] = int(self.counters.get("ae_predictions", 0)) + 1
                            try:
                                rf_model = getattr(self.fusion, "rf_model", None)
                                rf_cols = list(getattr(self.fusion, "rf_feature_columns", []) or [])
                                imps = list(getattr(rf_model, "feature_importances_", []) or [])
                                if rf_cols and imps and len(rf_cols) == len(imps):
                                    top_idx = sorted(range(len(imps)), key=lambda i: float(imps[i]), reverse=True)[:5]
                                    top_feats = [(rf_cols[i], float(imps[i]), float(raw_feats.get(rf_cols[i], 0.0) or 0.0)) for i in top_idx]
                                else:
                                    top_feats = []
                            except Exception:
                                top_feats = []
                            logger.info(
                                "model_out key=%s rf_prob=%.4f rf_conf=%.4f ae_score=%.4f ae_err=%.6f fusion=%.4f sev=%s allow_alert=%s allow_block=%s reason=%s top_feats=%s",
                                str(flow.key),
                                float(rf_out.get("malicious_probability", 0.0) or 0.0),
                                float(rf_out.get("confidence", 0.0) or 0.0),
                                float(ae_out.get("anomaly_score", 0.0) or 0.0),
                                float(ae_out.get("reconstruction_error", 0.0) or 0.0),
                                float(det.get("fusion_score", 0.0) or 0.0),
                                str(det.get("severity", "")),
                                str(allow_alert),
                                str(allow_block),
                                str(reason),
                                str(top_feats),
                            )
                        except Exception:
                            logger.error("model debug failed:\n%s", traceback.format_exc())

                    suppress, s_reason = self._should_suppress_noise(det, flow, raw_feats)
                    if suppress:
                        self._suppressed_total += 1
                        if self.debug:
                            logger.info("detection_suppressed reason=%s severity=%s fusion=%.4f key=%s", str(s_reason), str(det.get("severity", "")), float(det.get("fusion_score", 0.0) or 0.0), str(flow.key))
                        continue

                    self._post_detection(det)
                    self._maybe_telegram(det)
                except Exception:
                    if self.debug:
                        logger.error("flow processing failed:\n%s", traceback.format_exc())
                    continue
                finally:
                    lat_ms = (time.perf_counter() - t0) * 1000.0
                    if np.isfinite(lat_ms):
                        self._lat_ms_ema = (self._lat_ms_alpha * float(lat_ms)) + ((1.0 - self._lat_ms_alpha) * float(self._lat_ms_ema))

            if time.time() - last_flush >= float(self.config.flush_interval_seconds):
                try:
                    expired = self.flow_builder.flush_expired(now=self._replay_last_ts + float(self.flow_builder.flow_timeout_seconds) + 0.001 if self._replay_mode and self._replay_last_ts else None)
                except Exception:
                    if self.debug:
                        logger.error("flow_builder.flush_expired failed:\n%s", traceback.format_exc())
                    expired = []
                for flow in expired:
                    self.flows_completed += 1
                    self.counters["flows_completed"] = int(self.counters.get("flows_completed", 0)) + 1
                    t0 = time.perf_counter()
                    try:
                        raw_feats, rf_vec = self.features.extract(flow.packets)
                        src_ip = flow.key[0]
                        dst_ip = flow.key[1]
                        if not self._should_consider_flow(src_ip, dst_ip):
                            self._ignored_non_device += 1
                            if self.debug:
                                logger.info("expired_flow_discard reason=non_device_network key=%s", str(flow.key))
                            continue
                        obf, obf_scores = self._obfuscation_flag(raw_feats, flow_packets=list(getattr(flow, "packets", []) or []))
                        boost, trig, h_reason = self._apply_heuristics(src_ip, int(flow.key[3] or 0), int(flow.key[4] or 0), flow, raw_feats)
                        det = self.fusion.process_event(
                            feature_vector=raw_feats,
                            source_ip=src_ip,
                            destination_ip=dst_ip,
                            predicted_attack="RF/AE Fusion",
                            obfuscation_detected=obf,
                            extra={
                                "packets_in_flow": int(getattr(flow, "packet_count", len(flow.packets))),
                                "flow_bytes": int(getattr(flow, "byte_count", 0)),
                                "flow_key": "|".join([str(x) for x in flow.key]),
                                **obf_scores,
                            },
                            enable_autoblock=False,
                            autoblock_fusion_threshold=float(self.config.autoblock_fusion_threshold),
                            persist=False,
                        )
                        f = self._clamp01(float(det.get("fusion_score", 0.0) or 0.0))
                        det["fusion_score"] = f
                        if trig and boost > 0:
                            det["heuristic_triggered"] = True
                            det["heuristic_reason"] = str(h_reason)
                            det["heuristic_boost"] = float(boost)
                            det["fusion_score"] = self._clamp01(float(det.get("fusion_score", 0.0) or 0.0) + float(boost))
                            f = float(det["fusion_score"])
                        else:
                            det["heuristic_triggered"] = False
                        try:
                            det["severity"] = self._severity_from_score(float(det.get("fusion_score", 0.0) or 0.0))
                        except Exception:
                            pass
                        try:
                            det["predicted_attack"] = self._attack_kind_from_signals(bool(obf), str(h_reason) if trig else "", obf_scores=obf_scores)
                        except Exception:
                            pass
                        if f < float(self.config.detection_publish_threshold) and not obf:
                            if self.debug:
                                logger.info("expired_detection_discard reason=below_publish_threshold score=%.4f key=%s", float(f), str(flow.key))
                            continue
                        allow_alert, allow_block, reason = self._gate_alert_and_block(src_ip, f, obf)
                        det["_allow_alert"] = bool(allow_alert)
                        det["_decision_reason"] = str(reason)
                        if not allow_alert and f >= float(self.config.alert_fusion_threshold):
                            self._suppressed_cooldown += 1
                        if allow_alert:
                            self._ip_bucket(src_ip)["last_alert"] = time.time()

                        suppress, s_reason = self._should_suppress_noise(det, flow, raw_feats)
                        if suppress:
                            self._suppressed_total += 1
                            if self.debug:
                                logger.info("expired_detection_suppressed reason=%s severity=%s fusion=%.4f key=%s", str(s_reason), str(det.get("severity", "")), float(det.get("fusion_score", 0.0) or 0.0), str(flow.key))
                            continue
                        self._post_detection(det)
                        self._maybe_telegram(det)
                    except Exception:
                        if self.debug:
                            logger.error("expired flow processing failed:\n%s", traceback.format_exc())
                        continue
                    finally:
                        lat_ms = (time.perf_counter() - t0) * 1000.0
                        if np.isfinite(lat_ms):
                            self._lat_ms_ema = (self._lat_ms_alpha * float(lat_ms)) + ((1.0 - self._lat_ms_alpha) * float(self._lat_ms_ema))
                last_flush = time.time()

            self._post_telemetry()

            if time.time() - float(self._last_stats_log) >= 5.0:
                self._last_stats_log = time.time()
                stats = self.flow_builder.stats()
                logger.info(
                    "live_telemetry5s packets_seen=%d pkts_filtered=%d flows_created=%d flows_active=%d flows_completed=%d feat_vecs=%d fusion_events=%d written=%d ignored_non_device=%d ignored_small_flow=%d suppressed=%d dropped_pkts=%d dropped_flows=%d thresholds(alert=%.3f block=%.3f) bpf_mode=%s",
                    int(self.counters.get("packets_seen", 0)),
                    int(self.counters.get("packets_filtered", 0)),
                    int(stats.get("flows_created", 0)),
                    int(stats.get("active_flows", 0)),
                    int(self.counters.get("flows_completed", 0)),
                    int(self.counters.get("feature_vectors_generated", 0)),
                    int(self.counters.get("fusion_events", 0)),
                    int(self.counters.get("detections_written", 0)),
                    int(self._ignored_non_device),
                    int(self._ignored_small_flow),
                    int(self._suppressed_cooldown),
                    int(self.dropped_packets),
                    int(stats.get("dropped_flows", 0)),
                    float(self.config.alert_fusion_threshold),
                    float(self.config.autoblock_fusion_threshold),
                    "restrict_to_device_network" if bool(self.config.restrict_to_device_network) else "all_traffic",
                )

        self._workers_stop.set()
        try:
            self.monitor.stop()
        except Exception:
            pass
        try:
            self._executor.shutdown(wait=False, cancel_futures=True)
        except Exception:
            try:
                self._executor.shutdown(wait=False)
            except Exception:
                pass


def main() -> int:
    mode = os.getenv("LIVE_MODE", "sniff").strip().lower()
    iface = os.getenv("LIVE_INTERFACE")
    bpf = os.getenv("LIVE_BPF")
    preset = os.getenv("LIVE_BPF_PRESET", "").strip().lower()
    pcap = os.getenv("LIVE_PCAP")
    replay_pcap = os.getenv("LIVE_REPLAY_PCAP") or pcap
    speed = float(os.getenv("LIVE_REPLAY_SPEED", "1.0"))
    loop = os.getenv("LIVE_REPLAY_LOOP", "0") == "1"
    max_sleep = float(os.getenv("LIVE_REPLAY_MAX_SLEEP", "2.0"))

    if not bpf:
        if preset == "medical_devices_only":
            try:
                import json as _json
                with open("config/device_registry.json", "r", encoding="utf-8") as f:
                    reg = _json.load(f) or {}
                ips = [ip for ip in reg.keys() if isinstance(ip, str) and ip.strip()]
                if ips:
                    hosts = " or ".join([f"host {ip.strip()}" for ip in ips[:50]])
                    bpf = f"({hosts}) and (tcp or udp or icmp)"
            except Exception:
                bpf = None
        elif preset == "local_subnet":
            cidr = os.getenv("LIVE_SUBNET_CIDR", "192.168.0.0/16").strip()
            bpf = f"net {cidr} and (tcp or udp or icmp)"
        else:
            try:
                import json as _json
                with open("config/device_registry.json", "r", encoding="utf-8") as f:
                    reg = _json.load(f) or {}
                ips = [ip for ip in reg.keys() if isinstance(ip, str) and ip.strip()]
                if ips:
                    hosts = " or ".join([f"host {ip.strip()}" for ip in ips[:50]])
                    bpf = f"({hosts}) and (tcp or udp or icmp)"
                else:
                    bpf = "net 192.168.0.0/16 and (tcp or udp or icmp)"
            except Exception:
                bpf = "net 192.168.0.0/16 and (tcp or udp or icmp)"

    logger.setLevel(logging.INFO)
    logger.info(
        "live_start mode=%s iface=%s bpf=%s pcap=%s speed=%.3f loop=%s",
        mode,
        str(iface or ""),
        str(bpf or ""),
        str(replay_pcap or ""),
        float(speed),
        str(bool(loop)),
    )

    monitor_cfg = LiveMonitorConfig(
        interface=iface,
        bpf_filter=bpf,
        pcap_path=None,
        replay_speed=float(speed),
        replay_loop=bool(loop),
        replay_max_sleep_s=float(max_sleep),
    )
    monitor = LivePacketMonitor(monitor_cfg)

    attack_test_mode = os.getenv("LIVE_ATTACK_TEST_MODE", "0") == "1"
    lab_mode = os.getenv("LIVE_LAB_MODE", "0") == "1"

    engine_cfg = LiveEngineConfig(
        flow_timeout_seconds=float(os.getenv("LIVE_FLOW_TIMEOUT", "10")),
        max_packets_per_flow=int(os.getenv("LIVE_MAX_PKTS_PER_FLOW", "2000")),
        max_active_flows=int(os.getenv("LIVE_MAX_ACTIVE_FLOWS", "50000")),
        flush_interval_seconds=float(os.getenv("LIVE_FLUSH_INTERVAL", "1")),
        enable_telegram=os.getenv("LIVE_TELEGRAM", "1") == "1",
        enable_autoblock=os.getenv("LIVE_AUTOBLOCK", "0") == "1",
        autoblock_fusion_threshold=float(os.getenv("LIVE_AUTOBLOCK_THRESHOLD", "0.98")),
        alert_fusion_threshold=float(os.getenv("LIVE_ALERT_THRESHOLD", "0.92")),
        ws_telemetry_interval_seconds=float(os.getenv("LIVE_TELEMETRY_INTERVAL", "1.0")),
        settings_refresh_seconds=float(os.getenv("LIVE_SETTINGS_REFRESH", "2.0")),
        packet_batch_size=int(os.getenv("LIVE_PACKET_BATCH", "512")),
        restrict_to_device_network=os.getenv("LIVE_RESTRICT_TO_DEVICES", "1") == "1",
        min_packets_for_model=int(os.getenv("LIVE_MIN_PKTS", "3")),
        min_bytes_for_model=int(os.getenv("LIVE_MIN_BYTES", "200")),
        detection_publish_threshold=float(os.getenv("LIVE_PUBLISH_THRESHOLD", "0.5")),
        per_ip_alert_cooldown_seconds=float(os.getenv("LIVE_ALERT_COOLDOWN", "20")),
        per_ip_block_cooldown_seconds=float(os.getenv("LIVE_BLOCK_COOLDOWN", "120")),
        attack_test_mode=attack_test_mode,
        heuristic_window_seconds=float(os.getenv("LIVE_HEURISTIC_WINDOW", "10")),
        syn_scan_unique_ports_threshold=int(os.getenv("LIVE_SYN_PORTS_THRESHOLD", "15")),
        lab_mode=lab_mode,
        low_severity_publish=os.getenv("LIVE_PUBLISH_LOW", "0") == "1",
        low_suppression_fusion_max=float(os.getenv("LIVE_LOW_SUPPRESS_MAX", "0.55")),
        heartbeat_interval_seconds=float(os.getenv("LIVE_HEARTBEAT_INTERVAL", "5.0")),
    )

    if mode == "replay":
        if "LIVE_LAB_MODE" not in os.environ:
            engine_cfg.lab_mode = True
        engine_cfg.restrict_to_device_network = False
        if "LIVE_FLOW_TIMEOUT" not in os.environ:
            engine_cfg.flow_timeout_seconds = 0.5
        if "LIVE_FLUSH_INTERVAL" not in os.environ:
            engine_cfg.flush_interval_seconds = 0.25
        if "LIVE_TELEMETRY_INTERVAL" not in os.environ:
            engine_cfg.ws_telemetry_interval_seconds = 0.25
        if "LIVE_PUBLISH_THRESHOLD" not in os.environ:
            engine_cfg.detection_publish_threshold = 0.0
        if "LIVE_MIN_PKTS" not in os.environ:
            engine_cfg.min_packets_for_model = 1
        if "LIVE_MIN_BYTES" not in os.environ:
            engine_cfg.min_bytes_for_model = 0

    if mode == "replay" and os.getenv("LIVE_REPLAY_FORCE_FLUSH", "0") == "1":
        try:
            engine_cfg.flow_timeout_seconds = float(os.getenv("LIVE_REPLAY_FLOW_TIMEOUT", "0.5"))
        except Exception:
            engine_cfg.flow_timeout_seconds = 0.5
        try:
            engine_cfg.flush_interval_seconds = float(os.getenv("LIVE_REPLAY_FLUSH_INTERVAL", "0.25"))
        except Exception:
            engine_cfg.flush_interval_seconds = 0.25

    if attack_test_mode:
        engine_cfg.restrict_to_device_network = False
        engine_cfg.detection_publish_threshold = 0.0
        engine_cfg.min_packets_for_model = 1
        engine_cfg.min_bytes_for_model = 0
        engine_cfg.per_ip_alert_cooldown_seconds = 0.0
        engine_cfg.per_ip_block_cooldown_seconds = 0.0
        if "LIVE_ALERT_THRESHOLD" not in os.environ:
            engine_cfg.alert_fusion_threshold = 0.7
        if "LIVE_AUTOBLOCK_THRESHOLD" not in os.environ:
            engine_cfg.autoblock_fusion_threshold = 0.85

    if lab_mode and not attack_test_mode:
        engine_cfg.restrict_to_device_network = False
        engine_cfg.low_severity_publish = True
        engine_cfg.per_ip_alert_cooldown_seconds = 0.0
        engine_cfg.per_ip_block_cooldown_seconds = 0.0
        if "LIVE_ALERT_THRESHOLD" not in os.environ:
            engine_cfg.alert_fusion_threshold = 0.85
        if "LIVE_AUTOBLOCK_THRESHOLD" not in os.environ:
            engine_cfg.autoblock_fusion_threshold = 0.95
        if "LIVE_AUTOBLOCK" not in os.environ:
            engine_cfg.enable_autoblock = False

    eng = LiveDetectionEngine(monitor, engine_cfg)
    eng.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
