import sys

try:
    import streamlit as st
    import pandas as pd
    import plotly.express as px
    import plotly.graph_objects as go
    import websocket
    import requests
except Exception as exc:
    sys.stderr.write(
        "Missing Python dependencies for dashboard.\n"
        "Create a virtual environment and install requirements:\n"
        "  python -m venv .venv\n"
        "  .\\.venv\\Scripts\\Activate.ps1\n"
        "  pip install -r requirements.txt\n"
        f"Error: {exc}\n"
    )
    raise SystemExit(1)

import json
import os
import queue
import threading
import time
from collections import deque
from datetime import datetime, timezone

# -------------------------------------------------
# PAGE CONFIG
# -------------------------------------------------

st.set_page_config(
    page_title="IoMT Hospital Security Monitor",
    layout="wide"
)

# -------------------------------------------------
# STYLE
# -------------------------------------------------

st.markdown("""
<style>

body{
background-color:#0b0f17;
}

.login-box{
background-color:#111827;
padding:30px;
border-radius:12px;
border:1px solid #00ffaa33;
}

.metric-box{
background-color:#111827;
padding:20px;
border-radius:10px;
border:1px solid #00ffaa33;
text-align:center;
}

.metric-value{
font-size:40px;
color:#00ffaa;
font-weight:bold;
}

.device-box{
background-color:#0f172a;
padding:20px;
border-radius:10px;
border:1px solid #1f2937;
text-align:center;
}

.soc-feed{
  background-color:#0f172a;
  border:1px solid #1f2937;
  border-radius:10px;
  padding:12px;
  height:420px;
  overflow-y:auto;
}

.sev-CRITICAL{ color:#ff4d4f; font-weight:700; }
.sev-HIGH{ color:#ff7a45; font-weight:700; }
.sev-MEDIUM{ color:#fadb14; font-weight:700; }
.sev-LOW{ color:#73d13d; font-weight:700; }

.tag{
  display:inline-block;
  padding:2px 8px;
  border-radius:999px;
  border:1px solid #1f2937;
  background:#111827;
  font-size:12px;
  margin-left:6px;
}

</style>
""", unsafe_allow_html=True)

# -------------------------------------------------
# LIVE STREAM (WEBSOCKET)
# -------------------------------------------------

def _api_url() -> str:
    return os.getenv("IOMT_API_URL", "http://localhost:3001").rstrip("/")


def _ws_url(api_url: str) -> str:
    u = (api_url or "").strip()
    if u.startswith("https://"):
        u = "wss://" + u[len("https://") :]
    elif u.startswith("http://"):
        u = "ws://" + u[len("http://") :]
    return u.rstrip("/") + "/ws"


def _ensure_live_state():
    if "ws_queue" not in st.session_state:
        st.session_state.ws_queue = queue.Queue()
    if "ws_stop" not in st.session_state:
        st.session_state.ws_stop = threading.Event()
    if "live_state" not in st.session_state:
        st.session_state.live_state = {
            "detections": deque(maxlen=500),
            "alerts": deque(maxlen=500),
            "blocked": {},
            "telemetry": {},
            "settings": {},
            "devices": {},
            "heartbeat": {},
            "connected": False,
            "last_ws_error": "",
        }


def _ws_worker(ws_url: str, out_q: "queue.Queue[dict]", stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            ws = websocket.create_connection(ws_url, timeout=3)
            ws.settimeout(1)
            out_q.put({"type": "_status", "data": {"connected": True, "last_ws_error": ""}})
            while not stop_event.is_set():
                try:
                    raw = ws.recv()
                except websocket.WebSocketTimeoutException:
                    continue
                if not raw:
                    continue
                try:
                    msg = json.loads(raw)
                    if isinstance(msg, dict) and "type" in msg:
                        out_q.put(msg)
                except Exception:
                    continue
        except Exception as e:
            out_q.put({"type": "_status", "data": {"connected": False, "last_ws_error": str(e)}})
            time.sleep(1.0)
        finally:
            try:
                ws.close()
            except Exception:
                pass


def _ensure_ws_started(api_url: str):
    _ensure_live_state()
    t = st.session_state.get("ws_thread")
    if t is not None and getattr(t, "is_alive", lambda: False)():
        return
    ws_url = _ws_url(api_url)
    t = threading.Thread(target=_ws_worker, args=(ws_url, st.session_state.ws_queue, st.session_state.ws_stop), daemon=True)
    st.session_state.ws_thread = t
    t.start()


def _drain_ws():
    _ensure_live_state()
    state = st.session_state.live_state
    q = st.session_state.ws_queue
    drained = 0
    while drained < 500:
        try:
            msg = q.get_nowait()
        except Exception:
            break
        drained += 1

        mtype = msg.get("type")
        data = msg.get("data")
        if mtype == "_status" and isinstance(data, dict):
            state["connected"] = bool(data.get("connected"))
            state["last_ws_error"] = str(data.get("last_ws_error") or "")
            continue
        if mtype == "init" and isinstance(data, dict):
            state["detections"].clear()
            state["alerts"].clear()
            for d in data.get("detections") or []:
                if isinstance(d, dict):
                    state["detections"].append(d)
            for a in data.get("alerts") or []:
                if isinstance(a, dict):
                    state["alerts"].append(a)
            blocked = {}
            for b in data.get("blocked") or []:
                if isinstance(b, dict) and b.get("ip"):
                    blocked[str(b.get("ip"))] = b
            state["blocked"] = blocked
            state["telemetry"] = data.get("telemetry") or {}
            state["heartbeat"] = data.get("heartbeat") or {}
            state["settings"] = data.get("settings") or {}
            state["devices"] = data.get("devices") or {}
            continue
        if mtype == "detection" and isinstance(data, dict):
            state["detections"].append(data)
            continue
        if mtype == "alert" and isinstance(data, dict):
            state["alerts"].append(data)
            continue
        if mtype == "blocked" and isinstance(data, dict) and data.get("ip"):
            state["blocked"][str(data.get("ip"))] = data
            continue
        if mtype == "unblocked" and isinstance(data, dict) and data.get("ip"):
            state["blocked"].pop(str(data.get("ip")), None)
            continue
        if mtype == "telemetry" and isinstance(data, dict):
            state["telemetry"] = data
            continue
        if mtype == "heartbeat" and isinstance(data, dict):
            state["heartbeat"] = data
            continue
        if mtype == "settings" and isinstance(data, dict):
            state["settings"] = data
            continue


def _post_settings(api_url: str, payload: dict) -> bool:
    try:
        r = requests.post(f"{api_url}/live/settings", json=payload, timeout=2)
        return bool(r.ok)
    except Exception:
        return False


def _post_unblock(api_url: str, ip: str) -> bool:
    try:
        r = requests.post(f"{api_url}/live/unblock/{ip}", json={"operator": "dashboard"}, timeout=4)
        return bool(r.ok)
    except Exception:
        return False


def _post_block(api_url: str, ip: str) -> bool:
    try:
        r = requests.post(f"{api_url}/live/block/{ip}", json={"operator": "dashboard"}, timeout=4)
        return bool(r.ok)
    except Exception:
        return False


def _post_ack(api_url: str, kind: str, item_id: str) -> bool:
    try:
        r = requests.post(f"{api_url}/live/ack", json={"kind": kind, "id": item_id}, timeout=2)
        return bool(r.ok)
    except Exception:
        return False

# -------------------------------------------------
# TITLE
# -------------------------------------------------

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

admin_user = os.getenv("DASHBOARD_ADMIN_USER", "admin")
admin_pass = os.getenv("DASHBOARD_ADMIN_PASS", "admin123")

if not st.session_state.authenticated:
    st.markdown("<br><br>", unsafe_allow_html=True)
    c1, c2, c3 = st.columns([1, 1, 1])
    with c2:
        st.markdown('<div class="login-box">', unsafe_allow_html=True)
        st.markdown("### Network Monitoring")
        with st.form("login_form", clear_on_submit=False):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login")
        st.markdown("</div>", unsafe_allow_html=True)

        if submitted:
            if username == admin_user and password == admin_pass:
                st.session_state.authenticated = True
                st.rerun()
            else:
                st.error("Invalid username or password")

    st.stop()

with st.sidebar:
    if st.button("Logout"):
        st.session_state.authenticated = False
        st.rerun()

    api_url_input = st.text_input("API URL", value=_api_url(), help="Example: http://localhost:3001").rstrip("/")
    st.session_state.api_url = api_url_input
    _ensure_ws_started(api_url_input)
    _drain_ws()
    _ensure_live_state()
    state = st.session_state.live_state

    if state.get("connected"):
        st.success("Websocket: connected")
    else:
        st.warning("Websocket: disconnected")
        if state.get("last_ws_error"):
            st.caption(state.get("last_ws_error"))

    hb = state.get("heartbeat") or {}
    hb_recv = str(hb.get("received_at") or "")
    hb_age_s = None
    offline_thr = 30.0
    try:
        offline_thr = float(os.getenv("HEARTBEAT_OFFLINE_SECONDS", "30"))
    except Exception:
        offline_thr = 30.0
    offline_thr = max(5.0, min(offline_thr, 120.0))
    try:
        if hb_recv:
            dt = datetime.fromisoformat(hb_recv.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            hb_age_s = max(0.0, (datetime.now(timezone.utc) - dt).total_seconds())
    except Exception:
        hb_age_s = None

    if hb_age_s is not None and hb_age_s <= offline_thr:
        st.success(f"Detector: online ({hb_age_s:.1f}s)")
    else:
        st.warning("Detector: offline")

    tlm = state.get("telemetry") or {}
    if isinstance(tlm, dict):
        st.caption(
            f"API online={tlm.get('api_online')} post_failed={tlm.get('api_post_failed_total')} post_q={tlm.get('api_post_queue_size')} backlog={tlm.get('api_backlog_size')}"
        )

    current = state.get("settings") or {}
    telegram_enabled = st.toggle("Telegram alerts", value=bool(current.get("telegram_enabled", True)))
    alert_thr = st.slider("Alert threshold", min_value=0.0, max_value=1.0, value=float(current.get("alert_fusion_threshold", 0.6)), step=0.01)

    if st.button("Apply Controls"):
        ok = _post_settings(
            api_url_input,
            {
                "autoblock_enabled": False,
                "telegram_enabled": bool(telegram_enabled),
                "alert_fusion_threshold": float(alert_thr),
            },
        )
        if ok:
            st.success("Updated")
        else:
            st.error("Failed to update")

st.title("🏥 IoMT Hospital Network Security Monitor")
st.caption("Real-Time Intrusion Detection for Medical Devices")

# -------------------------------------------------
# LIVE VIEW
# -------------------------------------------------

@st.fragment(run_every="2s")
def live_view():
    api_url = (st.session_state.get("api_url") or _api_url()).rstrip("/")

    try:
        traffic = pd.DataFrame(requests.get(f"{api_url}/api/traffic?limit=2000", timeout=2).json())
    except Exception:
        st.warning(f"Waiting for API at {api_url} ...")
        return

    required_cols = ["timestamp","src_ip","dst_ip","proto","packet_size","prediction"]

    for col in required_cols:
        if col not in traffic.columns:
            traffic[col] = 0

    traffic["timestamp"] = pd.to_datetime(traffic["timestamp"], errors="coerce")

    if "status" not in traffic.columns:
        traffic["status"] = traffic["prediction"].map({1: "ANOMALY", 0: "NORMAL"})
        traffic["status"].fillna("NORMAL", inplace=True)

    proto_series = traffic["proto"]
    if proto_series.dtype == object:
        proto_lower = proto_series.astype(str).str.lower().str.strip()
        proto_mapped = proto_lower.map({"icmp": 1, "tcp": 6, "udp": 17})
        traffic["proto"] = proto_mapped.fillna(pd.to_numeric(proto_series, errors="coerce")).fillna(0).astype(int)
    else:
        traffic["proto"] = pd.to_numeric(proto_series, errors="coerce").fillna(0).astype(int)

    PROTO_MAP = {
        1:"ICMP",
        6:"TCP",
        17:"UDP"
    }

    traffic["protocol"] = traffic["proto"].map(PROTO_MAP)
    traffic["protocol"].fillna("OTHER", inplace=True)

    DEVICE_MAP = {
    "192.168.100.10":"MRI Scanner",
    "192.168.100.11":"ECG Monitor",
    "192.168.100.12":"Infusion Pump",
    "192.168.100.13":"Patient Monitor",
    "192.168.100.14":"Nurse Station",
    "192.168.100.15":"Hospital Server"
    }

    traffic["device"] = traffic["dst_ip"].map(DEVICE_MAP)
    traffic["device"].fillna("External Device", inplace=True)

    try:
        metrics = requests.get(f"{api_url}/api/metrics", timeout=2).json()
        total = int(metrics.get("total", len(traffic)))
        normal = int(metrics.get("normal", len(traffic[traffic["prediction"] == 0])))
        anomalies = int(metrics.get("anomalies", len(traffic[traffic["prediction"] == 1])))
        devices = int(metrics.get("devices", traffic["src_ip"].nunique()))
        blocked = int(metrics.get("blocked", 0))
        obfuscated = int(metrics.get("obfuscated", 0))
        obfuscated_anomalies = int(metrics.get("obfuscated_anomalies", 0))
    except Exception:
        total = len(traffic)
        normal = len(traffic[traffic["prediction"]==0])
        anomalies = len(traffic[traffic["prediction"]==1])
        devices = traffic["src_ip"].nunique()
        blocked = 0
        obfuscated = 0
        obfuscated_anomalies = 0

    c1,c2,c3,c4,c5,c6 = st.columns(6)

    c1.metric("Packets", total)
    c2.metric("Normal Traffic", normal)
    c3.metric("Anomalies", anomalies)
    c4.metric("Devices", devices)
    c5.metric("Blocked IPs", blocked)
    if obfuscated > 0:
        c6.metric("Obfuscated", obfuscated, delta=f"{obfuscated_anomalies} attacks", delta_color="inverse")
    else:
        c6.metric("Obfuscated", 0)

    st.divider()
    st.subheader("IoMT Device Security Status")

    cols = st.columns(3)

    for i,(ip,name) in enumerate(DEVICE_MAP.items()):

        device_data = traffic[traffic["dst_ip"]==ip]

        if len(device_data)==0:
            status="🟢 SAFE"
        else:

            recent=device_data.tail(30)

            if (recent["prediction"]==1).sum()>3:
                status="🔴 UNDER ATTACK"

            elif (recent["prediction"]==1).sum()>0:
                status="🟡 SUSPICIOUS"

            else:
                status="🟢 SAFE"

        with cols[i%3]:

            st.markdown(f"""
            <div class="device-box">
            <h4>{name}</h4>
            <h2>{status}</h2>
            </div>
            """,unsafe_allow_html=True)

    st.divider()
    st.subheader("Network Activity")

    recent = traffic.sort_values("timestamp").tail(500)

    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=recent["timestamp"],
        y=recent["packet_size"],
        mode="lines"
    ))

    fig.update_layout(template="plotly_dark")

    st.plotly_chart(fig, use_container_width=True)

    col1,col2 = st.columns(2)

    with col1:

        st.subheader("Protocol Distribution")

        proto_counts = traffic["protocol"].value_counts()

        fig2 = px.pie(
            names=proto_counts.index,
            values=proto_counts.values
        )

        fig2.update_layout(template="plotly_dark")

        st.plotly_chart(fig2, use_container_width=True)

    with col2:

        st.subheader("Top Attack Sources")

        attackers = traffic[traffic["prediction"]==1]["src_ip"].value_counts().head(10)

        if len(attackers)>0:

            fig3 = px.bar(
                x=attackers.index,
                y=attackers.values
            )

            fig3.update_layout(template="plotly_dark")

            st.plotly_chart(fig3, use_container_width=True)

        else:

            st.success("No attacks detected")

    st.divider()
    st.subheader("Attack Timeline")

    attacks = traffic[traffic["prediction"]==1].tail(200)

    if len(attacks)>0:

        fig4 = px.scatter(
            attacks,
            x="timestamp",
            y="device",
            color="src_ip"
        )

        fig4.update_layout(template="plotly_dark")

        st.plotly_chart(fig4, use_container_width=True)

    st.divider()
    st.subheader("Recent Alerts")

    try:
        alerts = pd.DataFrame(requests.get(f"{api_url}/api/alerts?limit=200", timeout=2).json())
        if len(alerts) > 0:
            st.dataframe(alerts.tail(20), use_container_width=True)
        else:
            st.success("No alerts logged yet")
    except Exception:
        st.success("No alerts logged yet")

    st.divider()
    st.subheader("Live Network Traffic")

    st.dataframe(traffic.tail(50), use_container_width=True)

@st.fragment(run_every="1s")
def soc_view():
    api_url = (st.session_state.get("api_url") or _api_url()).rstrip("/")
    _ensure_ws_started(api_url)
    _drain_ws()
    _ensure_live_state()
    state = st.session_state.live_state

    if not state.get("devices"):
        try:
            state["devices"] = requests.get(f"{api_url}/live/devices", timeout=2).json()
        except Exception:
            state["devices"] = {}

    detections = list(state["detections"])
    alerts = list(state["alerts"])
    blocked = state.get("blocked") or {}
    telemetry = state.get("telemetry") or {}
    settings = state.get("settings") or {}

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Packets/sec", f'{telemetry.get("packets_per_sec", 0):.1f}')
    c2.metric("Flows/sec", f'{telemetry.get("flows_per_sec", 0):.1f}')
    c3.metric("Queue", int(telemetry.get("queue_size", 0)))
    c4.metric("Blocked IPs", len(blocked))

    st.divider()

    left, right = st.columns([2, 1])
    with left:
        st.subheader("LIVE ATTACK FEED")
        feed = detections[-60:]
        rows = []
        for d in reversed(feed):
            sev = str(d.get("severity", "LOW")).upper()
            ts = str(d.get("timestamp", ""))
            src = str(d.get("source_ip", ""))
            dst = str(d.get("destination_ip", ""))
            dev = str(d.get("device_name", ""))
            atk = str(d.get("predicted_attack", "") or "")
            score = float(d.get("fusion_score", 0.0) or 0.0)
            badge = f'<span class="sev-{sev}">{sev}</span>'
            label = f" — {atk}" if atk else ""
            rows.append(f"<div>{badge} <span class='tag'>{score:.3f}</span> {ts} — {src} → {dev or dst}{label}</div>")
        st.markdown("<div class='soc-feed'>" + "".join(rows) + "</div>", unsafe_allow_html=True)

    with right:
        st.subheader("ACTIVE THREATS")
        high = [d for d in detections if str(d.get("severity", "")).upper() in {"HIGH", "CRITICAL"}]
        high = high[-50:]
        if high:
            df = pd.DataFrame(high)[
                [
                    "timestamp",
                    "source_ip",
                    "destination_ip",
                    "device_name",
                    "severity",
                    "fusion_score",
                    "auto_blocked",
                ]
            ]
            st.dataframe(df.tail(15), use_container_width=True, height=260)
        else:
            st.info("No high-severity threats yet")

        st.divider()
        recent_sources = []
        seen = set()
        for d in reversed(detections[-200:]):
            if not isinstance(d, dict):
                continue
            ip = str(d.get("source_ip", "")).strip()
            if not ip:
                continue
            if ip in seen:
                continue
            seen.add(ip)
            recent_sources.append(ip)
            if len(recent_sources) >= 50:
                break
        selected_src = st.selectbox("Attacking IP", options=[""] + recent_sources)
        if selected_src and st.button("Block Selected IP"):
            ok = _post_block(api_url, selected_src)
            if ok:
                st.success("Blocked")
            else:
                st.error("Block failed")

        blocked_list = sorted(list(blocked.keys()))
        selected = st.selectbox("Blocked IP", options=[""] + blocked_list)
        if selected and st.button("Unblock Selected IP"):
            ok = _post_unblock(api_url, selected)
            if ok:
                st.success("Unblocked")
            else:
                st.error("Unblock failed")

        unacked = [a for a in alerts if not bool(a.get("acknowledged"))]
        if unacked:
            choices = [f'{a.get("id","")} | {a.get("severity","")} | {a.get("source_ip","")}' for a in unacked if a.get("id")]
            choice = st.selectbox("Unacked alert", options=[""] + choices)
            if choice and st.button("Acknowledge Alert"):
                item_id = choice.split("|", 1)[0].strip()
                ok = _post_ack(api_url, "alert", item_id)
                if ok:
                    st.success("Acknowledged")
                else:
                    st.error("Ack failed")

    st.divider()
    st.subheader("HOSPITAL DEVICE MAP")
    reg = state.get("devices") or {}
    device_items = list(reg.items()) if isinstance(reg, dict) else []
    if not device_items:
        st.info("No devices loaded")
    else:
        cols = st.columns(3)
        for i, (ip, meta) in enumerate(device_items):
            meta = meta if isinstance(meta, dict) else {}
            name = meta.get("device_name") or ip
            dept = meta.get("department") or "-"
            room = meta.get("room") or "-"
            recent = [d for d in detections[-200:] if str(d.get("destination_ip", "")) == str(ip)]
            risk = "🟢 SAFE"
            sev_set = {str(d.get("severity", "")).upper() for d in recent if isinstance(d, dict)}
            if "CRITICAL" in sev_set or "HIGH" in sev_set:
                risk = "🔴 UNDER ATTACK"
            elif "MEDIUM" in sev_set:
                risk = "🟡 SUSPICIOUS"
            with cols[i % 3]:
                st.markdown(
                    f"""
                    <div class="device-box">
                      <h4>{name}</h4>
                      <div>{dept} — {room}</div>
                      <h2>{risk}</h2>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

    st.divider()
    st.subheader("MODEL CONFIDENCE + OBFUSCATION")
    recent_for_metrics = detections[-200:] if detections else []
    def _max_metric(key: str) -> float:
        m = 0.0
        for d in recent_for_metrics:
            if not isinstance(d, dict):
                continue
            try:
                v = float(d.get(key, 0.0) or 0.0)
            except Exception:
                v = 0.0
            if v > m:
                m = v
        return float(m)

    latest = detections[-1] if detections else {}
    mc1, mc2, mc3, mc4, mc5, mc6 = st.columns(6)
    mc1.metric("RF conf", f'{float(latest.get("random_forest_confidence", 0.0) or 0.0):.3f}')
    mc2.metric("AE score", f'{float(latest.get("autoencoder_score", 0.0) or 0.0):.3f}')
    mc3.metric("Fusion", f'{float(latest.get("fusion_score", 0.0) or 0.0):.3f}')
    mc4.metric("Jitter", f'{_max_metric("timing_jitter_score"):.3f}')
    mc5.metric("Frag", f'{_max_metric("fragmentation_anomaly_score"):.3f}')
    mc6.metric("Header", f'{_max_metric("header_consistency_score"):.3f}')


tab_soc = st.tabs(["SOC Live"])[0]
with tab_soc:
    soc_view()

