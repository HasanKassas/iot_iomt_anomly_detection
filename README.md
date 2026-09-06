# IoMT Hospital Network Security Monitor

This project (Romanian title: **„Detectarea și prevenirea atacurilor cibernetice asupra dispozitivelor medicale IoT utilizând tehnici de învățare automată”**) implements a real-time anomaly detection + monitoring stack for Internet of Medical Things (IoMT) devices in a hospital-like network.

It combines:
- ML detection (Random Forest + Autoencoder) using flow-level features
- Obfuscation and heuristic signals (SYN scan, fragmentation, timing jitter) for more reliable lab replays
- A live SOC dashboard (Streamlit) fed by a Node.js API + WebSocket broadcaster
- Manual response (block/unblock) from the dashboard
- Telegram alerts (rate-limited + de-duplicated per attacking IP)

For the full, detailed documentation (intended as the base for a long report), see [DOCUMENTATION.md](file:///d:/iot_iomt_anomly_detection/DOCUMENTATION.md).

## Key Features
- **Real-Time IDS Pipeline**: Packet → Flow → Feature extraction → RF + AE inference → Fusion score → Severity → Publish to API → Live dashboard.
- **Attack Labels in Live Feed**: `SYN_SCAN`, `FRAGMENTATION`, `TIMING_JITTER`, `OBFUSCATION`, or `RF/AE Fusion`.
- **Severity Bands (Project Rule)**:
  - `LOW`: < 0.4
  - `MEDIUM`: 0.4–0.7
  - `HIGH`: 0.7–1.0
  - `CRITICAL`: > 1.0 (rare; can happen if you boost beyond 1.0 in some paths)
- **Telegram Alerts**: Sends only for `MEDIUM/HIGH/CRITICAL` (configurable), with dedupe “once per source IP per 5 minutes”.
- **Manual Response**: Block/Unblock any attacking source IP from the dashboard (no automatic blocking by default).
- **Replay Lab Mode**: Generate and replay attack PCAPs (SYN scan, port scan, fragmentation, jitter).

## Architecture (High Level)
- **Detector (Python)**: [live_detection_engine.py](file:///d:/iot_iomt_anomly_detection/src/realtime/live_detection_engine.py)
  - Consumes packets (sniff or replay), builds flows, extracts features, runs models, applies heuristics, publishes detections.
- **API + WebSocket (Node.js)**: [server.js](file:///d:/iot_iomt_anomly_detection/api/server.js)
  - Stores recent detections/alerts/blocked IPs in `logs/` and broadcasts updates to connected dashboards.
- **Dashboard (Streamlit)**: [dashboard.py](file:///d:/iot_iomt_anomly_detection/dashboard.py)
  - Shows SOC view: live attack feed, device risk status, metrics, manual block/unblock.
- **Models (Artifacts)**: `models/`
  - Random Forest: `models/anomaly_model.pkl`
  - Autoencoder: `models/autoencoder_optimized.keras` + scaler + thresholds
- **Device Registry (Metadata)**: [device_registry.json](file:///d:/iot_iomt_anomly_detection/config/device_registry.json)
  - Maps IP → device name, department, room, criticality.

## Quick Start (Windows / PowerShell)
Run these in separate terminals.

### 1) Python environment
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2) Configure Telegram (optional but recommended)
Create/edit `.env` in the repo root:
```env
TELEGRAM_BOT_TOKEN=123456:ABCDEF...
TELEGRAM_CHAT_ID=123456789
```

### 3) Start the API (Node.js)
```powershell
cd api
npm install
npm run start
```

### 4) Start the dashboard
```powershell
cd ..
.\venv\Scripts\Activate.ps1
streamlit run dashboard.py
```

### 5) Run the detector (replay lab mode)
```powershell
cd ..
.\venv\Scripts\Activate.ps1
python -m src.realtime.replay_attack_demo --scenario syn_scan --dst 192.168.100.10 --lab --speed 1.0 --loop
```

## Model Evaluation (Offline)
Generates clean plots and a metrics table in `results/`:
```powershell
.\venv\Scripts\Activate.ps1
python main.py
```

Outputs:
- `results/class_distribution.png`
- `results/confusion_matrix_rf.png`
- `results/confusion_matrix_ae.png`
- `results/model_comparison.csv`

## Useful Commands (Attacks)
All via the replay demo runner:
```powershell
python -m src.realtime.replay_attack_demo --scenario syn_scan --dst 192.168.100.10 --lab --loop
python -m src.realtime.replay_attack_demo --scenario portscan --dst 192.168.100.10 --lab --loop
python -m src.realtime.replay_attack_demo --scenario fragmentation --dst 192.168.100.10 --lab --loop
python -m src.realtime.replay_attack_demo --scenario jitter --dst 192.168.100.10 --lab --loop
```

## Troubleshooting
- If Telegram does not send: confirm `.env` exists in the project root and contains `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`.
- If a script says `No module named 'src'`: always run tools as modules (example: `python -m src.realtime.replay_attack_demo ...`) from the repo root.
- To wipe live history in the dashboard: the replay demo sets `LIVE_CLEAR_HISTORY_ON_START=1` automatically in lab mode; you can also POST `{"clear_history": true}` to `/live/settings`.
