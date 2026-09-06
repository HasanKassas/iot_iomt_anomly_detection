# IoMT Hospital Network Security Monitor — Full Documentation

## Abstract
The Internet of Medical Things (IoMT) introduces significant cybersecurity risk in hospital environments because medical devices are often resource-constrained, long-lived, and deployed in networks where availability and integrity are critical. This project implements a real-time anomaly detection and response stack designed for an IoMT-style hospital network.

The system processes traffic as packets and flows, extracts features, runs a hybrid detection strategy (Random Forest + Autoencoder), computes a fused risk score, labels likely attack types using heuristics (SYN scan, fragmentation, timing jitter) and obfuscation signals, and publishes events to a Node.js API. A Streamlit dashboard provides a Security Operations Center (SOC) view for live monitoring and manual response (block/unblock). Telegram alerts provide real-time notification with de-duplication to avoid spamming.

## Table of Contents
- 1. Problem Statement and Motivation
- 2. Project Goals and Requirements
- 3. System Overview
- 4. Data and Dataset
- 5. Feature Engineering and Preprocessing
- 6. Machine Learning Models
- 7. Fusion Scoring and Severity Mapping
- 8. Real-Time Detection Pipeline
- 9. Attack Labeling (Heuristics)
- 10. Obfuscation Detection
- 11. API + WebSocket Server (Node.js)
- 12. Streamlit Dashboard (SOC UI)
- 13. Telegram Notifications
- 14. Manual Response (Block/Unblock)
- 15. PCAP Replay and Attack Simulation
- 16. Configuration Reference (Environment Variables)
- 17. Logging, Persistence, and Storage
- 18. Validation and Testing
- 19. Limitations and Threats to Validity
- 20. Future Work
- Appendix A: Event Schemas (Detection, Alert, Telemetry)
- Appendix B: File/Module Map

---

## 1. Problem Statement and Motivation
Hospitals depend on connected systems (patient monitors, infusion pumps, ventilators, gateways). These devices exchange sensitive information and often interact with critical workflows. Attacks against IoMT devices can cause:
- Loss of availability (denial-of-service impacts patient monitoring).
- Integrity violations (tampering with device telemetry or control messages).
- Privacy breaches (exfiltration of patient data).
- Lateral movement in the hospital network (pivoting from weak IoT devices to core systems).

Traditional IT security tools are often not sufficient because IoMT traffic patterns differ from enterprise traffic, and devices may be difficult to patch. Therefore, a monitoring + anomaly detection stack tailored for IoMT is a practical defense layer.

---

## 2. Project Goals and Requirements

### 2.1 Functional goals
- Monitor traffic and detect anomalies in (near) real time.
- Provide operator visibility via a dashboard (live attack feed, device status).
- Provide notifications (Telegram) for actionable severities.
- Provide manual response capability (block/unblock source IPs).
- Support repeatable lab demonstrations using PCAP replays and synthetic attack generation.

### 2.2 Non-functional goals
- Stability: the pipeline must not deadlock or stall when network conditions are noisy.
- Explainability: provide useful metadata (device enrichment, severity label, attack label, contributing features).
- Configurability: allow thresholds and features to be tuned (via environment variables and/or config files).

---

## 3. System Overview

### 3.1 High-level architecture
The system is a 3-component stack:

1) **Detector (Python)**  
Consumes packets (sniff or replay), builds flows, extracts features, runs detection logic, and publishes results.

2) **API + WebSocket (Node.js)**  
Receives detection events, stores recent history, and broadcasts real-time updates via WebSocket to the dashboard.

3) **Dashboard (Streamlit / Python)**  
Connects to the WebSocket endpoint to render live attack feed, device map, and manual response controls.

### 3.2 Data flow (event pipeline)
Packet ingestion → Flow aggregation → Feature extraction → RF prediction → AE reconstruction error → Fusion score → Severity + labels → POST to API → Broadcast to dashboard → Optional Telegram alert.

---

## 4. Data and Dataset

### 4.1 Included data files
The repository includes example datasets under `data/`:
- `data/train_test_network.csv`: main dataset used by `main.py` for evaluation.
- `data/iomt_large_test_dataset_50k.csv`: additional dataset (may be used for experiments).

### 4.2 Labeling convention
The offline evaluation expects a binary label:
- `label = 0` → normal traffic
- `label = 1` → attack/anomaly

If the dataset does not include a `label` column, the evaluation script will fail by design.

---

## 5. Feature Engineering and Preprocessing

### 5.1 Purpose
Network traffic includes many fields that are not directly useful for statistical ML (string fields, hostnames, MIME types). Preprocessing converts the raw dataset into a numeric matrix compatible with scikit-learn and TensorFlow models.

### 5.2 Preprocessing steps
The preprocessing logic is implemented in:
- `src/preprocessing.py`
- `src/evaluate_comparison.py` (for evaluation)

Core steps:
1) Remove duplicates.
2) Replace `"-"` with `NaN` then fill missing values with `0`.
3) Drop non-useful columns (IP addresses, application strings, Zeek-like metadata fields).
4) One-hot encode remaining categorical columns.
5) Ensure numeric-only matrix.
6) Align columns with `models/feature_columns.pkl` if present.
7) Apply standard scaling using `models/scaler.pkl` (Random Forest pipeline) and `models/autoencoder_scaler.pkl` (Autoencoder pipeline).

### 5.3 Feature column alignment (critical for deployment)
The runtime expects feature vectors to match the training schema. To guarantee compatibility:
- Feature column names are stored in `models/feature_columns.pkl`.
- Input data is reindexed to this schema at inference time.

---

## 6. Machine Learning Models

The project uses two complementary models:
- A **Random Forest classifier** trained on flow-level feature vectors.
- An **Autoencoder** trained to reconstruct normal traffic patterns, producing anomaly scores from reconstruction error.

### 6.1 Random Forest
File: `src/train_model.py`
- `n_estimators=200`
- `class_weight="balanced"`
- `random_state=42`
- `n_jobs=-1`

Model artifact:
- `models/anomaly_model.pkl`

Inference behavior:
- If the model exposes `predict_proba`, the probability of class `1` is used as `malicious_probability`.
- Confidence is computed as `max(p, 1-p)`.

### 6.2 Autoencoder
File: `src/models/autoencoder_inference.py`

Artifacts:
- `models/autoencoder_optimized.keras` (TensorFlow model)
- `models/autoencoder_scaler.pkl` (scaler for AE input space)
- `models/autoencoder_threshold.json` (threshold metadata)
- `models/ae_thresholds.json` (optional: percentile-based thresholds)

Core concept:
- Compute reconstruction error as mean squared error (MSE) between input and reconstruction.
- Compare MSE to a threshold (prefer p99 if available).
- Produce:
  - `prediction` (0/1)
  - `anomaly_score` (normalized ratio; capped)
  - `confidence` (derived from distance between p95/p99/p999 thresholds when available)
  - `top_contributing_features` (highest per-feature reconstruction error contributions)

---

## 7. Fusion Scoring and Severity Mapping

### 7.1 Why fusion?
Random Forest is supervised and can be strong when training labels represent the environment well. Autoencoder is unsupervised/one-class oriented and is useful for unseen anomalies. Fusing the outputs provides robustness.

### 7.2 Fusion score calculation
File: `src/realtime/fusion_engine.py`

Inputs:
- RF probability: `rf_prob` ∈ [0,1]
- AE normalized score: `ae_score` ∈ [0,1] (AE anomaly score normalized from [0,10] to [0,1])
- Obfuscation flag: optional weight when `obfuscation_detected=True`

Default weights:
- RF: 0.7
- AE: 0.3
- Obfuscation: +0.1 (only if obfuscation detected)

The fusion score also uses an EMA (exponential moving average) per source IP to smooth spikes:
- `fusion_score = alpha*fusion_raw + (1-alpha)*fusion_prev`
- `alpha = 0.25` by default

### 7.3 Severity mapping
The project uses the following banding rule throughout the runtime:
- `LOW`: score < 0.4
- `MEDIUM`: 0.4 ≤ score < 0.7
- `HIGH`: 0.7 ≤ score ≤ 1.0
- `CRITICAL`: score > 1.0

Important note:
- The core fusion computation clamps to [0,1], but some boosted paths may temporarily push above 1.0 before clamping in some logic. The runtime includes a `CRITICAL` band to match the project requirement even if it is rarely reached.

---

## 8. Real-Time Detection Pipeline

### 8.1 Live engine responsibilities
Main file: `src/realtime/live_detection_engine.py`

Responsibilities:
- Start packet monitoring (sniff mode) or inject packets (replay mode).
- Build flows based on 5-tuple key `(src_ip, dst_ip, src_port, dst_port, proto)`.
- Extract flow features into a vector compatible with RF/AE models.
- Compute obfuscation signals and heuristics.
- Compute and publish detections to the API.
- Publish telemetry (packets/sec, flows/sec, queue size).
- Trigger Telegram notifications (after API publish when configured).

### 8.2 Flow building
File: `src/realtime/live_flow_builder.py`

Key logic:
- Flows are tracked by 5-tuple key and direction is inferred by matching reverse keys.
- Each flow keeps counters (packet_count, byte_count, tcp_syn_count, tcp_ack_count, etc.).
- Flows are completed when:
  - timeout expires, or
  - max packets per flow reached, or
  - replay mode forces completion for SYN-only flows (optional).

### 8.3 Packet monitor
File: `src/realtime/live_monitor.py`

The monitor maintains a queue used by the detection engine.
- In sniff mode, it captures traffic and normalizes packet fields.
- In replay mode, it reads a PCAP and injects normalized packet dictionaries into the queue.

---

## 9. Attack Labeling (Heuristics)

### 9.1 Why heuristics?
ML models often output a “risk score” rather than a specific attack type. For a demonstration and operator UX, it is useful to label likely attack behaviors when strong patterns exist.

Heuristics are applied in:
- `LiveDetectionEngine._apply_heuristics(...)`

Attack labels are derived using:
- `LiveDetectionEngine._attack_kind_from_signals(...)`

### 9.2 SYN scan detection (SYN_SCAN)
Pattern:
- Many TCP SYN-only flows (SYN present, ACK absent)
- Large number of unique destination ports within a sliding time window

Key parameters:
- `LIVE_HEURISTIC_WINDOW` (default 10 seconds)
- `LIVE_SYN_PORTS_THRESHOLD` (default 15 unique ports)

Behavior:
- When triggered, the detection includes:
  - `heuristic_triggered: true`
  - `heuristic_reason` containing `syn_scan_ports=<N>`
  - `predicted_attack: SYN_SCAN`

### 9.3 Fragmentation detection (FRAGMENTATION)
Pattern:
- Presence of IP fragments using raw IP fields:
  - `ip_frag_offset > 0` or `ip_mf == 1`

This avoids relying solely on higher-level feature extraction when packets are malformed or fragmented.

### 9.4 Timing jitter detection (TIMING_JITTER)
Pattern:
- High coefficient of variation of packet inter-arrival times in a flow.

This is computed from packet timestamps as a fallback when feature extraction does not produce jitter scores.

### 9.5 Default fallback label
If no heuristics or obfuscation is detected, the system may label the event as:
- `RF/AE Fusion`

This indicates the ML models flagged risk, but no specific behavior-based heuristic label was strong enough.

---

## 10. Obfuscation Detection

Obfuscation detection attempts to identify traffic manipulations often used to evade simple IDS patterns:
- fragmentation anomalies
- timing jitter
- header inconsistency

Implementation:
- `LiveDetectionEngine._obfuscation_flag(...)`

The function outputs:
- `obfuscation_detected` boolean
- `timing_jitter_score`
- `fragmentation_anomaly_score`
- `header_consistency_score`
- `flow_uniformity_score`

Default detection thresholds:
- timing_jitter_score ≥ 0.8, OR
- fragmentation_anomaly_score ≥ 0.2, OR
- header_consistency_score ≤ 0.4

---

## 11. API + WebSocket Server (Node.js)

Main file:
- `api/server.js`

### 11.1 Purpose
The API server provides:
- A central place to receive detections and telemetry from the detector.
- Storage of recent events in `logs/`.
- Real-time broadcast to dashboards using WebSockets.

### 11.2 Storage
Stores are written to:
- `logs/live_detections.json`
- `logs/live_alerts.json`
- `logs/live_settings.json`
- `logs/live_telemetry.json`
- `logs/live_heartbeat.json`
- `logs/blocked_ips.json`
- `logs/response_history.json`

Persistence can be disabled with:
- `LIVE_DISABLE_PERSISTENCE=1`

### 11.3 Key endpoints (overview)
- `GET /health` → API status
- `POST /api/detections` → publish detection event (broadcasts `type="detection"`)
- `GET /live/detections` → read recent detections
- `POST /api/alerts` → publish alert event (broadcasts `type="alert"`)
- `GET /api/alerts` → read recent alerts
- `POST /live/telemetry` → publish telemetry (broadcasts `type="telemetry"`)
- `POST /live/heartbeat` → detector heartbeat (broadcasts `type="heartbeat"`)
- `GET /live/devices` → device registry
- `POST /live/settings` → update runtime settings, optionally clear history
- `POST /live/block/:ip` → manually block a source IP
- `POST /live/unblock/:ip` → manually unblock a source IP

### 11.4 WebSocket channel
WebSocket path:
- `/ws`

On connect, the server sends `type="init"` containing the current state:
- last detections/alerts
- blocked IP list
- telemetry and settings
- device registry

Then it broadcasts incremental updates:
- `detection`, `alert`, `blocked`, `unblocked`, `telemetry`, `settings`, `heartbeat`

---

## 12. Streamlit Dashboard (SOC UI)

Main file:
- `dashboard.py`

### 12.1 Purpose
The dashboard provides:
- Live attack feed (time, severity, source, target device, predicted attack type).
- Device map (SAFE / SUSPICIOUS / UNDER ATTACK) based on recent detections.
- Manual response controls (block/unblock).
- Real-time operational metrics (packets/sec, flows/sec, queue size).

### 12.2 Live attack feed
The feed renders the last N detection events (default 60 shown in the SOC feed, while the state stores more). Each row includes:
- timestamp
- severity label
- source IP → destination IP
- destination device name + location info (department/room)
- attack label (`predicted_attack`)

### 12.3 Device risk status
Risk status is derived from severities recently targeting each device:
- MEDIUM → “SUSPICIOUS”
- HIGH/CRITICAL → “UNDER ATTACK”
- otherwise → “SAFE”

### 12.4 Manual response buttons
From the SOC view the operator can:
- select an attacking IP from recent detections
- block it via the API
- select a blocked IP and unblock it

---

## 13. Telegram Notifications

Implementation:
- `src/notifications/telegram_alerts.py`

### 13.1 Configuration
Credentials can be set using environment variables or a `.env` file in the repository root:
- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`

Aliases supported:
- Token: `TELEGRAM_BOT_TOKEN`, `TG_BOT_TOKEN`, `TELEGRAM_TOKEN`, `BOT_TOKEN`
- Chat ID: `TELEGRAM_CHAT_ID`, `TG_CHAT_ID`, `TELEGRAM_CHAT`, `CHAT_ID`

Recommended `.env` example:
```env
TELEGRAM_BOT_TOKEN=123456:ABCDEF...
TELEGRAM_CHAT_ID=123456789
```

### 13.2 Alert policy
- The detector sends Telegram only at or above `TELEGRAM_MIN_SEVERITY` (default `MEDIUM`).
- Messages are de-duplicated per source IP:
  - default window: 300 seconds (`TELEGRAM_DEDUPE_SECONDS`)
- A minimum send interval is enforced to prevent rapid bursts:
  - default: 10 seconds (`TELEGRAM_MIN_INTERVAL_SECONDS`)

### 13.3 “Send after dashboard update”
The detector can be configured to publish detections to the API synchronously before sending Telegram:
- `LIVE_SYNC_DETECTIONS=1` (default in this project)

This ensures the dashboard receives the detection event before the Telegram alert is dispatched.

---

## 14. Manual Response (Block/Unblock)

### 14.1 Concept
Blocking is an operator action performed through the dashboard. The detector itself is configured with autoblock disabled by default.

### 14.2 Windows firewall integration
Blocking uses Windows Firewall rules via `netsh advfirewall` when running on Windows.

Key behaviors:
- Rule name pattern: `IOMT_BLOCK_<ip>`
- Protected IPs (loopback, local host addresses, API host) are rejected to prevent self-blocking.

Manual endpoints:
- `POST /live/block/:ip`
- `POST /live/unblock/:ip`

---

## 15. PCAP Replay and Attack Simulation

File:
- `src/realtime/replay_attack_demo.py`

### 15.1 Purpose
Provides a repeatable demonstration mode:
- Generate synthetic PCAPs for specific scenarios.
- Run the detector in replay mode against those PCAPs.
- Loop replays for continuous dashboard demonstration.

### 15.2 Scenarios
- `syn_scan`: TCP SYN packets across many destination ports.
- `portscan`: TCP SYN packets across a fixed list of ports.
- `fragmentation`: UDP packets fragmented into multiple IP fragments.
- `jitter`: UDP packets with alternating short and long inter-arrival delays.

### 15.3 Example commands
```powershell
python -m src.realtime.replay_attack_demo --scenario syn_scan --dst 192.168.100.10 --lab --loop
python -m src.realtime.replay_attack_demo --scenario fragmentation --dst 192.168.100.10 --lab --loop
python -m src.realtime.replay_attack_demo --scenario jitter --dst 192.168.100.10 --lab --loop
```

---

## 16. Configuration Reference (Environment Variables)

This section lists the most important environment variables used at runtime.

### 16.1 API address
- `IOMT_API_URL` (default `http://localhost:3001`)

### 16.2 Detector mode
- `LIVE_MODE`: `sniff` or `replay`
- `LIVE_REPLAY_PCAP`: path to PCAP file for replay
- `LIVE_REPLAY_SPEED`: speed factor (1.0 real-time; 0 instant)
- `LIVE_REPLAY_LOOP`: `1` to loop PCAP continuously
- `LIVE_CLEAR_HISTORY_ON_START`: `1` to clear API history on startup (useful for demos)

### 16.3 Detector thresholds and tuning
- `LIVE_PUBLISH_THRESHOLD`: minimum fusion score to publish detections (replay mode defaults to 0.0)
- `LIVE_ALERT_THRESHOLD`: alert threshold in detector config
- `LIVE_HEURISTIC_WINDOW`: seconds window for SYN scan heuristics
- `LIVE_SYN_PORTS_THRESHOLD`: unique destination ports required for SYN scan
- `TELEGRAM_MIN_SEVERITY`: `LOW|MEDIUM|HIGH|CRITICAL` (default MEDIUM)

### 16.4 Telegram
- `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID`
- `TELEGRAM_DEDUPE_SECONDS` (default 300)
- `TELEGRAM_MIN_INTERVAL_SECONDS` (default 10)
- `TELEGRAM_TIMEOUT_SECONDS` (default 8)
- `TELEGRAM_MAX_RETRIES` (default 3)

### 16.5 API persistence
- `LIVE_DISABLE_PERSISTENCE=1` disables writing to `logs/` (memory-only mode)

---

## 17. Logging, Persistence, and Storage

### 17.1 Python logs
The detector prints operational logs:
- packets and flows counters
- publish events
- Telegram send failures (without leaking secrets)

### 17.2 Node.js logs
The API prints:
- startup information
- WebSocket broadcast count messages

### 17.3 Persistent JSON stores
The API persists recent state in `logs/*.json` so the dashboard can recover state across restarts.

---

## 18. Validation and Testing

### 18.1 Offline evaluation
Run:
```powershell
python main.py
```
This generates:
- class distribution plot
- confusion matrices for Random Forest and Autoencoder
- a CSV table comparing accuracy/precision/recall/F1/FPR

### 18.2 Real-time stack validation
File:
- `src/realtime/validate_realtime_stack.py`

Purpose:
- Basic checks that WebSocket broadcasts and API endpoints respond properly.

---

## 19. Limitations and Threats to Validity
- The ML models depend on dataset quality; if training data is not representative of real IoMT traffic, performance degrades.
- Heuristic attack labeling is not a full IDS signature engine; it detects behavior patterns and may miss stealthy attacks.
- IP-based manual blocking is coarse; NAT environments or shared gateways can cause collateral impact.
- Replay mode is a demonstration tool; real sniff mode depends on OS permissions and capture quality.

---

## 20. Future Work
- Add per-device baselining and seasonality-aware anomaly scoring.
- Add more attack labels (DNS tunneling, ARP spoofing, lateral movement).
- Add model drift detection and periodic retraining pipeline.
- Add role-based access control for manual response in the dashboard.
- Add exportable incident reports (PDF/CSV) from the dashboard.

---

## Appendix A: Event Schemas

### A.1 Detection event (conceptual)
Fields commonly present in `/api/detections` payloads:
- `id` (string)
- `timestamp` (ISO string)
- `source_ip`, `destination_ip`
- `device_name`, `department`, `room`, `criticality`
- `predicted_attack` (attack label)
- `random_forest_confidence`, `random_forest_probability`
- `autoencoder_score`, `reconstruction_error`
- `fusion_score`, `severity`
- `obfuscation_detected`
- `recommended_action`
- `top_contributing_features` (list)
- `timing_jitter_score`, `fragmentation_anomaly_score`, `header_consistency_score`, `flow_uniformity_score`
- `flow_key`, `packets_in_flow`, `flow_bytes`

### A.2 Telemetry event
- `timestamp`
- `packets_per_sec`, `flows_per_sec`
- `queue_size`
- `active_flows`
- `packets_processed_total`, `flows_completed_total`

---

## Appendix B: File/Module Map

### Python (runtime)
- `src/realtime/live_detection_engine.py`: Orchestrator for live detection, replay, heuristics, publishing, Telegram gating.
- `src/realtime/live_flow_builder.py`: Flow aggregation and counters.
- `src/realtime/live_feature_extractor.py`: Flow → feature vector conversion for inference.
- `src/realtime/fusion_engine.py`: RF + AE inference and fusion score computation.
- `src/notifications/telegram_alerts.py`: Telegram sender with rate limit + dedupe.
- `src/realtime/replay_attack_demo.py`: Scenario PCAP generator + replay runner.

### API (Node.js)
- `api/server.js`: REST endpoints + WebSocket broadcast + JSON persistence.

### Dashboard (Streamlit)
- `dashboard.py`: SOC UI, device map, manual response controls, and WebSocket client.

### Offline evaluation
- `main.py`, `src/evaluate_comparison.py`: Generates plots + model comparisons in `results/`.

