const express = require("express");
const fs = require("fs");
const path = require("path");
const http = require("http");
const { WebSocketServer } = require("ws");
const crypto = require("crypto");

const app = express();
app.use(express.json({ limit: "1mb" }));

const TRAFFIC_MAX = 5000;
const ALERTS_MAX = 5000;

let traffic = [];
let alerts = [];
let blockedIps = [];
let detections = [];

const STORE_DIR = path.join(__dirname, "..", "logs");
const BLOCKED_STORE = path.join(STORE_DIR, "blocked_ips.json");
const RESPONSE_HISTORY_STORE = path.join(STORE_DIR, "response_history.json");
const DETECTIONS_STORE = path.join(STORE_DIR, "live_detections.json");
const ALERTS_STORE = path.join(STORE_DIR, "live_alerts.json");
const SETTINGS_STORE = path.join(STORE_DIR, "live_settings.json");
const TELEMETRY_STORE = path.join(STORE_DIR, "live_telemetry.json");
const HEARTBEAT_STORE = path.join(STORE_DIR, "live_heartbeat.json");
const DEVICE_REGISTRY = path.join(__dirname, "..", "config", "device_registry.json");

let blockedMeta = {};
let liveSettings = {
  autoblock_enabled: false,
  telegram_enabled: true,
  autoblock_fusion_threshold: 0.98,
  alert_fusion_threshold: 0.92,
  restrict_to_device_network: true,
  settings_version: 1,
  last_updated: null,
};
let liveTelemetry = {};
let liveHeartbeat = {};

function nowIso() {
  return new Date().toISOString();
}

function ensureStoreDir() {
  try {
    fs.mkdirSync(STORE_DIR, { recursive: true });
  } catch (_) {}
}

function readJson(filePath, fallback) {
  try {
    if (!fs.existsSync(filePath)) return fallback;
    const raw = fs.readFileSync(filePath, "utf8");
    const parsed = JSON.parse(raw);
    return parsed ?? fallback;
  } catch (_) {
    return fallback;
  }
}

const _pendingWrites = new Map();
const _writeTimers = new Map();

function writeJson(filePath, data) {
  try {
    ensureStoreDir();
    _pendingWrites.set(filePath, data);
    if (_writeTimers.has(filePath)) return true;
    const t = setTimeout(() => {
      _writeTimers.delete(filePath);
      const payload = _pendingWrites.get(filePath);
      const tmp = `${filePath}.tmp`;
      fs.promises
        .writeFile(tmp, JSON.stringify(payload, null, 2), "utf8")
        .then(() => fs.promises.rename(tmp, filePath))
        .catch(() => {});
    }, 100);
    _writeTimers.set(filePath, t);
    return true;
  } catch (_) {
    return false;
  }
}

function toInt(value, fallback = 0) {
  const n = Number.parseInt(value, 10);
  return Number.isFinite(n) ? n : fallback;
}

function protoToInt(proto) {
  if (typeof proto === "string") {
    const p = proto.trim().toLowerCase();
    if (p === "icmp") return 1;
    if (p === "tcp") return 6;
    if (p === "udp") return 17;
  }
  return toInt(proto, 0);
}

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

function loadStores() {
  const meta = readJson(BLOCKED_STORE, {});
  blockedMeta = typeof meta === "object" && meta ? meta : {};
  blockedIps = Object.keys(blockedMeta);
  const det = readJson(DETECTIONS_STORE, []);
  detections = Array.isArray(det) ? det : [];

  const al = readJson(ALERTS_STORE, []);
  alerts = Array.isArray(al) ? al : [];

  const st = readJson(SETTINGS_STORE, liveSettings);
  liveSettings = st && typeof st === "object" ? { ...liveSettings, ...st } : liveSettings;
  if (!liveSettings.settings_version) liveSettings.settings_version = 1;
  if (!liveSettings.last_updated) liveSettings.last_updated = nowIso();

  const tlm = readJson(TELEMETRY_STORE, {});
  liveTelemetry = tlm && typeof tlm === "object" ? tlm : {};

  const hb = readJson(HEARTBEAT_STORE, {});
  liveHeartbeat = hb && typeof hb === "object" ? hb : {};
}

loadStores();
if (process.env.LIVE_CLEAR_HISTORY_ON_START === "1") {
  traffic = [];
  detections = [];
  alerts = [];
  blockedIps = [];
  blockedMeta = {};
  liveTelemetry = {};
  liveHeartbeat = {};
  liveSettings = {
    autoblock_enabled: false,
    telegram_enabled: true,
    autoblock_fusion_threshold: 0.98,
    alert_fusion_threshold: 0.92,
    restrict_to_device_network: true,
    settings_version: 1,
    last_updated: nowIso(),
  };
  writeJson(DETECTIONS_STORE, detections);
  writeJson(ALERTS_STORE, alerts);
  writeJson(BLOCKED_STORE, blockedMeta);
  writeJson(RESPONSE_HISTORY_STORE, []);
  writeJson(SETTINGS_STORE, liveSettings);
  writeJson(TELEMETRY_STORE, liveTelemetry);
  writeJson(HEARTBEAT_STORE, liveHeartbeat);
}
const DISABLE_PERSISTENCE = process.env.LIVE_DISABLE_PERSISTENCE === "1";
if (DISABLE_PERSISTENCE) {
  detections = [];
  alerts = [];
  liveTelemetry = {};
  liveHeartbeat = {};
}

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: "/ws" });
const wsClients = new Set();

function wsSend(ws, payload) {
  try {
    ws.send(JSON.stringify(payload));
    return true;
  } catch (_) {}
  return false;
}

function broadcast(type, data) {
  const msg = { type, data };
  let sent = 0;
  for (const ws of wsClients) {
    if (ws.readyState === 1) {
      const ok = wsSend(ws, msg);
      if (!ok) {
        try {
          ws.terminate();
        } catch (_) {}
        wsClients.delete(ws);
      } else {
        sent += 1;
      }
    }
  }
  if (sent > 0) {
    console.log(`websocket_broadcast_sent type=${type} clients=${sent} pid=${process.pid}`);
  }
}

wss.on("connection", (ws) => {
  wsClients.add(ws);
  ws.on("close", () => wsClients.delete(ws));
  ws.on("error", () => wsClients.delete(ws));

  const devices = readJson(DEVICE_REGISTRY, {});
  wsSend(ws, {
    type: "init",
    data: {
      detections: DISABLE_PERSISTENCE ? [] : detections.slice(Math.max(0, detections.length - 200)),
      alerts: DISABLE_PERSISTENCE ? [] : alerts.slice(Math.max(0, alerts.length - 200)),
      blocked: Object.values(blockedMeta).filter(Boolean),
      telemetry: liveTelemetry,
      heartbeat: liveHeartbeat,
      settings: liveSettings,
      devices: devices && typeof devices === "object" ? devices : {},
    },
  });
});

app.post("/api/traffic", (req, res) => {
  const body = req.body ?? {};

  const item = {
    timestamp: body.timestamp ? String(body.timestamp) : nowIso(),
    src_ip: body.src_ip ? String(body.src_ip) : "",
    dst_ip: body.dst_ip ? String(body.dst_ip) : "",
    proto: protoToInt(body.proto),
    packet_size: toInt(body.packet_size, 0),
    prediction: toInt(body.prediction, 0),
    status: body.status ? String(body.status) : toInt(body.prediction, 0) === 1 ? "ANOMALY" : "NORMAL",
  };

  if (body.obfuscation) {
    item.obfuscation = body.obfuscation;
  }
  if (body.obfuscation_level) {
    item.obfuscation_level = String(body.obfuscation_level);
  }
  if (body.anomaly_score !== undefined) {
    item.anomaly_score = Number(body.anomaly_score);
  }
  if (body.explanation) {
    item.explanation = body.explanation;
  }

  traffic.push(item);
  if (traffic.length > TRAFFIC_MAX) {
    traffic = traffic.slice(traffic.length - TRAFFIC_MAX);
  }

  res.json({ ok: true });
});

app.post("/api/detections", (req, res) => {
  const body = req.body ?? {};
  const item = {
    id: body.id ? String(body.id) : crypto.randomUUID ? crypto.randomUUID() : String(Date.now()),
    timestamp: body.timestamp ? String(body.timestamp) : nowIso(),
    source_ip: body.source_ip ? String(body.source_ip) : "",
    destination_ip: body.destination_ip ? String(body.destination_ip) : "",
    device_name: body.device_name ? String(body.device_name) : "Unknown Device",
    department: body.department ? String(body.department) : "Unknown",
    room: body.room ? String(body.room) : "Unknown",
    criticality: body.criticality ? String(body.criticality) : "unknown",
    predicted_attack: body.predicted_attack ? String(body.predicted_attack) : "Unknown",
    random_forest_confidence: body.random_forest_confidence !== undefined ? Number(body.random_forest_confidence) : 0,
    autoencoder_score: body.autoencoder_score !== undefined ? Number(body.autoencoder_score) : 0,
    fusion_score: body.fusion_score !== undefined ? Number(body.fusion_score) : 0,
    severity: body.severity ? String(body.severity) : "LOW",
    obfuscation_detected: Boolean(body.obfuscation_detected),
    recommended_action: body.recommended_action ? String(body.recommended_action) : "MONITOR",
    auto_blocked: Boolean(body.auto_blocked),
  };

  if (body.top_contributing_features) item.top_contributing_features = body.top_contributing_features;
  if (body.reconstruction_error !== undefined) item.reconstruction_error = Number(body.reconstruction_error);
  if (body.flow_key) item.flow_key = String(body.flow_key);
  if (body.packets_in_flow !== undefined) item.packets_in_flow = toInt(body.packets_in_flow, 0);
  if (body.flow_bytes !== undefined) item.flow_bytes = toInt(body.flow_bytes, 0);
  if (body.timing_jitter_score !== undefined) item.timing_jitter_score = Number(body.timing_jitter_score);
  if (body.fragmentation_anomaly_score !== undefined) item.fragmentation_anomaly_score = Number(body.fragmentation_anomaly_score);
  if (body.header_consistency_score !== undefined) item.header_consistency_score = Number(body.header_consistency_score);
  if (body.flow_uniformity_score !== undefined) item.flow_uniformity_score = Number(body.flow_uniformity_score);

  if (!DISABLE_PERSISTENCE) {
    detections.push(item);
    if (detections.length > ALERTS_MAX) {
      detections = detections.slice(detections.length - ALERTS_MAX);
    }
    writeJson(DETECTIONS_STORE, detections);
  }
  broadcast("detection", item);
  res.json({ ok: true });
});

app.get("/api/traffic", (req, res) => {
  const limit = Math.max(1, Math.min(5000, toInt(req.query.limit, 500)));
  const slice = traffic.slice(Math.max(0, traffic.length - limit));
  res.json(slice);
});

app.get("/live/detections", (req, res) => {
  const limit = Math.max(1, Math.min(5000, toInt(req.query.limit, 200)));
  const slice = detections.slice(Math.max(0, detections.length - limit));
  res.json(slice);
});

app.get("/api/metrics", (_req, res) => {
  const total = traffic.length;
  const anomalies = traffic.reduce((acc, t) => acc + (t.prediction === 1 ? 1 : 0), 0);
  const normal = total - anomalies;
  const devices = new Set(traffic.map((t) => t.src_ip).filter(Boolean)).size;
  const blocked = blockedIps.length;
  
  const obfuscated = traffic.reduce((acc, t) => acc + (t.obfuscation ? 1 : 0), 0);
  const obfuscated_anomalies = traffic.reduce((acc, t) => acc + ((t.prediction === 1 && t.obfuscation) ? 1 : 0), 0);

  res.json({ total, normal, anomalies, devices, blocked, obfuscated, obfuscated_anomalies });
});

app.post("/api/alerts", (req, res) => {
  const body = req.body ?? {};
  const item = {
    id: body.id ? String(body.id) : crypto.randomUUID ? crypto.randomUUID() : String(Date.now()),
    timestamp: body.timestamp ? String(body.timestamp) : nowIso(),
    source_ip: body.source_ip ? String(body.source_ip) : body.ip ? String(body.ip) : "",
  };

  if (body.severity) item.severity = String(body.severity);
  if (body.anomaly_score !== undefined) item.anomaly_score = Number(body.anomaly_score);
  if (body.packet) item.packet = body.packet;
  if (body.obfuscation_detected) item.obfuscation_detected = Boolean(body.obfuscation_detected);
  if (body.obfuscation_techniques) item.obfuscation_techniques = body.obfuscation_techniques;
  if (body.explanation) item.explanation = body.explanation;
  if (body.fusion_score !== undefined) item.fusion_score = Number(body.fusion_score);
  if (body.destination_ip) item.destination_ip = String(body.destination_ip);
  if (body.device_name) item.device_name = String(body.device_name);
  if (body.department) item.department = String(body.department);
  if (body.room) item.room = String(body.room);
  item.acknowledged = Boolean(body.acknowledged);

  if (!DISABLE_PERSISTENCE) {
    alerts.push(item);
    if (alerts.length > ALERTS_MAX) {
      alerts = alerts.slice(alerts.length - ALERTS_MAX);
    }
    writeJson(ALERTS_STORE, alerts);
  }
  broadcast("alert", item);

  res.json({ ok: true });
});

app.get("/api/alerts", (req, res) => {
  const limit = Math.max(1, Math.min(5000, toInt(req.query.limit, 50)));
  const slice = alerts.slice(Math.max(0, alerts.length - limit));
  res.json(slice);
});

app.get("/live/alerts", (req, res) => {
  const limit = Math.max(1, Math.min(5000, toInt(req.query.limit, 50)));
  const slice = alerts.slice(Math.max(0, alerts.length - limit));
  res.json(slice);
});

app.post("/api/blocked", (req, res) => {
  const body = req.body ?? {};
  const ip = body.ip ? String(body.ip) : "";
  if (!ip) {
    res.status(400).json({ ok: false, error: "ip is required" });
    return;
  }

  if (!blockedIps.includes(ip)) {
    blockedIps.push(ip);
  }

  const existing = blockedMeta[ip] ?? {};
  blockedMeta[ip] = {
    ip,
    blocked_at: existing.blocked_at ?? nowIso(),
    expires_at: existing.expires_at ?? null,
    reason: body.reason ? String(body.reason) : existing.reason ?? "",
  };
  writeJson(BLOCKED_STORE, blockedMeta);
  broadcast("blocked", blockedMeta[ip]);

  res.json({ ok: true });
});

app.get("/api/blocked", (_req, res) => {
  res.json(blockedIps.map((ip) => ({ ip })));
});

app.get("/live/blocked", (_req, res) => {
  const out = Object.values(blockedMeta).filter(Boolean);
  res.json(out);
});

app.post("/live/unblock/:ip", async (req, res) => {
  const ip = String(req.params.ip || "").trim();
  if (!ip) {
    res.status(400).json({ ok: false, error: "ip is required" });
    return;
  }
  const body = req.body ?? {};
  const operator = body.operator ? String(body.operator) : "";
  const notes = body.notes ? String(body.notes) : "";

  const existed = Boolean(blockedMeta[ip]);
  delete blockedMeta[ip];
  blockedIps = blockedIps.filter((x) => x !== ip);
  writeJson(BLOCKED_STORE, blockedMeta);

  let fw = { ok: true, backend: "noop" };
  try {
    if (process.platform === "win32") {
      const { spawn } = require("child_process");
      const rule = `IOMT_BLOCK_${ip}`;
      fw = await new Promise((resolve) => {
        const p = spawn("netsh", ["advfirewall", "firewall", "delete", "rule", `name=${rule}`], { windowsHide: true });
        let stdout = "";
        let stderr = "";
        p.stdout && p.stdout.on("data", (d) => (stdout += String(d)));
        p.stderr && p.stderr.on("data", (d) => (stderr += String(d)));
        p.on("close", (code) => resolve({ ok: code === 0, backend: "windows_firewall", stdout, stderr, rule }));
        p.on("error", (e) => resolve({ ok: false, backend: "windows_firewall", error: String(e), rule }));
      });
    }
  } catch (e) {
    fw = { ok: false, backend: "windows_firewall", error: String(e) };
  }

  const history = readJson(RESPONSE_HISTORY_STORE, []);
  const entry = { action: "unblock", ip, timestamp: nowIso(), operator, notes, existed, firewall: fw, marked_false_positive: true };
  const next = Array.isArray(history) ? [...history, entry] : [entry];
  writeJson(RESPONSE_HISTORY_STORE, next.slice(Math.max(0, next.length - 5000)));

  broadcast("unblocked", { ip, existed });
  res.json({ ok: true, ip, existed, firewall: fw });
});

app.post("/live/block/:ip", async (req, res) => {
  const ip = String(req.params.ip || "").trim();
  if (!ip) {
    res.status(400).json({ ok: false, error: "ip is required" });
    return;
  }
  const body = req.body ?? {};
  const operator = body.operator ? String(body.operator) : "";
  const notes = body.notes ? String(body.notes) : "";

  if (!blockedIps.includes(ip)) {
    blockedIps.push(ip);
  }
  blockedMeta[ip] = {
    ip,
    blocked_at: nowIso(),
    expires_at: null,
    reason: "manual_dashboard",
  };
  writeJson(BLOCKED_STORE, blockedMeta);

  let fw = { ok: true, backend: "noop" };
  try {
    if (process.platform === "win32") {
      const { spawn } = require("child_process");
      const rule = `IOMT_BLOCK_${ip}`;
      fw = await new Promise((resolve) => {
        const p = spawn(
          "netsh",
          ["advfirewall", "firewall", "add", "rule", `name=${rule}`, "dir=in", "action=block", `remoteip=${ip}`],
          { windowsHide: true }
        );
        let stdout = "";
        let stderr = "";
        let settled = false;
        const timer = setTimeout(() => {
          if (settled) return;
          settled = true;
          try {
            p.kill();
          } catch (_) {}
          resolve({ ok: false, backend: "windows_firewall", stdout, stderr: "timeout", rule });
        }, 3000);
        p.stdout && p.stdout.on("data", (d) => (stdout += String(d)));
        p.stderr && p.stderr.on("data", (d) => (stderr += String(d)));
        p.on("close", (code) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          resolve({ ok: code === 0, backend: "windows_firewall", stdout, stderr, rule });
        });
        p.on("error", (e) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          resolve({ ok: false, backend: "windows_firewall", error: String(e), rule });
        });
      });
    }
  } catch (e) {
    fw = { ok: false, backend: "windows_firewall", error: String(e) };
  }

  const history = readJson(RESPONSE_HISTORY_STORE, []);
  const entry = { action: "block", ip, timestamp: nowIso(), operator, notes, firewall: fw, manual: true };
  const next = Array.isArray(history) ? [...history, entry] : [entry];
  writeJson(RESPONSE_HISTORY_STORE, next.slice(Math.max(0, next.length - 5000)));

  broadcast("blocked", blockedMeta[ip]);
  res.json({ ok: true, ip, firewall: fw });
});

app.get("/live/devices", (_req, res) => {
  const reg = readJson(DEVICE_REGISTRY, {});
  res.json(reg && typeof reg === "object" ? reg : {});
});

app.get("/live/settings", (_req, res) => {
  res.json(liveSettings);
});

app.post("/live/settings", (req, res) => {
  const body = req.body ?? {};
  if (!body || typeof body !== "object") {
    res.status(400).json({ ok: false, error: "body must be an object" });
    return;
  }
  const next = { ...body };
  if (next.alert_threshold !== undefined && next.alert_fusion_threshold === undefined) {
    next.alert_fusion_threshold = Number(next.alert_threshold);
  }
  if (next.autoblock_threshold !== undefined && next.autoblock_fusion_threshold === undefined) {
    next.autoblock_fusion_threshold = Number(next.autoblock_threshold);
  }
  const prevVersion = Number(liveSettings.settings_version || 1);
  liveSettings = { ...liveSettings, ...next, settings_version: prevVersion + 1, last_updated: nowIso() };
  writeJson(SETTINGS_STORE, liveSettings);
  broadcast("settings", liveSettings);

  const clear = Boolean(next.clear_history);
  if (clear) {
    detections = [];
    alerts = [];
    writeJson(DETECTIONS_STORE, detections);
    writeJson(ALERTS_STORE, alerts);
    const devices = readJson(DEVICE_REGISTRY, {});
    const initMsg = {
      type: "init",
      data: {
        detections: [],
        alerts: [],
        blocked: Object.values(blockedMeta).filter(Boolean),
        telemetry: liveTelemetry,
        heartbeat: liveHeartbeat,
        settings: liveSettings,
        devices: devices && typeof devices === "object" ? devices : {},
      },
    };
    let sent = 0;
    for (const ws of wsClients) {
      if (ws.readyState === 1) {
        const ok = wsSend(ws, initMsg);
        if (ok) sent += 1;
      }
    }
    if (sent > 0) {
      console.log(`websocket_broadcast_sent type=init clients=${sent} pid=${process.pid}`);
    }
  }
  res.json({ ok: true, settings: liveSettings });
});

app.get("/live/telemetry", (_req, res) => {
  res.json(liveTelemetry);
});

app.post("/live/telemetry", (req, res) => {
  const body = req.body ?? {};
  if (!body || typeof body !== "object") {
    res.status(400).json({ ok: false, error: "body must be an object" });
    return;
  }
  liveTelemetry = body;
  if (!DISABLE_PERSISTENCE) writeJson(TELEMETRY_STORE, liveTelemetry);
  broadcast("telemetry", liveTelemetry);
  res.json({ ok: true });
});

app.get("/live/heartbeat", (_req, res) => {
  res.json(liveHeartbeat);
});

app.post("/live/heartbeat", (req, res) => {
  const body = req.body ?? {};
  if (!body || typeof body !== "object") {
    res.status(400).json({ ok: false, error: "body must be an object" });
    return;
  }
  liveHeartbeat = { ...body, received_at: nowIso() };
  if (!DISABLE_PERSISTENCE) writeJson(HEARTBEAT_STORE, liveHeartbeat);
  broadcast("heartbeat", liveHeartbeat);
  res.json({ ok: true });
});

app.post("/live/ack", (req, res) => {
  const body = req.body ?? {};
  const id = body.id ? String(body.id) : "";
  const kind = body.kind ? String(body.kind) : "alert";
  if (!id) {
    res.status(400).json({ ok: false, error: "id is required" });
    return;
  }

  if (kind === "detection") {
    const idx = detections.findIndex((d) => d && d.id === id);
    if (idx >= 0) {
      detections[idx].acknowledged = true;
      writeJson(DETECTIONS_STORE, detections);
      broadcast("detection", detections[idx]);
      res.json({ ok: true, item: detections[idx] });
      return;
    }
  } else {
    const idx = alerts.findIndex((a) => a && a.id === id);
    if (idx >= 0) {
      alerts[idx].acknowledged = true;
      writeJson(ALERTS_STORE, alerts);
      broadcast("alert", alerts[idx]);
      res.json({ ok: true, item: alerts[idx] });
      return;
    }
  }

  res.status(404).json({ ok: false, error: "not_found" });
});

const port = toInt(process.env.PORT, 3001);
server.listen(port, "0.0.0.0", () => {
  process.stdout.write(`API listening on http://localhost:${port}\n`);
});
