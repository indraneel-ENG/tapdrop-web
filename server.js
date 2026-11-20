"use strict";

/*
  TAPDROP WEB server
  - Serves the static web app (index.html, styles.css, app.js, optional vendor/ files).
  - Runs WebSocket signaling at /signal. Only pairing messages pass through here;
    files travel directly between phones over WebRTC.
*/

const http = require("http");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { WebSocketServer } = require("ws");

const PORT = Number(process.env.PORT) || 8080;
const ROOT = __dirname;
const SESSION_TTL_MS = 10 * 60 * 1000;   // pairing window
const KEEPALIVE_MS = 25 * 1000;          // keeps hosted proxies from idling sockets out
const MAX_MESSAGE_BYTES = 64 * 1024;

const JS = "text/javascript; charset=utf-8";
const FILES = {
  "/": { file: "index.html", type: "text/html; charset=utf-8" },
  "/index.html": { file: "index.html", type: "text/html; charset=utf-8" },
  "/styles.css": { file: "styles.css", type: "text/css; charset=utf-8" },
  "/app.js": { file: "app.js", type: JS },
  "/vendor/qrcode.min.js": { file: path.join("vendor", "qrcode.min.js"), type: JS },
  "/vendor/jsQR.js": { file: path.join("vendor", "jsQR.js"), type: JS }
};

const SECURITY_HEADERS = {
  "Content-Security-Policy":
    "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self'; " +
    "img-src 'self' data: blob:; connect-src 'self' ws: wss:; object-src 'none'; " +
    "base-uri 'none'; frame-ancestors 'none'",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(self)"
};

/* ---------- HTTP: static app ---------- */

const server = http.createServer((req, res) => {
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.writeHead(405, { Allow: "GET, HEAD" });
    return res.end();
  }

  const { pathname } = new URL(req.url, "http://localhost");

  if (pathname === "/healthz") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    return res.end("ok");
  }

  const entry = FILES[pathname];
  if (!entry) {
    res.writeHead(404, { "Content-Type": "text/plain" });
    return res.end("Not found");
  }

  // The path comes from the FILES whitelist above, never from the request.
  fs.readFile(path.join(ROOT, entry.file), (error, data) => {
    if (error) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      return res.end("Not found");
    }
    res.writeHead(200, {
      ...SECURITY_HEADERS,
      "Content-Type": entry.type,
      "Cache-Control": "no-cache"
    });
    res.end(req.method === "HEAD" ? undefined : data);
  });
});

/* ---------- WebSocket: signaling ---------- */

const wss = new WebSocketServer({ server, path: "/signal", maxPayload: MAX_MESSAGE_BYTES });
const sessions = new Map(); // sessionId -> { peers: Set<WebSocket>, created: number }

function send(ws, object) {
  if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(object));
}

function leave(ws) {
  const id = ws.sessionId;
  ws.sessionId = null;
  const session = id && sessions.get(id);
  if (!session) return;
  session.peers.delete(ws);
  if (session.peers.size === 0) sessions.delete(id);
}

function createSession(ws) {
  leave(ws);
  let id;
  do {
    id = crypto.randomBytes(8).toString("hex");
  } while (sessions.has(id));
  sessions.set(id, { peers: new Set([ws]), created: Date.now() });
  ws.sessionId = id;
  send(ws, { type: "created", sessionId: id });
}

function joinSession(ws, id) {
  leave(ws);
  const session = typeof id === "string" && /^[a-f0-9]{16}$/.test(id) ? sessions.get(id) : null;
  if (!session) {
    send(ws, { type: "error", message: "Session not found or expired" });
    return;
  }
  if (session.peers.size >= 2) {
    send(ws, { type: "error", message: "Session already has two devices" });
    return;
  }
  session.peers.add(ws);
  ws.sessionId = id;
  send(ws, { type: "joined", sessionId: id });
  for (const peer of session.peers) {
    if (peer !== ws) send(peer, { type: "peer-joined" });
  }
}

function relay(ws, msg) {
  const session = ws.sessionId && sessions.get(ws.sessionId);
  if (!session || msg.sessionId !== ws.sessionId || typeof msg.payload !== "object") return;
  for (const peer of session.peers) {
    if (peer !== ws) send(peer, { type: "signal", sessionId: ws.sessionId, payload: msg.payload });
  }
}

wss.on("connection", (ws) => {
  ws.sessionId = null;
  ws.isAlive = true;
  ws.on("pong", () => {
    ws.isAlive = true;
  });

  ws.on("message", (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      return;
    }
    if (msg.type === "create") createSession(ws);
    else if (msg.type === "join") joinSession(ws, msg.sessionId);
    else if (msg.type === "signal") relay(ws, msg);
  });

  ws.on("close", () => leave(ws));
});

// Drop pairing sessions nobody joined in time.
setInterval(() => {
  const now = Date.now();
  for (const [id, session] of sessions) {
    if (session.peers.size < 2 && now - session.created > SESSION_TTL_MS) {
      for (const peer of session.peers) peer.sessionId = null;
      sessions.delete(id);
    }
  }
}, 60 * 1000).unref();

// Ping clients; terminate sockets that stopped answering.
setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.isAlive) {
      ws.terminate();
      continue;
    }
    ws.isAlive = false;
    ws.ping();
  }
}, KEEPALIVE_MS).unref();

/* ---------- Start ---------- */

server.listen(PORT, "0.0.0.0", () => {
  console.log(`TAPDROP WEB running on port ${PORT}`);
  const lanAddresses = Object.values(os.networkInterfaces())
    .flat()
    .filter((net) => net && net.family === "IPv4" && !net.internal)
    .map((net) => net.address);
  for (const ip of lanAddresses) console.log(`  Local:  http://${ip}:${PORT}`);
  console.log("  Camera QR scanning needs HTTPS or localhost; use a hosted HTTPS URL for it.");
});
