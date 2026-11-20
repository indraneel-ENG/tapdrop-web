"use strict";

/*
  TAPDROP WEB — app.js
  Pairing: sender shows a QR code (signaling via server.js), or both sides exchange codes manually.
  Transfer: WebRTC DataChannel, 64 KB chunks, streamed from disk, SHA-256 verified, receiver consent.
*/

const $ = (id) => document.getElementById(id);
const CHUNK_SIZE = 64 * 1024;
const MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024;
const BUFFER_HIGH = 4 * 1024 * 1024;
const SAFE_MIME = /^(image|video|audio)\/[\w.+-]+$|^application\/(pdf|zip)$/;
const ICE_SERVERS = [{ urls: "stun:stun.l.google.com:19302" }];
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const state = {
  role: null,          // "sender" | "receiver"
  files: [],           // sender: chosen File objects
  queue: [],           // sender: indexes still to send
  outgoing: null,      // sender: { index, name, file, offset }
  pendingOffer: null,  // receiver: request awaiting accept/reject
  incoming: null,      // receiver: { index, name, size, mime, chunks, received, hash, started }
  failed: null,        // { index, name } retry target
  received: [],
  pairCode: "",
  pc: null,
  dc: null,
  ws: null,
  sessionId: null,
  scanStream: null,
  scanRaf: null,
  detector: null
};

/* ---------- UI helpers ---------- */

function showScreen(name) {
  document.querySelectorAll(".screen").forEach((s) => s.classList.remove("active"));
  $(`screen-${name}`).classList.add("active");
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function setStatus(text, kind = "") {
  $("statusText").textContent = text;
  $("statusDot").className = `dot ${kind}`;
}

let toastTimer;
function toast(message) {
  const el = $("toast");
  el.textContent = message;
  el.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), 3200);
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value.toFixed(value >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function safeName(name) {
  const clean = String(name || "file")
    .replace(/[\\/:*?"<>|\u0000-\u001f]/g, "_")
    .replace(/^\.+/, "_")
    .slice(0, 180);
  return clean || "file";
}

function encodeCode(obj) {
  return btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(obj))));
}

function decodeCode(text) {
  const bytes = Uint8Array.from(atob(text.trim()), (c) => c.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes));
}

async function copyText(text, label) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const area = document.createElement("textarea");
    area.value = text;
    document.body.appendChild(area);
    area.select();
    document.execCommand("copy");
    area.remove();
  }
  toast(`${label} copied`);
}

function fileRow(name, meta, button) {
  const row = document.createElement("div");
  row.className = "file-item";
  const info = document.createElement("div");
  info.className = "file-info";
  info.innerHTML = '<div class="name"></div><div class="meta"></div>';
  info.querySelector(".name").textContent = name;
  info.querySelector(".meta").textContent = meta;
  row.append(info, button);
  return row;
}

function iconButton(label, onClick) {
  const btn = document.createElement("button");
  btn.className = "icon-btn";
  btn.textContent = label;
  btn.onclick = onClick;
  return btn;
}

/* ---------- Incremental SHA-256 (streams large files without loading them whole) ---------- */

class IncrementalSHA256 {
  constructor() {
    this.k = [
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ];
    this.h = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    this.buffer = new Uint8Array(64);
    this.bufferLength = 0;
    this.bytesProcessed = 0;
  }

  update(data) {
    let offset = 0;
    this.bytesProcessed += data.byteLength;
    if (this.bufferLength) {
      const take = Math.min(64 - this.bufferLength, data.byteLength);
      this.buffer.set(data.subarray(0, take), this.bufferLength);
      this.bufferLength += take;
      offset = take;
      if (this.bufferLength === 64) {
        this.processBlock(this.buffer, 0);
        this.bufferLength = 0;
      }
    }
    while (offset + 64 <= data.byteLength) {
      this.processBlock(data, offset);
      offset += 64;
    }
    if (offset < data.byteLength) {
      const rest = data.subarray(offset);
      this.buffer.set(rest, this.bufferLength);
      this.bufferLength += rest.byteLength;
    }
  }

  processBlock(bytes, start) {
    const w = new Uint32Array(64);
    const view = new DataView(bytes.buffer, bytes.byteOffset + start, 64);
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = this.rotr(w[i - 15], 7) ^ this.rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = this.rotr(w[i - 2], 17) ^ this.rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = this.h;
    for (let i = 0; i < 64; i++) {
      const S1 = this.rotr(e, 6) ^ this.rotr(e, 11) ^ this.rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + this.k[i] + w[i]) >>> 0;
      const S0 = this.rotr(a, 2) ^ this.rotr(a, 13) ^ this.rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e;
      e = (d + temp1) >>> 0;
      d = c; c = b; b = a;
      a = (temp1 + temp2) >>> 0;
    }
    const next = [a, b, c, d, e, f, g, h];
    this.h = this.h.map((value, i) => (value + next[i]) >>> 0);
  }

  rotr(value, bits) {
    return ((value >>> bits) | (value << (32 - bits))) >>> 0;
  }

  hex() {
    const bitLength = this.bytesProcessed * 8;
    const padding = new Uint8Array((this.bufferLength < 56 ? 64 : 128) - this.bufferLength);
    padding[0] = 0x80;
    const lengthBytes = new Uint8Array(8);
    const view = new DataView(lengthBytes.buffer);
    view.setUint32(0, Math.floor(bitLength / 0x100000000));
    view.setUint32(4, bitLength >>> 0);
    this.update(padding.subarray(0, padding.byteLength - 8));
    this.update(lengthBytes);
    return this.h.map((x) => x.toString(16).padStart(8, "0")).join("");
  }
}

/* ---------- Settings ---------- */

function loadSettings() {
  $("signalUrl").value = localStorage.getItem("tapdrop_signal") || "";
  $("turnUrl").value = localStorage.getItem("tapdrop_turn_url") || "";
  $("turnUser").value = localStorage.getItem("tapdrop_turn_user") || "";
  $("turnPass").value = localStorage.getItem("tapdrop_turn_pass") || "";
  if (!$("signalUrl").value && location.host) {
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    $("signalUrl").value = `${proto}//${location.host}/signal`;
  }
}

function saveSettings() {
  localStorage.setItem("tapdrop_signal", $("signalUrl").value.trim());
  localStorage.setItem("tapdrop_turn_url", $("turnUrl").value.trim());
  localStorage.setItem("tapdrop_turn_user", $("turnUser").value.trim());
  localStorage.setItem("tapdrop_turn_pass", $("turnPass").value.trim());
}

function iceServers() {
  const servers = [...ICE_SERVERS];
  const turn = $("turnUrl").value.trim();
  if (turn) {
    servers.push({
      urls: turn,
      username: $("turnUser").value.trim() || undefined,
      credential: $("turnPass").value || undefined
    });
  }
  return servers;
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  $("themeBtn").textContent = theme === "dark" ? "🌙" : "☀️";
  localStorage.setItem("tapdrop_theme", theme);
}

/* ---------- WebRTC ---------- */

function closePeer() {
  if (state.dc) {
    state.dc.onopen = state.dc.onclose = state.dc.onmessage = null;
    state.dc.close();
  }
  if (state.pc) {
    state.pc.onconnectionstatechange = null;
    state.pc.close();
  }
  state.dc = null;
  state.pc = null;
}

function createPeerConnection() {
  closePeer();
  const pc = new RTCPeerConnection({ iceServers: iceServers() });
  // Answerer side: the offerer's data channel arrives here.
  pc.ondatachannel = (event) => setupDataChannel(event.channel);
  pc.onconnectionstatechange = () => {
    if (pc.connectionState === "connected") {
      setStatus("Connected — encrypted P2P channel", "ready");
    } else if (["failed", "disconnected", "closed"].includes(pc.connectionState)) {
      setStatus(`Connection ${pc.connectionState}`, "error");
    }
  };
  state.pc = pc;
  return pc;
}

function setupDataChannel(channel) {
  state.dc = channel;
  channel.binaryType = "arraybuffer";
  channel.onopen = () => {
    setStatus("Connected — encrypted P2P channel", "ready");
    if (state.role === "sender") sendNextRequest();
  };
  channel.onclose = () => {
    setStatus("Connection closed", "error");
    if (state.outgoing || state.incoming) pauseTransfer("Connection lost");
  };
  channel.onmessage = (event) => {
    if (typeof event.data === "string") handleControl(event.data);
    else handleChunk(event.data);
  };
}

function dcOpen() {
  return Boolean(state.dc) && state.dc.readyState === "open";
}

function sendControl(obj) {
  if (dcOpen()) state.dc.send(JSON.stringify(obj));
}

// Waits for ICE gathering so the full SDP (with candidates) is exchanged in one shot.
function waitIce(pc) {
  if (pc.iceGatheringState === "complete") return Promise.resolve();
  return new Promise((resolve) => {
    const done = () => {
      if (pc.iceGatheringState === "complete") {
        pc.removeEventListener("icegatheringstatechange", done);
        resolve();
      }
    };
    pc.addEventListener("icegatheringstatechange", done);
    setTimeout(resolve, 5000);
  });
}

function teardown() {
  stopScanner();
  if (state.ws) {
    state.ws.onclose = null;
    state.ws.close();
    state.ws = null;
  }
  closePeer();
  state.outgoing = null;
  state.incoming = null;
  state.pendingOffer = null;
  state.failed = null;
  $("retryTransferBtn").classList.add("hidden");
  $("incomingCard").classList.add("hidden");
}

/* ---------- Signaling (WebSocket, local server.js) ---------- */

function openSignaling(type, sessionId = null) {
  const url = $("signalUrl").value.trim();
  return new Promise((resolve, reject) => {
    if (!/^wss?:\/\//.test(url)) {
      reject(new Error("Set a ws:// signaling address in Settings"));
      return;
    }
    const ws = new WebSocket(url);
    const timer = setTimeout(() => {
      ws.close();
      reject(new Error("Signaling server did not respond"));
    }, 8000);

    ws.onopen = () => ws.send(JSON.stringify({ type, sessionId }));
    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.type === "created" || msg.type === "joined") {
        clearTimeout(timer);
        state.ws = ws;
        state.sessionId = msg.sessionId;
        ws.onmessage = (e) => handleSignal(JSON.parse(e.data));
        resolve(msg.sessionId);
      } else if (msg.type === "error") {
        clearTimeout(timer);
        ws.close();
        reject(new Error(msg.message));
      }
    };
    ws.onerror = () => {
      clearTimeout(timer);
      reject(new Error("Cannot reach signaling server"));
    };
    ws.onclose = () => {
      if (state.ws === ws) state.ws = null;
    };
  });
}

function sendSignal(payload) {
  if (state.ws && state.ws.readyState === WebSocket.OPEN) {
    state.ws.send(JSON.stringify({ type: "signal", sessionId: state.sessionId, payload }));
  }
}

async function handleSignal(msg) {
  try {
    if (msg.type === "peer-joined" && state.role === "sender") {
      // The sender created the session, so it is the offerer.
      const pc = createPeerConnection();
      setupDataChannel(pc.createDataChannel("tapdrop", { ordered: true }));
      await pc.setLocalDescription(await pc.createOffer());
      await waitIce(pc);
      sendSignal({ offer: pc.localDescription });
      setStatus("Receiver joined — connecting…", "");
    } else if (msg.type === "signal" && msg.payload.offer && state.role === "receiver") {
      const pc = createPeerConnection();
      await pc.setRemoteDescription(msg.payload.offer);
      await pc.setLocalDescription(await pc.createAnswer());
      await waitIce(pc);
      sendSignal({ answer: pc.localDescription });
      setStatus("Connecting…", "");
    } else if (msg.type === "signal" && msg.payload.answer && state.pc) {
      await state.pc.setRemoteDescription(msg.payload.answer);
    }
  } catch (error) {
    toast(`Connection failed: ${error.message}`);
    setStatus("Connection failed", "error");
  }
}

/* ---------- Sender ---------- */

function renderSelectedFiles() {
  $("fileList").replaceChildren(
    ...state.files.map((file, index) =>
      fileRow(safeName(file.name), formatBytes(file.size), iconButton("✕", () => {
        state.files.splice(index, 1);
        renderSelectedFiles();
      }))
    )
  );
  $("startSendBtn").disabled = state.files.length === 0;
}

async function startSender() {
  if (!state.files.length) return toast("Choose at least one file first");
  const big = state.files.find((f) => f.size > MAX_FILE_SIZE);
  if (big) return toast(`${safeName(big.name)} is over the 2 GB limit`);

  teardown();
  state.role = "sender";
  state.queue = state.files.map((_, i) => i);

  const qr = document.querySelector('input[name="pairMode"]:checked').value === "qr";
  $("sendPairArea").classList.remove("hidden");
  $("qrCard").classList.toggle("hidden", !qr);
  $("manualSendCard").classList.toggle("hidden", qr);
  if (!qr) {
    setStatus("Paste the receiver's offer code", "");
    return;
  }

  try {
    const sid = await openSignaling("create");
    state.pairCode = encodeCode({ v: 1, ws: $("signalUrl").value.trim(), sid });
    const canvas = document.createElement("canvas");
    await QRCode.toCanvas(canvas, state.pairCode, { width: 250, margin: 1 });
    $("qrBox").replaceChildren(canvas);
    $("copyPairBtn").onclick = () => copyText(state.pairCode, "Pairing code");
    setStatus("Waiting for receiver to scan", "");
  } catch (error) {
    toast(error.message);
    setStatus("Signaling unavailable — try manual pairing", "error");
  }
}

async function generateAnswerFromOffer() {
  try {
    const { offer } = decodeCode($("offerInput").value);
    if (!offer) throw new Error("not an offer code");
    if (!state.files.length) throw new Error("choose files first");
    if (state.role !== "sender") {
      teardown();
      state.role = "sender";
      state.queue = state.files.map((_, i) => i);
    }
    const pc = createPeerConnection();
    await pc.setRemoteDescription(offer);
    await pc.setLocalDescription(await pc.createAnswer());
    await waitIce(pc);
    $("answerOutput").value = encodeCode({ v: 1, answer: pc.localDescription });
    toast("Answer ready — send it back to the receiver");
  } catch (error) {
    toast(`Invalid offer code: ${error.message}`);
  }
}

/* ---------- Receiver ---------- */

function startReceiverScan() {
  teardown();
  state.role = "receiver";
  $("scanCard").classList.remove("hidden");
  if (!window.isSecureContext || !navigator.mediaDevices) {
    $("scanStatus").textContent = "Camera needs HTTPS or localhost. Use manual pairing instead.";
    return;
  }
  startScanner();
}

async function createManualOffer() {
  try {
    teardown();
    state.role = "receiver";
    const pc = createPeerConnection();
    setupDataChannel(pc.createDataChannel("tapdrop", { ordered: true }));
    await pc.setLocalDescription(await pc.createOffer());
    await waitIce(pc);
    $("offerOutput").value = encodeCode({ v: 1, offer: pc.localDescription });
    toast("Offer ready — send it to the sender");
  } catch (error) {
    toast(`Could not create offer: ${error.message}`);
  }
}

async function acceptManualAnswer() {
  try {
    const { answer } = decodeCode($("answerInput").value);
    if (!answer || !state.pc) throw new Error("create an offer first");
    await state.pc.setRemoteDescription(answer);
    setStatus("Connecting…", "");
  } catch (error) {
    toast(`Invalid answer code: ${error.message}`);
  }
}

/* ---------- QR scanning ---------- */

async function startScanner() {
  try {
    state.scanStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: "environment", width: { ideal: 1280 }, height: { ideal: 720 } }
    });
    const video = $("scanVideo");
    video.srcObject = state.scanStream;
    await video.play();
    $("scanStatus").textContent = "Point the camera at the sender's QR code";

    if (!state.detector && "BarcodeDetector" in window) {
      const formats = await BarcodeDetector.getSupportedFormats();
      if (formats.includes("qr_code")) state.detector = new BarcodeDetector({ formats: ["qr_code"] });
    }

    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d", { willReadFrequently: true });

    const scan = async () => {
      if (!state.scanStream) return;
      let value = null;
      try {
        if (state.detector) {
          const codes = await state.detector.detect(video);
          value = codes[0]?.rawValue ?? null;
        } else if (window.jsQR && video.videoWidth) {
          canvas.width = video.videoWidth;
          canvas.height = video.videoHeight;
          ctx.drawImage(video, 0, 0);
          const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
          value = window.jsQR(img.data, img.width, img.height)?.data ?? null;
        }
      } catch {
        /* keep scanning */
      }
      if (value) {
        stopScanner();
        joinFromQr(value);
        return;
      }
      state.scanRaf = requestAnimationFrame(scan);
    };
    scan();
  } catch {
    $("scanStatus").textContent = "Camera unavailable. Use manual pairing instead.";
  }
}

function stopScanner() {
  cancelAnimationFrame(state.scanRaf);
  state.scanRaf = null;
  if (state.scanStream) {
    state.scanStream.getTracks().forEach((track) => track.stop());
    state.scanStream = null;
  }
}

async function joinFromQr(raw) {
  let pair = null;
  try {
    pair = decodeCode(raw);
  } catch {
    pair = null;
  }
  if (!pair || pair.v !== 1 || !/^wss?:\/\//.test(pair.ws) || !/^[a-f0-9]{16}$/.test(pair.sid)) {
    toast("That isn't a TAPDROP code — keep scanning");
    startScanner();
    return;
  }

  $("signalUrl").value = pair.ws;
  saveSettings();
  setStatus("Joining sender…", "");
  try {
    await openSignaling("join", pair.sid);
    $("scanStatus").textContent = "Joined — waiting for the connection";
    setStatus("Joined — waiting for the connection", "");
  } catch (error) {
    toast(error.message);
    setStatus("Could not join session", "error");
  }
}

/* ---------- Transfer protocol ---------- */

function handleControl(raw) {
  let msg;
  try {
    msg = JSON.parse(raw);
  } catch {
    return;
  }
  const sender = state.role === "sender";
  switch (msg.type) {
    case "file-request": if (!sender) onFileRequest(msg); break;
    case "file-accept": if (sender) onAccepted(msg.index); break;
    case "file-reject": if (sender) onRejected(msg.index); break;
    case "file-end": if (!sender) onFileEnd(msg); break;
    case "file-ok": if (sender) onFileOk(msg.index); break;
    case "file-failed": if (sender) onFileFailed(msg); break;
    case "resend": if (sender) onResend(msg.index); break;
    case "cancel": onRemoteCancel(); break;
    case "done": if (!sender) onAllDone(); break;
    default: break;
  }
}

function showTransfer(title, name) {
  $("transferTitle").textContent = title;
  $("transferFile").textContent = name;
  $("progressBar").style.width = "0%";
  $("transferPercent").textContent = "0%";
  $("transferSpeed").textContent = "0 B/s";
  $("transferHash").textContent = "";
  $("retryTransferBtn").classList.add("hidden");
  showScreen("transfer");
}

function setTransferDone(title, text) {
  $("transferTitle").textContent = title;
  $("transferFile").textContent = text;
  $("progressBar").style.width = "100%";
  $("transferPercent").textContent = "100%";
  $("retryTransferBtn").classList.add("hidden");
}

function updateProgress(done, total, started) {
  const pct = total ? Math.min(100, (done / total) * 100) : 100;
  const secs = Math.max((performance.now() - started) / 1000, 0.001);
  $("progressBar").style.width = `${pct}%`;
  $("transferPercent").textContent = `${pct.toFixed(1)}%`;
  $("transferSpeed").textContent = `${formatBytes(done / secs)}/s`;
}

// Stops the active file on either side. The batch stays paused until Retry.
function pauseTransfer(reason, notify = false) {
  const current = state.role === "sender" ? state.outgoing : state.incoming;
  if (state.role === "sender") state.outgoing = null;
  else state.incoming = null;
  if (current) {
    if (current.chunks) current.chunks = [];
    state.failed = { index: current.index, name: current.name };
    if (notify) sendControl({ type: "file-failed", index: current.index, reason });
  }
  $("transferHash").textContent = reason;
  if (state.failed) $("retryTransferBtn").classList.remove("hidden");
  setStatus(reason, "error");
  toast(reason);
}

function cancelTransfer() {
  if (state.pendingOffer) return respondToOffer(false);
  const active = state.role === "sender" ? state.outgoing : state.incoming;
  if (!active) return toast("Nothing to cancel");
  sendControl({ type: "cancel" });
  pauseTransfer("Transfer cancelled");
}

function onRemoteCancel() {
  if (state.pendingOffer) {
    state.pendingOffer = null;
    $("incomingCard").classList.add("hidden");
  }
  if (state.outgoing || state.incoming) pauseTransfer("Cancelled by the other phone");
}

function retryTransfer() {
  const f = state.failed;
  if (!f) return;
  if (!dcOpen()) return toast("Connection lost — pair again to retry");
  state.failed = null;
  $("retryTransferBtn").classList.add("hidden");
  if (state.role === "sender") {
    state.queue = [f.index, ...state.queue.filter((i) => i !== f.index)];
    sendNextRequest();
  } else {
    sendControl({ type: "resend", index: f.index });
    setStatus("Asked the sender to resend", "");
  }
}

/* Sender side */

function sendNextRequest() {
  if (state.outgoing) return;
  const index = state.queue.shift();
  if (index === undefined) {
    sendControl({ type: "done" });
    setTransferDone("Sent", "All files sent");
    setStatus("All files sent", "ready");
    return;
  }
  const file = state.files[index];
  if (!file) return sendNextRequest();
  state.outgoing = { index, name: safeName(file.name), file, offset: 0 };
  showTransfer("Sending", state.outgoing.name);
  sendControl({
    type: "file-request",
    index,
    name: state.outgoing.name,
    size: file.size,
    mime: file.type || "application/octet-stream"
  });
}

function onAccepted(index) {
  if (state.outgoing && state.outgoing.index === index) streamFile(state.outgoing);
}

function onRejected(index) {
  if (state.outgoing && state.outgoing.index === index) {
    state.outgoing = null;
    toast("Receiver declined a file");
    sendNextRequest();
  }
}

function onFileOk(index) {
  if (state.outgoing && state.outgoing.index === index) {
    state.outgoing = null;
    sendNextRequest();
  }
}

function onFileFailed(msg) {
  if (state.outgoing && state.outgoing.index === msg.index) {
    pauseTransfer(String(msg.reason || "Receiver rejected the file"));
  }
}

function onResend(index) {
  if (state.outgoing || !state.files[index]) return;
  state.queue = [index, ...state.queue.filter((i) => i !== index)];
  sendNextRequest();
}

// Reads the file in 64 KB slices, hashing as it goes. Never loads the whole file.
async function streamFile(out) {
  const hash = new IncrementalSHA256();
  const started = performance.now();
  const dc = state.dc;
  try {
    while (out.offset < out.file.size) {
      if (state.outgoing !== out) return;
      if (dc.readyState !== "open") return pauseTransfer("Connection lost");
      while (dc.bufferedAmount > BUFFER_HIGH) await sleep(10);
      const buffer = await out.file.slice(out.offset, out.offset + CHUNK_SIZE).arrayBuffer();
      if (state.outgoing !== out) return;
      hash.update(new Uint8Array(buffer));
      dc.send(buffer);
      out.offset += buffer.byteLength;
      updateProgress(out.offset, out.file.size, started);
    }
    if (state.outgoing === out) {
      sendControl({ type: "file-end", index: out.index, sha256: hash.hex() });
    }
  } catch (error) {
    if (state.outgoing === out) pauseTransfer(`Send failed: ${error.message}`);
  }
}

/* Receiver side */

function validateMeta(msg) {
  const size = Number(msg.size);
  if (!Number.isInteger(msg.index) || msg.index < 0) return null;
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX_FILE_SIZE) return null;
  return {
    index: msg.index,
    name: safeName(msg.name),
    size,
    mime: SAFE_MIME.test(msg.mime) ? msg.mime : "application/octet-stream"
  };
}

function onFileRequest(msg) {
  const meta = validateMeta(msg);
  if (!meta || state.incoming || state.pendingOffer) {
    sendControl({ type: "file-reject", index: msg.index });
    return;
  }
  state.pendingOffer = meta;
  $("incomingInfo").textContent = `${meta.name} · ${formatBytes(meta.size)}`;
  $("incomingCard").classList.remove("hidden");
  showScreen("receive");
  setStatus("Incoming file — accept or reject", "");
}

function respondToOffer(accept) {
  const meta = state.pendingOffer;
  if (!meta) return;
  state.pendingOffer = null;
  $("incomingCard").classList.add("hidden");
  if (!accept) {
    sendControl({ type: "file-reject", index: meta.index });
    setStatus("Connected — transfer declined", "ready");
    return;
  }
  state.incoming = {
    ...meta,
    chunks: [],
    received: 0,
    hash: new IncrementalSHA256(),
    started: performance.now()
  };
  sendControl({ type: "file-accept", index: meta.index });
  showTransfer("Receiving", meta.name);
}

function handleChunk(buffer) {
  const inc = state.incoming;
  if (!inc) return;
  inc.received += buffer.byteLength;
  if (inc.received > inc.size) return pauseTransfer("File is larger than announced", true);
  inc.chunks.push(buffer);
  inc.hash.update(new Uint8Array(buffer));
  updateProgress(inc.received, inc.size, inc.started);
}

function onFileEnd(msg) {
  const inc = state.incoming;
  if (!inc || msg.index !== inc.index) return;
  const digest = inc.hash.hex();
  if (inc.received !== inc.size || digest !== msg.sha256) {
    pauseTransfer("Integrity check failed — file discarded", true);
    return;
  }
  addReceived(inc.name, new Blob(inc.chunks, { type: inc.mime }));
  state.incoming = null;
  sendControl({ type: "file-ok", index: inc.index });
  setTransferDone("Received", inc.name);
  $("transferHash").textContent = `SHA-256 verified · ${digest.slice(0, 16)}…`;
}

function addReceived(name, blob) {
  const url = URL.createObjectURL(blob);
  state.received.push({ name, url });
  const save = iconButton("⬇", () => {
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
  });
  $("receivedList").prepend(fileRow(name, formatBytes(blob.size), save));
}

function onAllDone() {
  setTransferDone("Complete", "All files received");
  setStatus("All files received", "ready");
}

/* ---------- Init ---------- */

function init() {
  loadSettings();
  applyTheme(localStorage.getItem("tapdrop_theme") || "dark");
  setStatus("Not connected");

  $("themeBtn").onclick = () =>
    applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
  $("sendBtn").onclick = () => showScreen("send");
  $("receiveBtn").onclick = () => showScreen("receive");
  $("settingsBtn").onclick = () => showScreen("settings");

  document.querySelectorAll("[data-back]").forEach((btn) => {
    btn.onclick = () => {
      stopScanner();
      saveSettings();
      showScreen(btn.dataset.back);
    };
  });

  $("fileInput").onchange = (event) => {
    state.files = Array.from(event.target.files);
    renderSelectedFiles();
  };
  $("startSendBtn").onclick = startSender;
  $("generateAnswerBtn").onclick = generateAnswerFromOffer;
  $("copyAnswerBtn").onclick = () => copyText($("answerOutput").value, "Answer code");

  $("startReceiveBtn").onclick = startReceiverScan;
  $("stopScanBtn").onclick = () => {
    stopScanner();
    $("scanStatus").textContent = "Camera stopped";
  };
  $("createOfferBtn").onclick = createManualOffer;
  $("copyOfferBtn").onclick = () => copyText($("offerOutput").value, "Offer code");
  $("acceptAnswerBtn").onclick = acceptManualAnswer;

  $("acceptFileBtn").onclick = () => respondToOffer(true);
  $("rejectFileBtn").onclick = () => respondToOffer(false);
  $("cancelTransferBtn").onclick = cancelTransfer;
  $("retryTransferBtn").onclick = retryTransfer;

  document.querySelectorAll('input[name="pairMode"]').forEach((radio) => {
    radio.onchange = () => $("sendPairArea").classList.add("hidden");
  });
  document.querySelectorAll('input[name="receiveMode"]').forEach((radio) => {
    radio.onchange = () => {
      const qr = document.querySelector('input[name="receiveMode"]:checked').value === "qr";
      stopScanner();
      $("receiveQrArea").classList.toggle("hidden", !qr);
      $("manualReceiveCard").classList.toggle("hidden", qr);
    };
  });
}

document.addEventListener("DOMContentLoaded", init);
