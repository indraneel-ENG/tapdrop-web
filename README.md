# TAPDROP WEB

Share files between two Android phones through the browser. No app install.
Files travel directly between the phones over an encrypted WebRTC DataChannel.
The server only relays pairing messages.

## Project layout

```
index.html   app shell
styles.css   theme and layout
app.js       pairing, transfer protocol, integrity checks
server.js    serves the app and runs WebSocket signaling at /signal
package.json
vendor/      optional: qrcode.min.js and jsQR.js for offline use
```

## Run on the web (recommended: camera QR scanning works)

Phone camera scanning requires HTTPS. Deploy the folder as a Node web service on any host that
supports Node 18+, HTTPS and WebSockets:

- Build command: `npm install`
- Start command: `npm start`
- Health check path: `/healthz`

Open the HTTPS address on both phones. Signaling runs on the same address, so no separate
server or IP is needed.

Free-tier hosts may sleep when idle. The first load can take up to a minute.

## Run on a local network (no internet)

1. Install Node.js 18+ on one computer on the same Wi-Fi or hotspot.
2. In the project folder, run `npm install` and then `npm start`.
3. Open the `http://<computer-LAN-IP>:8080` address printed in the terminal on both phones.

Browsers block camera access on plain `http://`, so use **Manual pairing**: copy the offer
and answer codes between the phones. Manual pairing over a local network works without the
internet, because the phones connect using local addresses.

## How pairing works

1. Sender chooses files and taps **Start connection**. The app asks the server for a session.
2. Sender shows a QR code. Receiver scans it, or pastes codes in Manual pairing.
3. Both phones exchange connection details through the server, then connect directly.
4. Receiver accepts or rejects each file. Accepted files stream in 64 KB chunks.
5. Each file is verified with SHA-256 before it is saved.

## Limits and honest notes

- **Internet and signaling:** QR pairing needs the server to be reachable from both phones.
  Manual pairing on the same network needs no server. A public STUN server is configured for
  connections across networks. If a direct connection can't be made, for example on some
  corporate or carrier networks, add a TURN server under **Connection settings**.
- **Stale settings:** If you used an older version, clear the **Signaling server** field so
  the app uses the current address.
- **Memory:** The receiver assembles the incoming file in memory before saving it. Very large
  files can fail on phones with limited RAM.
- **Safety:** Received files are saved only. They are never opened or run by the app. Types
  other than images, video, audio, PDF and ZIP are saved as generic downloads.
- **Testing:** Test on your two target phones before relying on it.
