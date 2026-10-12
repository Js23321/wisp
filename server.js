// Minimal Wisp v1 server (WebSocket -> TCP proxy). One file, one dependency (ws).
// Works with any path, so wss://your-host/ and wss://your-host/wisp/ both connect.
"use strict";
const http = require("http");
const net = require("net");
const dns = require("dns");
const { WebSocketServer } = require("ws");

// ---------- settings (all optional; set them as environment variables) ----------
const PORT            = parseInt(process.env.PORT || "8080", 10);
const BUFFER          = parseInt(process.env.BUFFER || "128", 10);          // packets a stream may send before waiting
const MAX_STREAMS     = parseInt(process.env.MAX_STREAMS || "64", 10);      // per WebSocket
const MAX_CONNS_PER_IP= parseInt(process.env.MAX_CONNS_PER_IP || "10", 10); // WebSockets per visitor IP
const CONNECT_TIMEOUT = parseInt(process.env.CONNECT_TIMEOUT || "10000", 10);
const ALLOW_PRIVATE   = process.env.ALLOW_PRIVATE === "1";                  // only for local testing
const TRUST_PROXY     = process.env.TRUST_PROXY !== "0";                    // read visitor IP from X-Forwarded-For
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
const parsePorts = s => (s || "").split(",").map(x => parseInt(x, 10)).filter(n => n > 0 && n < 65536);
const ALLOWED_PORTS   = parsePorts(process.env.ALLOWED_PORTS);              // empty = any port except the blocked ones
const BLOCKED_PORTS   = parsePorts(process.env.BLOCKED_PORTS || "25,465,587,2525");

// ---------- never let people reach the host's own network ----------
const blocked = new net.BlockList();
[["0.0.0.0",8],["10.0.0.0",8],["100.64.0.0",10],["127.0.0.0",8],["169.254.0.0",16],["172.16.0.0",12],
 ["192.0.0.0",24],["192.168.0.0",16],["198.18.0.0",15],["224.0.0.0",4],["240.0.0.0",4]]
  .forEach(([a, p]) => blocked.addSubnet(a, p, "ipv4"));
[["::",128],["::1",128],["fc00::",7],["fe80::",10],["ff00::",8]].forEach(([a, p]) => blocked.addSubnet(a, p, "ipv6"));
function isBlockedIp(ip) {
  if (ALLOW_PRIVATE) return false;
  const v = net.isIP(ip);
  if (!v) return true;
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);              // IPv4-in-IPv6
  if (m) return blocked.check(m[1], "ipv4");
  return blocked.check(ip, v === 4 ? "ipv4" : "ipv6");
}

// ---------- Wisp packet helpers ----------
const T_CONNECT = 1, T_DATA = 2, T_CONTINUE = 3, T_CLOSE = 4;
function frame(type, id, payload) {
  const b = Buffer.allocUnsafe(5 + payload.length);
  b[0] = type; b.writeUInt32LE(id >>> 0, 1); payload.copy(b, 5);
  return b;
}
const u32 = n => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };

function closeReason(err) {
  switch (err && err.code) {
    case "ECONNREFUSED": return 0x44;
    case "ENOTFOUND": case "EAI_AGAIN": case "ENODATA": return 0x42;
    case "ETIMEDOUT": return 0x47;
    case "EHOSTUNREACH": case "ENETUNREACH": return 0x42;
    default: return 0x03;
  }
}

// ---------- HTTP side (health check so hosts see the service is alive) ----------
const server = http.createServer((req, res) => {
  res.writeHead(200, { "content-type": "text/plain" });
  res.end("Wisp server is running. Use this address with wss:// in your client.\n");
});
const wss = new WebSocketServer({ noServer: true, maxPayload: 4 * 1024 * 1024, perMessageDeflate: false });
const perIp = new Map();

function clientIp(req) {
  if (TRUST_PROXY) {
    const f = req.headers["x-forwarded-for"];
    if (f) return String(f).split(",")[0].trim();
  }
  return req.socket.remoteAddress || "unknown";
}

server.on("upgrade", (req, socket, head) => {
  if (ALLOWED_ORIGINS.length && !ALLOWED_ORIGINS.includes(req.headers.origin || "")) {
    socket.write("HTTP/1.1 403 Forbidden\r\n\r\n"); return socket.destroy();
  }
  const ip = clientIp(req);
  if ((perIp.get(ip) || 0) >= MAX_CONNS_PER_IP) {
    socket.write("HTTP/1.1 429 Too Many Requests\r\n\r\n"); return socket.destroy();
  }
  wss.handleUpgrade(req, socket, head, ws => { ws.ip = ip; wss.emit("connection", ws, req); });
});

wss.on("connection", ws => {
  perIp.set(ws.ip, (perIp.get(ws.ip) || 0) + 1);
  const streams = new Map();               // id -> { sock, queue, ready, inflight, unacked }
  let alive = true;

  const send = buf => { if (ws.readyState === 1) ws.send(buf, { binary: true }); };
  const sendClose = (id, reason) => send(frame(T_CLOSE, id, Buffer.from([reason])));

  function endStream(id, reason, notify) {
    const st = streams.get(id);
    if (!st) return;
    streams.delete(id);
    st.queue = [];
    try { st.sock && st.sock.destroy(); } catch (e) {}
    if (notify) sendClose(id, reason);
  }

  function writeToRemote(id, st, data) {
    st.inflight++;
    st.sock.write(data, () => {
      st.inflight--; st.unacked++;
      if (st.unacked >= Math.max(1, BUFFER >> 1) && streams.has(id)) {   // tell the client it may send more
        st.unacked = 0;
        send(frame(T_CONTINUE, id, u32(Math.max(0, BUFFER - st.inflight))));
      }
    });
  }

  function openStream(id, port, host) {
    const st = { sock: null, queue: [], ready: false, inflight: 0, unacked: 0 };
    streams.set(id, st);
    const fail = r => endStream(id, r, true);

    if (port < 1 || port > 65535 || !host || host.length > 253) return fail(0x41);
    if (BLOCKED_PORTS.includes(port) || (ALLOWED_PORTS.length && !ALLOWED_PORTS.includes(port))) return fail(0x48);

    // Try every address the name resolves to, IPv4 first (many hosts have no working IPv6 route).
    const tryAddrs = addrs => {
      let i = 0, lastReason = 0x47;
      const next = () => {
        if (!streams.has(id)) return;
        if (i >= addrs.length) return fail(lastReason);
        const ip = addrs[i++];
        if (isBlockedIp(ip)) { lastReason = 0x48; return next(); }
        const sock = net.connect({ host: ip, port });             // connect to the checked IP, not the name
        st.sock = sock;
        sock.setNoDelay(true);
        sock.setTimeout(i < addrs.length ? Math.min(CONNECT_TIMEOUT, 4000) : CONNECT_TIMEOUT, () => {
          if (st.sock === sock && !st.ready) { sock.destroy(); lastReason = 0x47; next(); }
        });
        sock.once("connect", () => {
          if (st.sock !== sock) return;
          st.ready = true; sock.setTimeout(0);
          sock.setKeepAlive(true, 30000);
          for (const d of st.queue) writeToRemote(id, st, d);
          st.queue = [];
        });
        sock.on("data", d => {
          for (let o = 0; o < d.length; o += 16384) send(frame(T_DATA, id, d.subarray(o, o + 16384)));
          if (ws.bufferedAmount > 1024 * 1024 && !sock.isPaused()) {           // slow browser: pause the game server
            sock.pause();
            const t = setInterval(() => {
              if (ws.readyState !== 1 || sock.destroyed) return clearInterval(t);
              if (ws.bufferedAmount < 256 * 1024) { clearInterval(t); sock.resume(); }
            }, 25);
          }
        });
        sock.on("end", () => { if (st.sock === sock) endStream(id, 0x02, true); });
        sock.on("error", err => {
          if (st.sock !== sock) return;
          if (!st.ready) { sock.destroy(); lastReason = closeReason(err); return next(); }
          endStream(id, 0x03, true);
        });
        sock.on("close", () => { if (st.sock === sock && st.ready) endStream(id, 0x02, true); });
      };
      next();
    };

    if (net.isIP(host)) tryAddrs([host]);
    else dns.lookup(host, { all: true }, (err, list) => {
      if (err || !list.length) return fail(0x42);
      list.sort((a, b) => a.family - b.family);                 // IPv4 before IPv6
      tryAddrs(list.map(a => a.address));
    });
  }

  send(frame(T_CONTINUE, 0, u32(BUFFER)));   // greeting: how many packets a stream may send

  ws.on("message", (msg, isBinary) => {
    if (!isBinary || msg.length < 5) return;
    const type = msg[0], id = msg.readUInt32LE(1), body = msg.subarray(5);
    if (type === T_CONNECT) {
      if (body.length < 4 || streams.has(id)) return;
      if (streams.size >= MAX_STREAMS) return sendClose(id, 0x49);
      if (body[0] !== 1) return sendClose(id, 0x41);                          // TCP only
      openStream(id, body.readUInt16LE(1), body.toString("utf8", 3));
    } else if (type === T_DATA) {
      const st = streams.get(id);
      if (!st) return;
      if (st.ready) writeToRemote(id, st, Buffer.from(body));
      else if (st.queue.length < BUFFER * 2) st.queue.push(Buffer.from(body));
    } else if (type === T_CLOSE) {
      endStream(id, 0x02, false);
    }
  });

  ws.on("pong", () => { alive = true; });
  const beat = setInterval(() => {                    // keeps hosts/proxies from dropping idle sockets
    if (!alive) return ws.terminate();
    alive = false; try { ws.ping(); } catch (e) {}
  }, 25000);

  ws.on("close", () => {
    clearInterval(beat);
    for (const id of [...streams.keys()]) endStream(id, 0x02, false);
    const n = (perIp.get(ws.ip) || 1) - 1;
    n <= 0 ? perIp.delete(ws.ip) : perIp.set(ws.ip, n);
  });
  ws.on("error", () => {});
});

server.listen(PORT, () => console.log("Wisp server listening on port " + PORT));
