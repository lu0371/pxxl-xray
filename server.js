'use strict';
/*
 * Pxxl free tier: the edge terminates TLS and forwards plain HTTP to this
 * process on $PORT. This server therefore implements VLESS + WS directly in
 * Node, with NO TLS of its own and NO third-party binary.
 *
 * Why no Xray binary: Pxxl's container turned out to block execution of any
 * user-written file, everywhere we could write — the app dir is read-only,
 * the tmp dir is noexec, and /dev/shm is noexec too (all verified across
 * six deploys, 2026-10-30). A pure-JS implementation sidesteps the problem
 * entirely: the only thing that runs is node itself.
 *
 * VLESS (no encryption) over WS, TCP only in v1 (UDP/MUX commands are
 * rejected; plain browsing is TCP):
 *   client -> server first frame: version(1) uuid(16) addonLen(1) addon
 *     command(1: 0x01 TCP) port(2, BE) addrType(1) address payload...
 *   server -> client: version(1)=0x00, addonLen(1)=0x00, then relayed bytes.
 *
 * Required env (set in the platform's env settings, never committed):
 *   UUID     - VLESS client id
 *   WS_PATH  - WS path, must start with '/'
 * Optional:
 *   SUB_TOKEN - if set, GET /sub?token=<SUB_TOKEN> returns the base64
 *               subscription (one vless link). Without it /sub is 404.
 *   APP_DOMAIN - public host of this app, used only to build /sub output.
 * $PORT is supplied by the platform. Do NOT set it yourself.
 */
const http = require('http');
const net = require('net');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = parseInt(process.env.PORT, 10);
const UUID = process.env.UUID;
const WS_PATH = process.env.WS_PATH;
const SUB_TOKEN = process.env.SUB_TOKEN || '';
const DOMAIN = process.env.APP_DOMAIN || process.env.VELIXIR_DOMAIN || '';

if (!PORT) { console.error('PORT is not set by the platform'); process.exit(1); }
if (!UUID) { console.error('UUID env is missing'); process.exit(1); }
if (!WS_PATH || !WS_PATH.startsWith('/')) {
  console.error('WS_PATH env is missing or does not start with /');
  process.exit(1);
}

function parseUuidBytes(str) {
  const hex = str.replace(/-/g, '');
  if (!/^[0-9a-fA-F]{32}$/.test(hex)) return null;
  return Buffer.from(hex, 'hex');
}
const UUID_BYTES = parseUuidBytes(UUID);
if (!UUID_BYTES) { console.error('UUID env is not a valid UUID'); process.exit(1); }

// Parse one VLESS request header. Returns null on malformed input.
function parseVlessHeader(buf) {
  try {
    if (buf.length < 1 + 16 + 1 + 1 + 2 + 1 + 1) return null;
    let off = 0;
    const version = buf[off++];
    if (version !== 0) return null;
    const id = buf.subarray(off, off + 16); off += 16;
    const addonLen = buf[off++];
    off += addonLen;
    if (off + 1 + 2 + 1 > buf.length) return null;
    const command = buf[off++];
    const port = buf.readUInt16BE(off); off += 2;
    const addrType = buf[off++];
    let host;
    if (addrType === 1) {
      if (off + 4 > buf.length) return null;
      host = Array.from(buf.subarray(off, off + 4)).join('.'); off += 4;
    } else if (addrType === 2) {
      if (off + 1 > buf.length) return null;
      const len = buf[off++];
      if (off + len > buf.length) return null;
      host = buf.subarray(off, off + len).toString('utf8'); off += len;
    } else if (addrType === 3) {
      if (off + 16 > buf.length) return null;
      const parts = [];
      for (let i = 0; i < 16; i += 2) parts.push(buf.readUInt16BE(off + i).toString(16));
      host = parts.join(':'); off += 16;
    } else {
      return null;
    }
    return { id, command, port, host, payload: buf.subarray(off) };
  } catch {
    return null;
  }
}

function handleVlessConnection(ws) {
  let target = null;
  let headerDone = false;

  const closeBoth = () => {
    try { ws.close(); } catch {}
    try { target && target.destroy(); } catch {}
  };

  ws.on('message', (data) => {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    if (!headerDone) {
      headerDone = true;
      const req = parseVlessHeader(buf);
      if (!req) { console.error('vless: malformed header'); closeBoth(); return; }
      if (!crypto.timingSafeEqual(req.id, UUID_BYTES)) {
        console.error('vless: uuid mismatch');
        closeBoth();
        return;
      }
      if (req.command !== 0x01) {
        console.error(`vless: unsupported command ${req.command} (TCP only)`);
        closeBoth();
        return;
      }
      target = net.connect(req.port, req.host, () => {
        ws.send(Buffer.from([0x00, 0x00]), { binary: true });
        if (req.payload.length) target.write(req.payload);
      });
      target.on('data', (chunk) => {
        try { ws.send(chunk, { binary: true }); } catch { target.destroy(); }
      });
      target.on('error', (err) => {
        console.error(`vless: target ${req.host}:${req.port} error: ${err.message}`);
        closeBoth();
      });
      target.on('close', closeBoth);
      return;
    }
    // After the header, frames are raw relay payload.
    if (target && !target.destroyed) target.write(buf);
  });

  ws.on('close', () => { try { target && target.destroy(); } catch {} });
  ws.on('error', () => { try { target && target.destroy(); } catch {} });
}

function subscriptionLink() {
  const host = DOMAIN || 'your-app.pxxl.app';
  const params = new URLSearchParams({
    encryption: 'none', security: 'tls', sni: host, type: 'ws', host,
    path: WS_PATH,
  });
  return `vless://${UUID}@${host}:443?${params.toString()}#Pxxl-Xray`;
}

function buildServer() {
  const server = http.createServer((req, res) => {
    if (req.url === WS_PATH) { res.writeHead(400); res.end('Bad Request'); return; }
    if (req.url && req.url.startsWith('/sub')) {
      const token = new URL(req.url, 'http://localhost').searchParams.get('token');
      if (SUB_TOKEN && token === SUB_TOKEN) {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(Buffer.from(subscriptionLink(), 'utf8').toString('base64') + '\n');
        return;
      }
      res.writeHead(404); res.end('Not Found'); return;
    }
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok\n');
  });

  const wss = new WebSocketServer({ noServer: true });
  server.on('upgrade', (req, socket, head) => {
    if (req.url !== WS_PATH) { socket.destroy(); return; }
    wss.handleUpgrade(req, socket, head, (ws) => {
      console.log('vless: ws client connected');
      handleVlessConnection(ws);
    });
  });

  return server;
}

// Listen on PORT and, if different, on EXPOSE_PORT too: the panel defines
// both, and it is unclear which one the platform health check probes.
// Bind 0.0.0.0 explicitly so IPv4 probes cannot miss an IPv6-only socket.
const LISTEN_PORTS = [...new Set([PORT, parseInt(process.env.EXPOSE_PORT || '', 10)].filter((p) => Number.isInteger(p) && p > 0))];
for (const p of LISTEN_PORTS) {
  buildServer().listen(p, '0.0.0.0', () => console.log(`listening on 0.0.0.0:${p}`));
}
console.log(`vless-js ready, ports=${LISTEN_PORTS.join(',')}`);
