'use strict';
/*
 * Pxxl free tier: the edge terminates TLS and forwards plain HTTP to this
 * process on $PORT. Xray therefore runs as VLESS + WS with NO TLS of its own,
 * listening only on 127.0.0.1. Only Upgrade requests on WS_PATH are proxied
 * to Xray; everything else gets a harmless status code.
 *
 * Xray core is downloaded at startup from the official XTLS GitHub release,
 * pinned to a fixed version and verified against the official SHA2-256
 * published in the release .dgst file. A hash mismatch aborts startup.
 *
 * Required env (set in the platform's env settings, never committed):
 *   UUID     - VLESS client id
 *   WS_PATH  - WS path, must start with '/'
 * Optional:
 *   SUB_TOKEN - if set, GET /sub?token=<SUB_TOKEN> returns the base64
 *               subscription (one vless link). Without it /sub is 404.
 *   APP_DOMAIN - public host of this app, used only to build /sub output.
 *   XRAY_PORT - internal Xray listen port, default 10000
 * $PORT is supplied by the platform. Do NOT set it yourself.
 */
const http = require('http');
const net = require('net');
const os = require('os');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn, spawnSync } = require('child_process');
const https = require('https');
const AdmZip = require('adm-zip');

const XRAY_VERSION = 'v26.10.29';
const XRAY_ZIP_SHA256 = '8a5f3e6a1057e4bd0f8a7c57c9d91204b4be0b74222a6e210d070603101163c2';
const XRAY_ZIP_URL = `https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-64.zip`;

const PORT = parseInt(process.env.PORT, 10);
const UUID = process.env.UUID;
const WS_PATH = process.env.WS_PATH;
const XRAY_PORT = parseInt(process.env.XRAY_PORT || '10000', 10);
const SUB_TOKEN = process.env.SUB_TOKEN || '';
const DOMAIN = process.env.APP_DOMAIN || process.env.VELIXIR_DOMAIN || '';

if (!PORT) { console.error('PORT is not set by the platform'); process.exit(1); }
if (!UUID) { console.error('UUID env is missing'); process.exit(1); }
if (!WS_PATH || !WS_PATH.startsWith('/')) {
  console.error('WS_PATH env is missing or does not start with /');
  process.exit(1);
}

// Pxxl runtime facts, learned the hard way across four deploys:
// - Creating a subdirectory under the app dir fails (mkdir ENOENT), so no
//   "<dir>/.xray" workdir scheme works there at all.
// - The tmp dir is writable but noexec: a binary there fails to spawn EACCES.
// - So: write the binary file DIRECTLY into a candidate dir (no subdir
//   creation), chmod it, and actually run it. First dir that runs wins.
//   The config file only needs to be readable, so it always lives in tmp.
const BIN_DIR_CANDIDATES = process.env.XRAY_DIR
  ? [process.env.XRAY_DIR]
  : [...new Set([__dirname, process.cwd(), os.homedir()])];
let BIN = path.join(BIN_DIR_CANDIDATES[0], 'xray');
let CONFIG = path.join(os.tmpdir(), 'xray-config.json');
let WORKDIR = BIN_DIR_CANDIDATES[0];

function download(url, dest) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { 'User-Agent': 'pxxl-xray/1.0' } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return download(res.headers.location, dest).then(resolve, reject);
      }
      if (res.statusCode !== 200) {
        return reject(new Error(`download failed: HTTP ${res.statusCode}`));
      }
      const out = fs.createWriteStream(dest);
      res.pipe(out);
      out.on('finish', () => out.close(resolve));
      out.on('error', reject);
    });
    req.on('error', reject);
  });
}

async function ensureXray() {
  // Download once to the tmp dir (write-only use, never executed from there).
  const zipPath = path.join(os.tmpdir(), 'xray-download.zip');
  if (!fs.existsSync(zipPath)) {
    console.log(`downloading Xray ${XRAY_VERSION} (official XTLS release)...`);
    await download(XRAY_ZIP_URL, zipPath);
    const digest = crypto.createHash('sha256').update(fs.readFileSync(zipPath)).digest('hex');
    if (digest !== XRAY_ZIP_SHA256) {
      fs.unlinkSync(zipPath);
      throw new Error(`xray zip sha256 mismatch: got ${digest}`);
    }
    console.log('xray zip sha256 verified');
  }
  const zip = new AdmZip(zipPath);
  const entry = zip.getEntry('xray');
  if (!entry) throw new Error('xray binary not found in zip');
  const binData = entry.getData();
  let lastErr = null;
  for (const dir of BIN_DIR_CANDIDATES) {
    try {
      const bin = path.join(dir, 'xray');
      fs.writeFileSync(bin, binData);
      fs.chmodSync(bin, 0o755);
      // A noexec mount still passes mode-bit checks, so actually run it.
      const test = spawnSync(bin, ['version'], { timeout: 8000, encoding: 'utf8' });
      if (test.error) throw test.error;
      if (test.status !== 0) throw new Error(`xray version exited ${test.status}`);
      WORKDIR = dir; BIN = bin;
      console.log(`xray ready in ${dir}`);
      return;
    } catch (err) {
      console.error(`xray dir ${dir} unusable: ${err.message}`);
      lastErr = err;
    }
  }
  throw lastErr || new Error('no usable xray dir');
}

function startXray() {
  const config = {
    log: { loglevel: 'warning' },
    inbounds: [{
      listen: '127.0.0.1',
      port: XRAY_PORT,
      protocol: 'vless',
      settings: { clients: [{ id: UUID }], decryption: 'none' },
      streamSettings: { network: 'ws', wsSettings: { path: WS_PATH } },
    }],
    outbounds: [{ protocol: 'freedom', tag: 'direct' }],
  };
  fs.writeFileSync(CONFIG, JSON.stringify(config));
  const child = spawn(BIN, ['run', '-c', CONFIG], { stdio: ['ignore', 'inherit', 'inherit'] });
  child.on('error', (err) => console.error(`xray spawn error: ${err.message}`));
  child.on('exit', (code) => console.error(`xray exited with code ${code}`));
  return child;
}

function subscriptionLink() {
  const host = DOMAIN || 'your-app.pxxl.app';
  const params = new URLSearchParams({
    encryption: 'none', security: 'tls', sni: host, type: 'ws', host,
    path: WS_PATH,
  });
  return `vless://${UUID}@${host}:443?${params.toString()}#Pxxl-Xray`;
}

async function main() {
  // Listen FIRST: Pxxl's health check runs seconds after the container
  // starts, but the Xray download can take longer than that window. If we
  // only listen after the download, the check fails and the container is
  // killed before Xray ever arrives. WS proxying works once Xray is up.
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

  server.on('upgrade', (req, socket, head) => {
    if (req.url !== WS_PATH) { socket.destroy(); return; }
    const upstream = net.connect(XRAY_PORT, '127.0.0.1', () => {
      const headers = Object.entries(req.headers)
        .filter(([k]) => k.toLowerCase() !== 'host')
        .map(([k, v]) => `${k}: ${v}`).join('\r\n');
      upstream.write(`${req.method} ${req.url} HTTP/1.1\r\nHost: 127.0.0.1\r\n${headers}\r\n\r\n`);
      if (head && head.length) upstream.write(head);
      socket.pipe(upstream);
      upstream.pipe(socket);
    });
    upstream.on('error', () => socket.destroy());
    socket.on('error', () => upstream.destroy());
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
  console.log(`workdir=${WORKDIR} ports=${LISTEN_PORTS.join(',')}`);

  // Start Xray in the background; never let a download failure kill the
  // HTTP server (that would fail the health check again). Retry a few times.
  const start = async () => { await ensureXray(); startXray(); };
  try {
    await start();
  } catch (err) {
    console.error('xray startup failed, will retry in background:', err.message);
    (async () => {
      for (let i = 0; i < 5; i++) {
        await new Promise((r) => setTimeout(r, 15000));
        try { await start(); console.log('xray started on retry'); return; }
        catch (e) { console.error('xray retry failed:', e.message); }
      }
    })();
  }
}

main().catch((err) => { console.error(err); process.exit(1); });
