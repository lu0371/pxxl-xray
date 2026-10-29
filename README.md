# pxxl-xray

Xray VLESS + WS backup line for the Pxxl free tier (GitHub-source deploy).
The Pxxl edge terminates TLS and forwards plain HTTP to this process on
$PORT; Xray listens on plain WS at 127.0.0.1 only. Xray core is downloaded
at startup from the official XTLS GitHub release, pinned to v26.10.29 and
verified against the official SHA2-256 before use.

Required env vars (set in Pxxl project settings, never commit them):

- `UUID` — VLESS client id
- `WS_PATH` — WebSocket path, must start with `/`

Optional:

- `SUB_TOKEN` — enables `GET /sub?token=<SUB_TOKEN>` (base64 subscription)
- `APP_DOMAIN` — public host of this app, used only for the /sub link
- `XRAY_PORT` — internal Xray port, default 10000

Start command: `node server.js` (via `npm start`).
