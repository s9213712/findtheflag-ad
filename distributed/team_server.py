#!/usr/bin/env python3
"""
Distributed FindTheFlag team server.

Every team receives this same file. Only team_config.json differs.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = Path(os.environ.get("FTF_TEAM_CONFIG", str(BASE_DIR / "team_config.json")))
ROUND_SECONDS = 300
SERVICE_META = {
    "default": "Default Admin",
    "token": "Token Forge",
    "shop": "Coupon Shop",
}


def load_config() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        sample = {
            "team_id": "alpha",
            "team_secret": "replace-me",
            "admin_url": "http://127.0.0.1:8088",
            "public_base_url": "http://127.0.0.1:9100",
            "host": "127.0.0.1",
            "port": 9100,
            "reporting_enabled": True,
            "round_seconds": 300,
            "heartbeat_interval_seconds": 30,
            "admin_timeout_seconds": 3,
            "services": ["default"],
        }
        CONFIG_PATH.write_text(json.dumps(sample, indent=2), encoding="utf-8")
        raise SystemExit(f"Created sample config at {CONFIG_PATH}; edit it and restart.")
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


CONFIG = load_config()
TEAM_ID = str(CONFIG["team_id"])
TEAM_SECRET = str(CONFIG["team_secret"])
ADMIN_URL = str(CONFIG["admin_url"]).rstrip("/")
PUBLIC_BASE_URL = str(CONFIG.get("public_base_url", ""))
REPORTING_ENABLED = bool(CONFIG.get("reporting_enabled", True))
ROUND_SECONDS = int(os.environ.get("FTF_ROUND_SECONDS", str(CONFIG.get("round_seconds", 300))))
HEARTBEAT_INTERVAL_SECONDS = int(os.environ.get("FTF_TEAM_HEARTBEAT_INTERVAL_SECONDS", str(CONFIG.get("heartbeat_interval_seconds", 30))))
ADMIN_TIMEOUT_SECONDS = int(os.environ.get("FTF_TEAM_ADMIN_TIMEOUT_SECONDS", str(CONFIG.get("admin_timeout_seconds", 3))))
ENABLED_SERVICES = [service for service in CONFIG.get("services", ["default"]) if service in SERVICE_META] or ["default"]

phase_seen = "offline"
last_reported_round = -1
last_admin_error = ""


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def current_round() -> int:
    return int(time.time() // ROUND_SECONDS)


def round_remaining() -> int:
    return ROUND_SECONDS - int(time.time() % ROUND_SECONDS)


def flag_for(service: str, round_no: int | None = None) -> str:
    if round_no is None:
        round_no = current_round()
    digest = hmac.new(
        TEAM_SECRET.encode(),
        f"{TEAM_ID}:{service}:{round_no}".encode(),
        hashlib.sha256,
    ).hexdigest()[:18]
    return f"FTF{{{TEAM_ID}_{service}_{round_no}_{digest}}}"


def sign_body(raw: bytes) -> str:
    return hmac.new(TEAM_SECRET.encode(), raw, hashlib.sha256).hexdigest()


def verify_signature(raw: bytes, signature: str) -> bool:
    expected = hmac.new(TEAM_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def post_admin(path: str, payload: dict[str, Any], timeout: int | None = None) -> dict[str, Any]:
    if timeout is None:
        timeout = ADMIN_TIMEOUT_SECONDS
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    req = urllib.request.Request(
        ADMIN_URL + path,
        data=raw,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Team-Id": TEAM_ID,
            "X-Team-Signature": sign_body(raw),
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode())


def heartbeat_payload() -> dict[str, Any]:
    return {
        "team_id": TEAM_ID,
        "timestamp": int(time.time()),
        "public_base_url": PUBLIC_BASE_URL,
        "phase_seen": phase_seen,
        "services": {service: {"status": "up", "latency_ms": 0} for service in ENABLED_SERVICES},
    }


def flag_payload(round_no: int) -> dict[str, Any]:
    return {
        "team_id": TEAM_ID,
        "round": round_no,
        "generated_at": int(time.time()),
        "flags": {service: flag_for(service, round_no) for service in ENABLED_SERVICES},
    }


def reporter_loop() -> None:
    global phase_seen, last_admin_error, last_reported_round
    if not REPORTING_ENABLED:
        return
    while True:
        try:
            response = post_admin("/api/team/heartbeat", heartbeat_payload())
            phase_seen = str(response.get("phase", phase_seen))
            round_no = int(response.get("round", current_round()))
            if phase_seen == "live" and round_no != last_reported_round:
                post_admin("/api/team/flags", flag_payload(round_no))
                last_reported_round = round_no
            last_admin_error = ""
        except Exception as exc:
            last_admin_error = str(exc)
        time.sleep(HEARTBEAT_INTERVAL_SECONDS)


def page(title: str, body: str, status: int = 200) -> tuple[int, str, str]:
    service_links = "\n".join(
        f'<a href="/service/{esc(service)}">{esc(SERVICE_META[service])}</a>'
        for service in ENABLED_SERVICES
    )
    doc = f"""<!doctype html>
<html lang="zh-Hant">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{esc(title)} - {esc(TEAM_ID)}</title>
  <style>
    body {{ margin:0; font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; background:#f5f7fa; color:#17212b; }}
    header {{ background:#102631; color:white; padding:16px 22px; border-bottom:4px solid #d8a331; }}
    nav {{ display:flex; gap:14px; flex-wrap:wrap; margin-top:8px; }}
    nav a {{ color:white; }}
    main {{ max-width:900px; margin:0 auto; padding:22px; }}
    .card,.notice {{ background:white; border:1px solid #d9e0e8; border-radius:8px; padding:14px; margin:12px 0; }}
    input {{ width:100%; padding:9px; border:1px solid #b8c4d0; border-radius:6px; }}
    label {{ display:block; font-weight:700; margin:10px 0 5px; }}
    button,.button {{ display:inline-flex; background:#176b87; color:white; border:0; border-radius:6px; padding:9px 12px; font-weight:700; text-decoration:none; cursor:pointer; }}
    pre {{ background:#101827; color:#d8f3ff; padding:12px; border-radius:6px; overflow:auto; }}
    .bad {{ color:#b42318; }}
    .ok {{ color:#247a45; }}
  </style>
</head>
<body>
  <header>
    <strong>Team Server: {esc(TEAM_ID)}</strong>
    <nav>
      <a href="/">Status</a>
      {service_links}
      <a href="/health">Health</a>
    </nav>
  </header>
  <main>{body}</main>
</body>
</html>"""
    return status, "text/html; charset=utf-8", doc


def status_page() -> tuple[int, str, str]:
    service_buttons = "".join(
        f'<p><a class="button" href="/service/{esc(service)}">{esc(SERVICE_META[service])}</a></p>'
        for service in ENABLED_SERVICES
    )
    body = f"""
    <h1>Team Status</h1>
    <div class="notice">Round: <strong id="round">{current_round()}</strong> | Next flag in: <strong id="round-remaining">{round_remaining()}s</strong></div>
    <div class="card">
      <p>Admin phase seen: <strong id="phase-seen">{esc(phase_seen)}</strong></p>
      <p>Last reported round: <strong id="last-reported-round">{last_reported_round}</strong></p>
      <p>Reporting: <strong>{'enabled' if REPORTING_ENABLED else 'disabled'}</strong></p>
      <p id="admin-error" class="{'bad' if last_admin_error else 'ok'}">{'Admin error: ' + esc(last_admin_error) if last_admin_error else 'Admin link healthy or waiting for first heartbeat.'}</p>
    </div>
    <div class="card">
      <h2>Services</h2>
      {service_buttons}
    </div>
    <script>
      async function refreshStatus() {{
        try {{
          const res = await fetch('/health', {{cache: 'no-store'}});
          const data = await res.json();
          document.querySelector('#round').textContent = data.round;
          document.querySelector('#round-remaining').textContent = data.round_remaining + 's';
          document.querySelector('#phase-seen').textContent = data.phase_seen;
          document.querySelector('#last-reported-round').textContent = data.last_reported_round;
          const error = document.querySelector('#admin-error');
          if (data.admin_error) {{
            error.className = 'bad';
            error.textContent = 'Admin error: ' + data.admin_error;
          }} else {{
            error.className = 'ok';
            error.textContent = 'Admin link healthy or waiting for first heartbeat.';
          }}
        }} catch (err) {{}}
      }}
      setInterval(refreshStatus, 1000);
    </script>
    """
    return page("Status", body)


def default_service(query: dict[str, list[str]]) -> tuple[int, str, str]:
    username = query.get("username", [""])[0]
    password = query.get("password", [""])[0]
    if username == "admin" and password == "admin":
        message = f"Welcome vendor admin. Current backup flag: {flag_for('default')}"
    elif username or password:
        message = "Invalid credentials."
    else:
        message = "Vendor console locked."
    body = f"""
    <h1>Default Admin</h1>
    <div class="notice">This service intentionally starts with vendor defaults. Harden it during the offline window.</div>
    <div class="card">
      <form>
        <label>Username</label>
        <input name="username" value="{esc(username)}" placeholder="admin">
        <label>Password</label>
        <input name="password" value="{esc(password)}" placeholder="admin">
        <button>Login</button>
      </form>
    </div>
    <pre>{esc(message)}</pre>
    """
    return page("Default Admin", body)


def token_service(query: dict[str, list[str]]) -> tuple[int, str, str]:
    guest = base64.urlsafe_b64encode(json.dumps({"user": "guest", "role": "guest"}).encode()).decode().rstrip("=")
    token = query.get("token", [guest])[0]
    try:
        raw = base64.urlsafe_b64decode((token + "=" * (-len(token) % 4)).encode()).decode()
        payload = json.loads(raw)
        if payload.get("role") == "admin":
            message = f"Admin token accepted. Current token flag: {flag_for('token')}"
        else:
            message = f"Hello {payload.get('user', 'guest')} with role {payload.get('role', 'guest')}."
    except Exception as exc:
        message = f"Token error: {exc}"
    body = f"""
    <h1>Token Forge</h1>
    <div class="notice">This service trusts unsigned base64 JSON tokens.</div>
    <div class="card">
      <p>Guest token:</p>
      <pre>{esc(guest)}</pre>
      <form>
        <label>Token</label>
        <input name="token" value="{esc(token)}">
        <button>Open</button>
      </form>
    </div>
    <pre>{esc(message)}</pre>
    """
    return page("Token Forge", body)


def shop_service(query: dict[str, list[str]]) -> tuple[int, str, str]:
    item = query.get("item", ["sticker"])[0]
    qty_raw = query.get("qty", ["1"])[0]
    coupon = query.get("coupon", [""])[0]
    prices = {"sticker": 3, "hoodie": 35, "flag-crate": 250}
    try:
        qty = int(qty_raw)
    except ValueError:
        qty = 1
    if item not in prices:
        message = "Unknown item."
    else:
        discount = 999 if coupon == "UNDERFLOW" else 0
        total = prices[item] * qty - discount
        if item == "flag-crate" and total <= 0:
            message = f"Crate opened. Current shop flag: {flag_for('shop')}"
        else:
            message = f"Order total: {total} credits."
    body = f"""
    <h1>Coupon Shop</h1>
    <div class="notice">Restricted flag crates should not be free.</div>
    <div class="card">
      <form>
        <label>Item</label>
        <input name="item" value="{esc(item)}">
        <label>Quantity</label>
        <input name="qty" value="{esc(qty_raw)}">
        <label>Coupon</label>
        <input name="coupon" value="{esc(coupon)}">
        <button>Buy</button>
      </form>
    </div>
    <pre>{esc(message)}</pre>
    """
    return page("Coupon Shop", body)


SERVICE_RENDERERS = {
    "default": default_service,
    "token": token_service,
    "shop": shop_service,
}


def health_json() -> dict[str, Any]:
    return {
        "team_id": TEAM_ID,
        "round": current_round(),
        "round_remaining": round_remaining(),
        "phase_seen": phase_seen,
        "services": {service: "up" for service in ENABLED_SERVICES},
        "reporting_enabled": REPORTING_ENABLED,
        "last_reported_round": last_reported_round,
        "admin_error": last_admin_error,
    }


class ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True


class TeamHandler(BaseHTTPRequestHandler):
    server_version = "FTFTeamServer/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[{time.strftime('%H:%M:%S')}] {self.address_string()} {fmt % args}")

    def send_json(self, status: int, data: dict[str, Any]) -> None:
        raw = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def read_body(self) -> bytes:
        length = int(self.headers.get("content-length", "0") or "0")
        return self.rfile.read(length) if length else b""

    def respond(self, response: tuple[int, str, str]) -> None:
        status, content_type, text = response
        raw = text.encode()
        self.send_response(int(status))
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = urllib.parse.parse_qs(parsed.query)
        if path == "/":
            return self.respond(status_page())
        if path == "/status":
            return self.respond(status_page())
        if path == "/health":
            return self.send_json(200, health_json())
        if path.startswith("/service/"):
            service = path.rsplit("/", 1)[-1]
            renderer = SERVICE_RENDERERS.get(service)
            if service in ENABLED_SERVICES and renderer:
                return self.respond(renderer(query))
            return self.respond(page("Service disabled", "<h1>Service disabled</h1>", HTTPStatus.NOT_FOUND))
        return self.respond(page("Not found", "<h1>Not found</h1>", HTTPStatus.NOT_FOUND))

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        body = self.read_body()
        if path == "/__checker/flags":
            signature = self.headers.get("X-Checker-Signature", "")
            if not verify_signature(body, signature):
                return self.send_json(403, {"ok": False, "message": "bad checker signature"})
            try:
                payload = json.loads(body.decode() or "{}")
                round_no = int(payload.get("round", current_round()))
            except Exception:
                return self.send_json(400, {"ok": False, "message": "bad checker payload"})
            return self.send_json(
                200,
                {
                    "ok": True,
                    "team_id": TEAM_ID,
                    "round": round_no,
                    "flags": {service: flag_for(service, round_no) for service in ENABLED_SERVICES},
                },
            )
        return self.respond(page("Not found", "<h1>Not found</h1>", HTTPStatus.NOT_FOUND))


def main() -> None:
    host = str(CONFIG.get("host", "127.0.0.1"))
    port = int(CONFIG.get("port", 9100))
    if REPORTING_ENABLED:
        threading.Thread(target=reporter_loop, daemon=True).start()
    print(f"Team server {TEAM_ID} running at http://{host}:{port}")
    print(f"Admin URL: {ADMIN_URL}")
    ReusableThreadingHTTPServer((host, port), TeamHandler).serve_forever()


if __name__ == "__main__":
    main()
