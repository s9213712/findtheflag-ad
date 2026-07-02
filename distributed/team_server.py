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
import sqlite3
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
    "memo": "Memo Search",
    "archive": "Archive Viewer",
    "vault": "Recovery Vault",
    "cipher": "Cipher Session",
    "proxy": "Internal Proxy",
    "waf": "WAF Gateway",
    "supply": "Supply Update",
    "edge": "Edge Session",
    "media": "Media Packager",
    "agent": "Agent Tools",
    "saml": "SAML Gateway",
    "hook": "OAuth Relay",
    "ledger": "Points Ledger",
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


def memo_db() -> sqlite3.Connection:
    db_path = BASE_DIR / "runtime" / "memo.sqlite3"
    db_path.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL)")
    conn.execute("CREATE TABLE IF NOT EXISTS secrets(round INTEGER PRIMARY KEY, flag TEXT NOT NULL)")
    if conn.execute("SELECT COUNT(*) FROM notes").fetchone()[0] == 0:
        conn.executemany(
            "INSERT INTO notes(title, body) VALUES (?, ?)",
            [
                ("deploy", "Rotate service credentials before live starts."),
                ("audit", "Review search, archive, and proxy handlers first."),
                ("runbook", "Checker access is signed and should remain intact."),
            ],
        )
    round_no = current_round()
    conn.execute(
        "INSERT OR REPLACE INTO secrets(round, flag) VALUES (?, ?)",
        (round_no, flag_for("memo", round_no)),
    )
    conn.commit()
    return conn


def memo_service(query: dict[str, list[str]]) -> tuple[int, str, str]:
    q = query.get("q", ["deploy"])[0]
    rows: list[tuple[str, str]] = []
    error = ""
    try:
        conn = memo_db()
        sql = f"SELECT title, body FROM notes WHERE title LIKE '%{q}%' ORDER BY id LIMIT 8"
        rows = [(str(title), str(body)) for title, body in conn.execute(sql).fetchall()]
        conn.close()
    except Exception as exc:
        error = str(exc)
    rendered = "".join(f"<p><strong>{esc(title)}</strong><br>{esc(body)}</p>" for title, body in rows)
    body = f"""
    <h1>Memo Search</h1>
    <div class="notice">Operations notes are indexed for quick incident response.</div>
    <div class="card">
      <form>
        <label>Search</label>
        <input name="q" value="{esc(q)}">
        <button>Search</button>
      </form>
    </div>
    <div class="card">{rendered or '<p>No notes.</p>'}</div>
    <pre>{esc(error) if error else 'Query completed.'}</pre>
    """
    return page("Memo Search", body)


def archive_service(query: dict[str, list[str]]) -> tuple[int, str, str]:
    raw_doc = query.get("doc", ["welcome.txt"])[0]
    filtered = raw_doc.replace("../", "", 1).replace("..\\", "", 1)
    doc = urllib.parse.unquote(filtered)
    public_docs = {
        "welcome.txt": "Welcome to the incident archive.",
        "release.txt": "Quarterly release notes are staged here.",
        "policy/hardening.txt": "Do not remove checker or flag generation paths.",
    }
    internal_docs = {
        "private/flag.txt": f"Archive recovery flag: {flag_for('archive')}",
    }
    if doc in public_docs:
        content = public_docs[doc]
    elif doc.endswith("private/flag.txt"):
        content = internal_docs["private/flag.txt"]
    else:
        content = "Document not found."
    body = f"""
    <h1>Archive Viewer</h1>
    <div class="notice">Only public documents should be readable.</div>
    <div class="card">
      <form>
        <label>Document</label>
        <input name="doc" value="{esc(raw_doc)}">
        <button>Open</button>
      </form>
    </div>
    <pre>{esc(content)}</pre>
    """
    return page("Archive Viewer", body)


def vault_service(query: dict[str, list[str]]) -> tuple[int, str, str]:
    user = query.get("user", ["operator"])[0]
    code = query.get("code", [""])[0]
    expected = hashlib.md5(f"{TEAM_ID}:{current_round()}".encode()).hexdigest()[:6]
    if user == "admin" and code == expected:
        message = f"Recovery accepted. Vault flag: {flag_for('vault')}"
    elif code:
        message = "Recovery denied."
    else:
        message = "Vault locked."
    body = f"""
    <h1>Recovery Vault</h1>
    <div class="notice">Break-glass recovery codes are generated by the legacy scheduler.</div>
    <div class="card">
      <form>
        <label>User</label>
        <input name="user" value="{esc(user)}">
        <label>Recovery Code</label>
        <input name="code" value="{esc(code)}">
        <button>Recover</button>
      </form>
    </div>
    <pre>{esc(message)}</pre>
    """
    return page("Recovery Vault", body)


def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def cipher_token(payload: dict[str, str]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(xor_bytes(raw, b"ftf-session")).decode().rstrip("=")


def decipher_token(token: str) -> dict[str, Any]:
    raw = base64.urlsafe_b64decode((token + "=" * (-len(token) % 4)).encode())
    return json.loads(xor_bytes(raw, b"ftf-session").decode())


def cipher_service(query: dict[str, list[str]]) -> tuple[int, str, str]:
    guest = cipher_token({"role": "guest", "user": "analyst"})
    session = query.get("session", [guest])[0]
    try:
        payload = decipher_token(session)
        if payload.get("role") == "admin":
            message = f"Privileged session accepted. Cipher flag: {flag_for('cipher')}"
        else:
            message = f"Session for {payload.get('user', 'guest')} with role {payload.get('role', 'guest')}."
    except Exception as exc:
        message = f"Session decode error: {exc}"
    body = f"""
    <h1>Cipher Session</h1>
    <div class="notice">Session contents are encrypted before being sent to the browser.</div>
    <div class="card">
      <p>Guest session:</p>
      <pre>{esc(guest)}</pre>
      <form>
        <label>Session</label>
        <input name="session" value="{esc(session)}">
        <button>Open</button>
      </form>
    </div>
    <pre>{esc(message)}</pre>
    """
    return page("Cipher Session", body)


def proxy_service(query: dict[str, list[str]]) -> tuple[int, str, str]:
    url = query.get("url", ["http://docs.service.local/status"])[0]
    parsed = urllib.parse.urlparse(url)
    if ".service.local" not in url:
        message = "Proxy allowlist rejected this URL."
    elif parsed.hostname == "flag.service.local":
        message = f"Internal metadata response: {flag_for('proxy')}"
    elif parsed.hostname == "docs.service.local":
        message = "Documentation service is healthy."
    elif parsed.hostname == "status.service.local":
        message = "Status service reports nominal operations."
    else:
        message = "Backend host did not respond."
    body = f"""
    <h1>Internal Proxy</h1>
    <div class="notice">Only service-local URLs should be fetched by this diagnostic proxy.</div>
    <div class="card">
      <form>
        <label>URL</label>
        <input name="url" value="{esc(url)}">
        <button>Fetch</button>
      </form>
    </div>
    <pre>{esc(message)}</pre>
    """
    return page("Internal Proxy", body)


def waf_service(query: dict[str, list[str]]) -> tuple[int, str, str]:
    roles = query.get("role", ["user"])
    gateway_role = roles[0] if roles else "user"
    app_role = roles[-1] if roles else "user"
    if gateway_role == "admin":
        message = "Gateway blocked privileged role request."
    elif app_role == "admin":
        message = f"Application role upgraded after gateway normalization. WAF flag: {flag_for('waf')}"
    else:
        message = f"Gateway role={gateway_role}; application role={app_role}; request allowed."
    role_inputs = "".join(f'<input name="role" value="{esc(role)}">' for role in roles)
    body = f"""
    <h1>WAF Gateway</h1>
    <div class="notice">Gateway and backend normalize duplicate parameters differently.</div>
    <div class="card">
      <form>
        <label>Role Parameter(s)</label>
        {role_inputs}
        <button>Check</button>
      </form>
    </div>
    <pre>{esc(message)}</pre>
    """
    return page("WAF Gateway", body)


def supply_service(query: dict[str, list[str]]) -> tuple[int, str, str]:
    component = query.get("component", ["agent"])[0]
    version = query.get("version", ["stable"])[0]
    target = query.get("target", ["user"])[0]
    sig = query.get("sig", [""])[0]
    expected = hashlib.sha1(f"{component}:{version}".encode()).hexdigest()[:10]
    sample_sig = hashlib.sha1(b"agent:stable").hexdigest()[:10]
    if sig != expected:
        message = "Manifest signature rejected."
    elif component == "checker" and target == "root":
        message = f"Privileged update accepted. Supply flag: {flag_for('supply')}"
    else:
        message = f"Installed {component}@{version} for target={target}."
    body = f"""
    <h1>Supply Update</h1>
    <div class="notice">The update manifest signs package identity but omits the install target.</div>
    <div class="card">
      <p>Example signature for <code>agent:stable</code>: <code>{esc(sample_sig)}</code></p>
      <form>
        <label>Component</label>
        <input name="component" value="{esc(component)}">
        <label>Version</label>
        <input name="version" value="{esc(version)}">
        <label>Target</label>
        <input name="target" value="{esc(target)}">
        <label>Signature</label>
        <input name="sig" value="{esc(sig)}">
        <button>Apply Update</button>
      </form>
    </div>
    <pre>{esc(message)}</pre>
    """
    return page("Supply Update", body)


def edge_service(query: dict[str, list[str]]) -> tuple[int, str, str]:
    sid = query.get("sid", ["guest-a7f3"])[0]
    size_raw = query.get("bytes", ["24"])[0]
    public = f"sid={sid};role=guest;status=ok;"
    adjacent = f"session-cache={flag_for('edge')};audit=clean;"
    try:
        size = max(0, min(int(size_raw), 220))
    except ValueError:
        size = 24
    leaked = (public + adjacent)[:size]
    body = f"""
    <h1>Edge Session</h1>
    <div class="notice">The edge cache trusts a caller-supplied read length for session diagnostics.</div>
    <div class="card">
      <form>
        <label>Session ID</label>
        <input name="sid" value="{esc(sid)}">
        <label>Bytes</label>
        <input name="bytes" value="{esc(size_raw)}">
        <button>Read</button>
      </form>
    </div>
    <pre>{esc(leaked)}</pre>
    """
    return page("Edge Session", body)


def media_service(query: dict[str, list[str]]) -> tuple[int, str, str]:
    asset = query.get("asset", ["cover.jpg"])[0]
    if not asset.endswith(".jpg"):
        message = "Only poster image assets may be previewed."
    else:
        decoded = urllib.parse.unquote(asset)
        logical_path = decoded.split("#", 1)[0]
        if logical_path == "keys/flag.m3u8":
            message = f"Media key manifest: {flag_for('media')}"
        elif logical_path == "cover.jpg":
            message = "Poster preview is ready."
        else:
            message = "Asset not found."
    body = f"""
    <h1>Media Packager</h1>
    <div class="notice">Poster preview validation and packager path resolution disagree about URL fragments.</div>
    <div class="card">
      <form>
        <label>Asset</label>
        <input name="asset" value="{esc(asset)}">
        <button>Preview</button>
      </form>
    </div>
    <pre>{esc(message)}</pre>
    """
    return page("Media Packager", body)


def agent_service(query: dict[str, list[str]]) -> tuple[int, str, str]:
    command = query.get("command", ["read:status"])[0]
    first_action = command.split(";", 1)[0]
    actions = [item.strip() for item in command.split(";") if item.strip()]
    if not first_action.startswith("read:"):
        message = "Tool guard rejected non-read action."
    elif "export:flag" in actions:
        message = f"Tool dispatcher exported protected context: {flag_for('agent')}"
    elif "read:status" in actions:
        message = "Agent status: all tools idle."
    else:
        message = "Read tool completed with no records."
    body = f"""
    <h1>Agent Tools</h1>
    <div class="notice">The policy guard checks the first tool action, while the dispatcher executes the full chain.</div>
    <div class="card">
      <form>
        <label>Tool Command</label>
        <input name="command" value="{esc(command)}">
        <button>Run</button>
      </form>
    </div>
    <pre>{esc(message)}</pre>
    """
    return page("Agent Tools", body)


def saml_signature(user: str, role: str) -> str:
    return hmac.new(b"saml-demo-key", f"user={user};role={role}".encode(), hashlib.sha256).hexdigest()[:12]


def saml_service(query: dict[str, list[str]]) -> tuple[int, str, str]:
    user = query.get("user", ["guest"])[0]
    roles = query.get("role", ["user"])
    sig = query.get("sig", [""])[0]
    signed_role = roles[0] if roles else "user"
    app_role = roles[-1] if roles else "user"
    expected = saml_signature(user, signed_role)
    sample_sig = saml_signature("guest", "user")
    if sig != expected:
        message = "Assertion signature rejected."
    elif app_role == "admin":
        message = f"Wrapped assertion accepted. SAML flag: {flag_for('saml')}"
    else:
        message = f"Signed in {user} as {app_role}."
    role_inputs = "".join(f'<input name="role" value="{esc(role)}">' for role in roles)
    body = f"""
    <h1>SAML Gateway</h1>
    <div class="notice">The verifier signs the first role claim, while the application authorizer uses the last role claim.</div>
    <div class="card">
      <p>Example signature for <code>guest/user</code>: <code>{esc(sample_sig)}</code></p>
      <form>
        <label>User</label>
        <input name="user" value="{esc(user)}">
        <label>Role Claim(s)</label>
        {role_inputs}
        <label>Signature</label>
        <input name="sig" value="{esc(sig)}">
        <button>Login</button>
      </form>
    </div>
    <pre>{esc(message)}</pre>
    """
    return page("SAML Gateway", body)


def hook_service(query: dict[str, list[str]]) -> tuple[int, str, str]:
    redirect = query.get("redirect", ["https://trusted.service.local/callback"])[0]
    if not redirect.startswith("https://trusted.service.local"):
        message = "Relay allowlist rejected redirect URI."
    else:
        parsed = urllib.parse.urlparse(urllib.parse.unquote(redirect))
        if parsed.hostname == "vault.internal":
            message = f"Relay delivered code to internal vault: {flag_for('hook')}"
        else:
            message = f"Authorization code delivered to {parsed.hostname or 'unknown'}."
    body = f"""
    <h1>OAuth Relay</h1>
    <div class="notice">The relay validates redirect prefixes before URL authority parsing.</div>
    <div class="card">
      <form>
        <label>Redirect URI</label>
        <input name="redirect" value="{esc(redirect)}">
        <button>Authorize</button>
      </form>
    </div>
    <pre>{esc(message)}</pre>
    """
    return page("OAuth Relay", body)


def ledger_service(query: dict[str, list[str]]) -> tuple[int, str, str]:
    account = query.get("account", ["guest"])[0]
    action = query.get("action", ["transfer"])[0]
    amount_raw = query.get("amount", ["10"])[0]
    recipient = query.get("recipient", ["store"])[0]
    nonce = query.get("nonce", ["1"])[0]
    sig = query.get("sig", [""])[0]
    expected = hashlib.sha1(f"{account}:{action}:{nonce}:ledger".encode()).hexdigest()[:10]
    sample_sig = hashlib.sha1(b"guest:transfer:1:ledger").hexdigest()[:10]
    try:
        amount = int(amount_raw)
    except ValueError:
        amount = 0
    if sig != expected:
        message = "Ledger signature rejected."
    elif action == "transfer" and recipient == "treasury" and amount >= 9000:
        message = f"Privileged ledger transfer accepted. Ledger flag: {flag_for('ledger')}"
    else:
        message = f"Queued {action} of {amount} points from {account} to {recipient}."
    body = f"""
    <h1>Points Ledger</h1>
    <div class="notice">Transaction signatures bind account, action, and nonce, but not amount or recipient.</div>
    <div class="card">
      <p>Example signature for <code>guest/transfer/1</code>: <code>{esc(sample_sig)}</code></p>
      <form>
        <label>Account</label>
        <input name="account" value="{esc(account)}">
        <label>Action</label>
        <input name="action" value="{esc(action)}">
        <label>Amount</label>
        <input name="amount" value="{esc(amount_raw)}">
        <label>Recipient</label>
        <input name="recipient" value="{esc(recipient)}">
        <label>Nonce</label>
        <input name="nonce" value="{esc(nonce)}">
        <label>Signature</label>
        <input name="sig" value="{esc(sig)}">
        <button>Submit</button>
      </form>
    </div>
    <pre>{esc(message)}</pre>
    """
    return page("Points Ledger", body)


SERVICE_RENDERERS = {
    "default": default_service,
    "token": token_service,
    "shop": shop_service,
    "memo": memo_service,
    "archive": archive_service,
    "vault": vault_service,
    "cipher": cipher_service,
    "proxy": proxy_service,
    "waf": waf_service,
    "supply": supply_service,
    "edge": edge_service,
    "media": media_service,
    "agent": agent_service,
    "saml": saml_service,
    "hook": hook_service,
    "ledger": ledger_service,
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
