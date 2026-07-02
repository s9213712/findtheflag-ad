#!/usr/bin/env python3
"""
FindTheFlag Attack-with-Defense local training arena.

This is an intentionally vulnerable CTF lab for local practice. Do not expose it
to the public internet.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import re
import sqlite3
import time
import urllib.parse
from dataclasses import dataclass
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
WEB_DIR = BASE_DIR / "web"
TEAM_WEB_DIR = WEB_DIR / "team"
ADMIN_WEB_DIR = WEB_DIR / "admin"
DB_PATH = DATA_DIR / "arena.sqlite3"
SECRET_PATH = DATA_DIR / "secret.txt"
ADMIN_PASSWORD_PATH = DATA_DIR / "admin_password.txt"
TEAM_PASSWORDS_PATH = DATA_DIR / "team_passwords.json"
ROUND_SECONDS = 120
PHASES = {"hardening", "live", "ended"}
DEFAULT_SCORING = {
    "attack_flag_points": 10,
    "patched_flag_points": 4,
    "availability_points": 2,
    "integrity_points": 2,
    "admin_access_penalty": 15,
    "infra_attack_penalty": 50,
    "checker_timeout_seconds": 3,
}
TEAMS = ["alpha", "bravo", "charlie", "delta"]


@dataclass(frozen=True)
class Service:
    key: str
    name: str
    category: str
    objective: str
    patch_name: str
    difficulty: str


SERVICES = [
    Service("memo", "Memo SQL", "Web / SQLi", "Read the private incident memo.", "Prepared statements", "easy"),
    Service("archive", "Archive Box", "Web / LFI", "Read a hidden archived file.", "Path normalization allowlist", "easy"),
    Service("token", "Token Forge", "Auth / Weak token", "Become an admin user.", "Signed tokens", "easy"),
    Service("default", "Default Admin", "Auth / Default credentials", "Log in with unchanged vendor credentials.", "Rotate default passwords", "easy"),
    Service("shop", "Coupon Shop", "Logic", "Buy the restricted flag item.", "Validate quantities and coupons", "easy"),
    Service("tickets", "Support Desk", "IDOR", "Open the confidential ticket.", "Owner checks", "easy"),
    Service("render", "Badge Renderer", "Template injection", "Render a badge that leaks config.", "Escape template variables", "medium"),
    Service("robot", "Robot Fetcher", "SSRF", "Fetch an internal metadata URL.", "Block private metadata targets", "medium"),
    Service("cookies", "Cookie Portal", "Auth / Trust boundary", "Access the admin portal.", "Server-side sessions", "easy"),
    Service("nosql", "People API", "NoSQL-style injection", "Bypass the operator login filter.", "Strict schema validation", "medium"),
    Service("backup", "Backup Index", "Predictable secret", "Download a predictable backup manifest.", "Randomized backup names", "easy"),
    Service("crypto", "XOR Locker", "Crypto", "Recover the plaintext flag.", "Authenticated encryption", "medium"),
    Service("redeem", "Redeem Race", "State logic", "Redeem the launch code twice.", "Atomic single-use redemption", "medium"),
]


def get_secret() -> str:
    DATA_DIR.mkdir(exist_ok=True)
    if not SECRET_PATH.exists():
        SECRET_PATH.write_text(base64.urlsafe_b64encode(os.urandom(32)).decode(), encoding="utf-8")
    return SECRET_PATH.read_text(encoding="utf-8").strip()


SECRET = get_secret()


def get_admin_password() -> str:
    env_password = os.environ.get("FTF_ADMIN_PASSWORD")
    if env_password:
        return env_password
    DATA_DIR.mkdir(exist_ok=True)
    if not ADMIN_PASSWORD_PATH.exists():
        password = base64.urlsafe_b64encode(os.urandom(12)).decode().rstrip("=")
        ADMIN_PASSWORD_PATH.write_text(password, encoding="utf-8")
    return ADMIN_PASSWORD_PATH.read_text(encoding="utf-8").strip()


ADMIN_PASSWORD = get_admin_password()


def get_team_passwords() -> dict[str, str]:
    DATA_DIR.mkdir(exist_ok=True)
    if TEAM_PASSWORDS_PATH.exists():
        try:
            data = json.loads(TEAM_PASSWORDS_PATH.read_text(encoding="utf-8"))
            if all(team in data for team in TEAMS):
                return {team: str(data[team]) for team in TEAMS}
        except json.JSONDecodeError:
            pass
    passwords = {
        team: base64.urlsafe_b64encode(os.urandom(9)).decode().rstrip("=")
        for team in TEAMS
    }
    TEAM_PASSWORDS_PATH.write_text(json.dumps(passwords, indent=2), encoding="utf-8")
    return passwords


TEAM_PASSWORDS = get_team_passwords()


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS patches (
                team TEXT NOT NULL,
                service TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 0,
                updated_at REAL NOT NULL,
                PRIMARY KEY (team, service)
            );
            CREATE TABLE IF NOT EXISTS submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attacker TEXT NOT NULL,
                victim TEXT NOT NULL,
                service TEXT NOT NULL,
                round INTEGER NOT NULL,
                flag TEXT NOT NULL,
                points INTEGER NOT NULL,
                created_at REAL NOT NULL,
                UNIQUE(attacker, victim, service, round)
            );
            CREATE TABLE IF NOT EXISTS service_state (
                team TEXT NOT NULL,
                service TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                PRIMARY KEY (team, service, key)
            );
            CREATE TABLE IF NOT EXISTS penalties (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                team TEXT NOT NULL,
                reason TEXT NOT NULL,
                path TEXT NOT NULL,
                points INTEGER NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS memo_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                team TEXT NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                public INTEGER NOT NULL
            );
            """
        )
        for team in TEAMS:
            for service in SERVICES:
                conn.execute(
                    "INSERT OR IGNORE INTO patches(team, service, enabled, updated_at) VALUES (?, ?, 0, ?)",
                    (team, service.key, time.time()),
                )
        conn.execute("INSERT OR IGNORE INTO settings(key, value) VALUES ('game_phase', 'hardening')")
        for key, value in DEFAULT_SCORING.items():
            conn.execute(
                "INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)",
                (f"scoring.{key}", str(value)),
            )
        existing = conn.execute("SELECT COUNT(*) FROM memo_entries").fetchone()[0]
        if existing == 0:
            for team in TEAMS:
                conn.executemany(
                    "INSERT INTO memo_entries(team, title, body, public) VALUES (?, ?, ?, ?)",
                    [
                        (team, "shift handoff", "Rotate logs before the next scoring window.", 1),
                        (team, "public status", "All endpoints are green from the outside checker.", 1),
                        (team, "private incident", "Operator vault note: {{ROUND_FLAG}}", 0),
                    ],
                )
        conn.execute(
            "UPDATE memo_entries SET body = 'Operator vault note: {{ROUND_FLAG}}' WHERE public = 0 AND title = 'private incident'"
        )


def current_round() -> int:
    return int(time.time() // ROUND_SECONDS)


def seconds_remaining() -> int:
    return ROUND_SECONDS - int(time.time() % ROUND_SECONDS)


def service_by_key(key: str) -> Service | None:
    return next((s for s in SERVICES if s.key == key), None)


def flag_for(team: str, service: str, round_no: int | None = None) -> str:
    if round_no is None:
        round_no = current_round()
    digest = hmac.new(
        SECRET.encode(),
        f"{team}:{service}:{round_no}".encode(),
        hashlib.sha256,
    ).hexdigest()[:18]
    return f"FTF{{{team}_{service}_{round_no}_{digest}}}"


def patched(team: str, service: str) -> bool:
    with db() as conn:
        row = conn.execute(
            "SELECT enabled FROM patches WHERE team = ? AND service = ?",
            (team, service),
        ).fetchone()
    return bool(row and row["enabled"])


def set_patch(team: str, service: str, enabled: bool) -> None:
    with db() as conn:
        conn.execute(
            """
            INSERT INTO patches(team, service, enabled, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(team, service)
            DO UPDATE SET enabled = excluded.enabled, updated_at = excluded.updated_at
            """,
            (team, service, 1 if enabled else 0, time.time()),
        )


def record_penalty(team: str, reason: str, path: str, points: int | None = None) -> None:
    if team not in TEAMS:
        return
    if points is None:
        points = scoring_config()["admin_access_penalty"]
    with db() as conn:
        conn.execute(
            "INSERT INTO penalties(team, reason, path, points, created_at) VALUES (?, ?, ?, ?, ?)",
            (team, reason, path[:240], points, time.time()),
        )


def get_state(team: str, service: str, key: str, default: str = "") -> str:
    with db() as conn:
        row = conn.execute(
            "SELECT value FROM service_state WHERE team = ? AND service = ? AND key = ?",
            (team, service, key),
        ).fetchone()
    return row["value"] if row else default


def put_state(team: str, service: str, key: str, value: str) -> None:
    with db() as conn:
        conn.execute(
            """
            INSERT INTO service_state(team, service, key, value)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(team, service, key) DO UPDATE SET value = excluded.value
            """,
            (team, service, key, value),
        )


def get_setting(key: str, default: str = "") -> str:
    with db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    with db() as conn:
        conn.execute(
            """
            INSERT INTO settings(key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )


def current_phase() -> str:
    phase = get_setting("game_phase", "hardening")
    return phase if phase in PHASES else "hardening"


def set_phase(phase: str) -> None:
    if phase not in PHASES:
        raise ValueError("unknown phase")
    set_setting("game_phase", phase)
    set_setting("phase_changed_at", str(time.time()))


def scoring_config() -> dict[str, int]:
    config: dict[str, int] = {}
    for key, default in DEFAULT_SCORING.items():
        raw = get_setting(f"scoring.{key}", str(default))
        try:
            value = int(raw)
        except ValueError:
            value = int(default)
        config[key] = max(0, value)
    return config


def set_scoring_config(values: dict[str, Any]) -> None:
    for key in DEFAULT_SCORING:
        if key not in values:
            continue
        try:
            value = int(str(values[key]))
        except ValueError:
            continue
        set_setting(f"scoring.{key}", str(max(0, value)))


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def b64_json(data: dict[str, Any]) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unb64_json(token: str) -> dict[str, Any]:
    padding = "=" * (-len(token) % 4)
    raw = base64.urlsafe_b64decode((token + padding).encode())
    return json.loads(raw.decode())


def sign_token(payload: dict[str, Any]) -> str:
    body = b64_json(payload)
    sig = hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()[:24]
    return f"{body}.{sig}"


def verify_token(token: str) -> dict[str, Any] | None:
    if "." not in token:
        return None
    body, sig = token.rsplit(".", 1)
    expected = hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()[:24]
    if not hmac.compare_digest(sig, expected):
        return None
    return unb64_json(body)


def parse_cookies(header: str | None) -> dict[str, str]:
    if not header:
        return {}
    cookie = SimpleCookie()
    cookie.load(header)
    return {key: morsel.value for key, morsel in cookie.items()}


def admin_session_cookie() -> str:
    return sign_token({"role": "admin", "issued_round": current_round()})


def team_session_cookie(team: str) -> str:
    return sign_token({"role": "team", "team": team, "issued_round": current_round()})


def is_admin(headers: dict[str, str]) -> bool:
    cookies = parse_cookies(headers.get("cookie"))
    payload = verify_token(cookies.get("admin_session", ""))
    return bool(payload and payload.get("role") == "admin")


def current_team(headers: dict[str, str]) -> str | None:
    cookies = parse_cookies(headers.get("cookie"))
    payload = verify_token(cookies.get("team_session", ""))
    if payload and payload.get("role") == "team" and payload.get("team") in TEAMS:
        return str(payload["team"])
    return None


def team_from_request(query: dict[str, list[str]], headers: dict[str, str]) -> str | None:
    authed_team = current_team(headers)
    if authed_team:
        return authed_team
    candidate = q_one(query, "team")
    if candidate in TEAMS:
        return candidate
    cookies = parse_cookies(headers.get("cookie"))
    candidate = cookies.get("team", "")
    return candidate if candidate in TEAMS else None


def admin_forbidden_page(team: str | None, path: str) -> tuple[int, str, str]:
    penalty = scoring_config()["admin_access_penalty"]
    if team:
        record_penalty(team, "admin page access", path)
        message = f"管理頁不是攻擊目標。已記錄 {team} 扣 {penalty} 分。"
    else:
        message = "管理頁不是攻擊目標。無法辨識隊伍時不記分，但此請求已被拒絕。"
    body = f"""
    <h1>Forbidden</h1>
    <div class="notice alert">{esc(message)}</div>
    <p>參賽者請回到 <a href="/play">Team Arena</a>。</p>
    """
    return page("Forbidden", body, HTTPStatus.FORBIDDEN)


def page(title: str, body: str, status: int = 200, extra_head: str = "", area: str = "team") -> tuple[int, str, str]:
    if area == "admin":
        brand = "FindTheFlag Admin Console"
        nav = """
        <a href="/admin">Dashboard</a>
        <a href="/admin/scoring">Scoring</a>
        <a href="/admin/defense">Defense</a>
        <a href="/admin/operator">Operator</a>
        <a href="/play">Team View</a>
        """
    else:
        brand = "FindTheFlag Team Arena"
        nav = """
        <a href="/play">Scoreboard</a>
        <a href="/play/targets">Targets</a>
        <a href="/play/defense">Defense</a>
        <a href="/play/login">Login</a>
        """
    html_doc = f"""<!doctype html>
<html lang="zh-Hant">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{esc(title)} - FindTheFlag AD</title>
  <style>
    :root {{
      color-scheme: light;
      --ink:#17212b; --muted:#637083; --line:#d9e0e8; --panel:#ffffff;
      --bg:#f4f7fa; --brand:#176b87; --accent:#c6532f; --ok:#247a45; --bad:#b42318;
      --warn:#936500; --code:#0f172a;
    }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color:var(--ink); background:var(--bg); }}
    a {{ color:var(--brand); text-decoration:none; }}
    a:hover {{ text-decoration:underline; }}
    header {{ background:#112631; color:white; border-bottom:4px solid #d8a331; }}
    .topbar {{ max-width:1200px; margin:0 auto; padding:18px 20px; display:flex; align-items:center; justify-content:space-between; gap:16px; }}
    .brand {{ font-size:20px; font-weight:800; letter-spacing:0; }}
    .nav {{ display:flex; gap:12px; flex-wrap:wrap; font-size:14px; }}
    .nav a {{ color:white; opacity:.92; }}
    main {{ max-width:1200px; margin:0 auto; padding:22px 20px 42px; }}
    h1 {{ margin:0 0 8px; font-size:32px; line-height:1.12; }}
    h2 {{ margin:22px 0 12px; font-size:20px; }}
    h3 {{ margin:0 0 8px; font-size:16px; }}
    p {{ color:var(--muted); line-height:1.55; }}
    .grid {{ display:grid; gap:14px; grid-template-columns:repeat(auto-fit, minmax(250px, 1fr)); }}
    .card {{ background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:16px; box-shadow:0 1px 2px rgba(23,33,43,.04); }}
    .service-grid {{ display:grid; gap:12px; grid-template-columns:repeat(auto-fit, minmax(260px, 1fr)); }}
    .service-card {{ min-height:172px; display:flex; flex-direction:column; justify-content:space-between; }}
    .meta {{ display:flex; gap:8px; flex-wrap:wrap; margin:10px 0; }}
    .pill {{ display:inline-flex; align-items:center; border:1px solid var(--line); background:#f8fafc; color:#334155; border-radius:999px; padding:4px 9px; font-size:12px; }}
    .pill.ok {{ color:var(--ok); border-color:#a8d5b8; background:#f2fbf5; }}
    .pill.bad {{ color:var(--bad); border-color:#f3b7ae; background:#fff5f3; }}
    .pill.warn {{ color:var(--warn); border-color:#e8d28e; background:#fff9e8; }}
    table {{ border-collapse:collapse; width:100%; background:white; border:1px solid var(--line); border-radius:8px; overflow:hidden; }}
    th, td {{ padding:10px 12px; border-bottom:1px solid var(--line); text-align:left; font-size:14px; vertical-align:top; }}
    th {{ background:#eef4f7; color:#334155; }}
    tr:last-child td {{ border-bottom:0; }}
    input, select, textarea {{ width:100%; border:1px solid #b8c4d0; border-radius:6px; padding:10px 11px; font:inherit; background:white; color:var(--ink); }}
    label {{ display:block; font-size:13px; font-weight:700; color:#334155; margin:10px 0 6px; }}
    button, .button {{ display:inline-flex; align-items:center; justify-content:center; border:0; border-radius:6px; padding:10px 13px; font-weight:800; font-size:14px; background:var(--brand); color:white; cursor:pointer; text-decoration:none; min-height:40px; }}
    button.secondary, .button.secondary {{ background:#e5edf2; color:#173447; }}
    button.danger {{ background:var(--accent); }}
    .row {{ display:flex; gap:10px; flex-wrap:wrap; align-items:end; }}
    .row > * {{ flex:1 1 170px; }}
    .code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; background:#101827; color:#d8f3ff; border-radius:6px; padding:10px; overflow:auto; white-space:pre-wrap; line-height:1.45; }}
    .notice {{ border-left:4px solid var(--brand); background:white; padding:12px 14px; border-radius:6px; color:#334155; }}
    .alert {{ border-left-color:var(--accent); }}
    .result {{ margin-top:12px; min-height:24px; color:#334155; }}
    .compact {{ margin:4px 0; color:#637083; font-size:13px; }}
    .hero {{ display:grid; grid-template-columns:minmax(0, 1.45fr) minmax(300px, .8fr); gap:18px; align-items:stretch; }}
    .hero .panel {{ background:white; border:1px solid var(--line); border-radius:8px; padding:18px; }}
    @media (max-width:760px) {{
      .hero {{ grid-template-columns:1fr; }}
      h1 {{ font-size:26px; }}
      .topbar {{ align-items:flex-start; flex-direction:column; }}
    }}
  </style>
  {extra_head}
</head>
<body>
  <header>
    <div class="topbar">
      <div class="brand">{brand}</div>
      <nav class="nav">
        {nav}
      </nav>
    </div>
  </header>
  <main>{body}</main>
</body>
</html>"""
    return status, "text/html; charset=utf-8", html_doc


def service_shell(team: str, service: Service, inner: str, query: dict[str, list[str]]) -> tuple[int, str, str]:
    patch = patched(team, service.key)
    body = f"""
    <div class="notice">
      <strong>{esc(team)} / {esc(service.name)}</strong>
      <span class="pill {'ok' if patch else 'warn'}">{'patched' if patch else 'vulnerable'}</span>
      <p class="compact">Goal: {esc(service.objective)}</p>
    </div>
    <h1>{esc(service.name)}</h1>
    {inner}
    <h2>Submit</h2>
    <div class="card">
      <form id="submit-form">
        <div class="row">
          <div><label>Flag</label><input name="flag" placeholder="FTF{{...}}"></div>
          <div><button>Submit flag</button></div>
        </div>
      </form>
      <div id="submit-result" class="result"></div>
    </div>
    <script>
      document.querySelector('#submit-form').addEventListener('submit', async (event) => {{
        event.preventDefault();
        const data = Object.fromEntries(new FormData(event.target).entries());
        const res = await fetch('/api/submit', {{method:'POST', headers:{{'Content-Type':'application/json'}}, body:JSON.stringify(data)}});
        const body = await res.json();
        document.querySelector('#submit-result').textContent = body.message;
      }});
    </script>
    """
    return page(f"{team} {service.name}", body)


def team_options(selected: str | None = None) -> str:
    return "".join(
        f'<option value="{esc(team)}" {"selected" if team == selected else ""}>{esc(team)}</option>'
        for team in TEAMS
    )


def q_one(query: dict[str, list[str]], key: str, default: str = "") -> str:
    values = query.get(key)
    return values[0] if values else default


def render_memo(team: str, query: dict[str, list[str]], body: bytes, headers: dict[str, str]) -> tuple[int, str, str]:
    q = q_one(query, "q")
    rows: list[sqlite3.Row] = []
    error = ""
    if q:
        with db() as conn:
            if patched(team, "memo"):
                rows = conn.execute(
                    "SELECT id, team, title, body, public FROM memo_entries WHERE team = ? AND public = 1 AND title LIKE ?",
                    (team, f"%{q}%"),
                ).fetchall()
            else:
                sql = f"SELECT id, team, title, body, public FROM memo_entries WHERE team = '{team}' AND public = 1 AND title LIKE '%{q}%'"
                try:
                    rows = conn.execute(sql).fetchall()
                except sqlite3.Error as exc:
                    error = str(exc)
    rendered_rows = []
    for row in rows:
        body_text = row["body"]
        if "{{ROUND_FLAG}}" in body_text:
            body_text = body_text.replace("{{ROUND_FLAG}}", flag_for(row["team"], "memo"))
        rendered_rows.append(
            f"<tr><td>{row['id']}</td><td>{esc(row['title'])}</td><td>{esc(body_text)}</td><td>{row['public']}</td></tr>"
        )
    rows_html = "".join(rendered_rows) or "<tr><td colspan='4'>No rows.</td></tr>"
    inner = f"""
    <div class="card">
      <form>
        <label>Search public memo titles</label>
        <div class="row"><input name="q" value="{esc(q)}" placeholder="shift"><button>Search</button></div>
      </form>
      {'<p class="alert notice">' + esc(error) + '</p>' if error else ''}
    </div>
    <h2>Results</h2>
    <table><thead><tr><th>ID</th><th>Title</th><th>Body</th><th>Public</th></tr></thead><tbody>{rows_html}</tbody></table>
    """
    return service_shell(team, service_by_key("memo"), inner, query)  # type: ignore[arg-type]


def render_archive(team: str, query: dict[str, list[str]], body: bytes, headers: dict[str, str]) -> tuple[int, str, str]:
    file_name = q_one(query, "file", "readme.txt")
    files = {
        "readme.txt": "Archive service for public runbooks.\nAvailable: readme.txt, checklist.txt",
        "checklist.txt": "1. Keep backups fresh\n2. Do not publish secret paths\n3. Rotate every round",
        f"teams/{team}/flags/archive.txt": flag_for(team, "archive"),
    }
    content = ""
    if patched(team, "archive"):
        safe_name = os.path.basename(file_name)
        content = files.get(safe_name, "not found")
    else:
        normalized = os.path.normpath(f"teams/{team}/public/{file_name}")
        if normalized.endswith("flags/archive.txt"):
            content = files[f"teams/{team}/flags/archive.txt"]
        else:
            content = files.get(file_name, files.get(os.path.basename(file_name), "not found"))
    inner = f"""
    <div class="card">
      <form>
        <label>Open archived file</label>
        <div class="row"><input name="file" value="{esc(file_name)}"><button>Open</button></div>
      </form>
    </div>
    <h2>File</h2>
    <pre class="code">{esc(content)}</pre>
    """
    return service_shell(team, service_by_key("archive"), inner, query)  # type: ignore[arg-type]


def render_token(team: str, query: dict[str, list[str]], body: bytes, headers: dict[str, str]) -> tuple[int, str, str]:
    guest = sign_token({"team": team, "user": "guest", "role": "guest"}) if patched(team, "token") else b64_json({"team": team, "user": "guest", "role": "guest"})
    token = q_one(query, "token", guest)
    result = "Guest access."
    try:
        payload = verify_token(token) if patched(team, "token") else unb64_json(token)
        if payload and payload.get("team") == team and payload.get("role") == "admin":
            result = f"Admin console unlocked: {flag_for(team, 'token')}"
        elif payload:
            result = f"Hello {payload.get('user', 'guest')} with role {payload.get('role', 'guest')}."
        else:
            result = "Invalid token signature."
    except Exception as exc:
        result = f"Token error: {exc}"
    inner = f"""
    <div class="card">
      <p>Guest token:</p>
      <pre class="code">{esc(guest)}</pre>
      <form>
        <label>Token</label>
        <textarea name="token" rows="3">{esc(token)}</textarea>
        <button>Open console</button>
      </form>
    </div>
    <h2>Console</h2>
    <pre class="code">{esc(result)}</pre>
    """
    return service_shell(team, service_by_key("token"), inner, query)  # type: ignore[arg-type]


def render_default(team: str, query: dict[str, list[str]], body: bytes, headers: dict[str, str]) -> tuple[int, str, str]:
    username = q_one(query, "username")
    password = q_one(query, "password")
    if body:
        try:
            payload = json.loads(body.decode())
            username = str(payload.get("username", username))
            password = str(payload.get("password", password))
        except json.JSONDecodeError:
            pass
    if not username and not password:
        message = "Vendor console locked."
    elif patched(team, "default"):
        if username == "admin" and password == "admin":
            message = "Default credentials disabled after hardening."
        else:
            message = "Invalid credentials."
    elif username == "admin" and password == "admin":
        message = f"Welcome vendor admin. Backup flag: {flag_for(team, 'default')}"
    else:
        message = "Invalid credentials."
    inner = f"""
    <div class="card">
      <form>
        <div class="row">
          <div><label>Username</label><input name="username" value="{esc(username)}" placeholder="admin"></div>
          <div><label>Password</label><input name="password" value="{esc(password)}" placeholder="admin"></div>
          <div><button>Login</button></div>
        </div>
      </form>
    </div>
    <pre class="code">{esc(message)}</pre>
    """
    return service_shell(team, service_by_key("default"), inner, query)  # type: ignore[arg-type]


def render_shop(team: str, query: dict[str, list[str]], body: bytes, headers: dict[str, str]) -> tuple[int, str, str]:
    item = q_one(query, "item", "sticker")
    qty_raw = q_one(query, "qty", "1")
    coupon = q_one(query, "coupon", "")
    prices = {"sticker": 3, "hoodie": 35, "flag-crate": 250}
    try:
        qty = int(qty_raw)
    except ValueError:
        qty = 1
    message = "Choose an item."
    if item in prices:
        discount = 10 if coupon == "LAUNCH10" else 0
        if patched(team, "shop"):
            qty = max(1, min(qty, 5))
            if item == "flag-crate":
                message = "flag-crate is out of stock for public buyers."
            else:
                total = max(0, prices[item] * qty - discount)
                message = f"Order total: {total} credits."
        else:
            if coupon == "UNDERFLOW":
                discount = 999
            total = prices[item] * qty - discount
            if item == "flag-crate" and total <= 0:
                message = f"Paid balance accepted. Crate opened: {flag_for(team, 'shop')}"
            else:
                message = f"Order total: {total} credits."
    inner = f"""
    <div class="card">
      <form>
        <div class="row">
          <div><label>Item</label><select name="item">
            <option value="sticker" {'selected' if item == 'sticker' else ''}>sticker - 3</option>
            <option value="hoodie" {'selected' if item == 'hoodie' else ''}>hoodie - 35</option>
            <option value="flag-crate" {'selected' if item == 'flag-crate' else ''}>flag-crate - 250</option>
          </select></div>
          <div><label>Quantity</label><input name="qty" value="{esc(qty_raw)}"></div>
          <div><label>Coupon</label><input name="coupon" value="{esc(coupon)}" placeholder="LAUNCH10"></div>
          <div><button>Buy</button></div>
        </div>
      </form>
    </div>
    <pre class="code">{esc(message)}</pre>
    """
    return service_shell(team, service_by_key("shop"), inner, query)  # type: ignore[arg-type]


def render_tickets(team: str, query: dict[str, list[str]], body: bytes, headers: dict[str, str]) -> tuple[int, str, str]:
    ticket_id = q_one(query, "id", "1001")
    tickets = {
        "1001": {"owner": "guest", "title": "Login issue", "body": "Reset your browser cache."},
        "1002": {"owner": "guest", "title": "Score delay", "body": "Scoreboard updates every few seconds."},
        "7319": {"owner": "operator", "title": "Confidential flag rotation", "body": flag_for(team, "tickets")},
    }
    ticket = tickets.get(ticket_id)
    if patched(team, "tickets") and ticket and ticket["owner"] != "guest":
        ticket = {"owner": "system", "title": "Access denied", "body": "Ticket owner mismatch."}
    if not ticket:
        ticket = {"owner": "system", "title": "Not found", "body": "No such ticket."}
    inner = f"""
    <div class="card">
      <form>
        <label>Ticket ID</label>
        <div class="row"><input name="id" value="{esc(ticket_id)}"><button>Open</button></div>
      </form>
    </div>
    <h2>{esc(ticket['title'])}</h2>
    <div class="card"><p class="compact">Owner: {esc(ticket['owner'])}</p><pre class="code">{esc(ticket['body'])}</pre></div>
    """
    return service_shell(team, service_by_key("tickets"), inner, query)  # type: ignore[arg-type]


def render_badge(team: str, query: dict[str, list[str]], body: bytes, headers: dict[str, str]) -> tuple[int, str, str]:
    name = q_one(query, "name", "guest")
    rendered = name
    if patched(team, "render"):
        rendered = esc(name)
    else:
        def repl(match: re.Match[str]) -> str:
            expr = match.group(1).strip()
            if expr in {"config.flag", "flag", "settings.secret"}:
                return flag_for(team, "render")
            if expr == "team":
                return team
            if expr == "7*7":
                return "49"
            return ""
        rendered = re.sub(r"\{\{\s*(.*?)\s*\}\}", repl, name)
    inner = f"""
    <div class="card">
      <form>
        <label>Badge name</label>
        <div class="row"><input name="name" value="{esc(name)}" placeholder="guest"><button>Render</button></div>
      </form>
    </div>
    <h2>Badge Preview</h2>
    <div class="card"><h3>{rendered}</h3><p>Temporary arena badge for {esc(team)}.</p></div>
    """
    return service_shell(team, service_by_key("render"), inner, query)  # type: ignore[arg-type]


def render_robot(team: str, query: dict[str, list[str]], body: bytes, headers: dict[str, str]) -> tuple[int, str, str]:
    url = q_one(query, "url", "https://status.example/public")
    content = "Remote fetch disabled in the local arena."
    if url:
        parsed = urllib.parse.urlparse(url)
        internal = parsed.netloc in {"metadata.local", "169.254.169.254", "127.0.0.1"} or parsed.hostname == "localhost"
        if patched(team, "robot") and internal:
            content = "blocked private metadata target"
        elif internal and parsed.path in {"/flag", "/latest/meta-data/flag"}:
            content = f"metadata-token={flag_for(team, 'robot')}"
        else:
            content = f"Fetched public preview for {url}: OK"
    inner = f"""
    <div class="card">
      <form>
        <label>URL</label>
        <div class="row"><input name="url" value="{esc(url)}"><button>Fetch</button></div>
      </form>
    </div>
    <pre class="code">{esc(content)}</pre>
    """
    return service_shell(team, service_by_key("robot"), inner, query)  # type: ignore[arg-type]


def render_cookies(team: str, query: dict[str, list[str]], body: bytes, headers: dict[str, str]) -> tuple[int, str, str]:
    cookies = parse_cookies(headers.get("cookie"))
    role = cookies.get("role", "guest")
    session = cookies.get("session", "")
    if patched(team, "cookies"):
        expected = sign_token({"team": team, "role": "admin"})
        admin = hmac.compare_digest(session, expected)
    else:
        admin = role == "admin"
    result = f"Admin report: {flag_for(team, 'cookies')}" if admin else "Guest portal. Admin role required."
    inner = f"""
    <div class="card">
      <p class="compact">Current cookie role: {esc(role)}</p>
      <form method="get">
        <button formaction="/play/team/{esc(team)}/cookies/set-user">Set guest cookie</button>
      </form>
    </div>
    <pre class="code">{esc(result)}</pre>
    """
    return service_shell(team, service_by_key("cookies"), inner, query)  # type: ignore[arg-type]


def render_nosql(team: str, query: dict[str, list[str]], body: bytes, headers: dict[str, str]) -> tuple[int, str, str]:
    if body:
        try:
            payload = json.loads(body.decode())
        except json.JSONDecodeError:
            payload = {}
    else:
        payload = {"username": "guest", "password": "guest"}
    users = [
        {"username": "guest", "password": "guest", "role": "viewer", "secret": "public profile"},
        {"username": "operator", "password": "correct-horse", "role": "admin", "secret": flag_for(team, "nosql")},
    ]
    matched = None
    if patched(team, "nosql"):
        if isinstance(payload.get("username"), str) and isinstance(payload.get("password"), str):
            for user in users:
                if user["username"] == payload["username"] and user["password"] == payload["password"]:
                    matched = user
    else:
        for user in users:
            ok = True
            for key in ("username", "password"):
                wanted = payload.get(key)
                if isinstance(wanted, dict) and "$ne" in wanted:
                    ok = ok and user[key] != wanted["$ne"]
                else:
                    ok = ok and user[key] == wanted
            if ok:
                matched = user
                break
    result = matched or {"error": "no match"}
    sample = json.dumps(payload, indent=2)
    inner = f"""
    <div class="card">
      <form method="post">
        <label>JSON filter</label>
        <textarea name="raw" rows="7">{esc(sample)}</textarea>
        <button>Query</button>
      </form>
      <p class="compact">POST raw JSON directly or use this form.</p>
    </div>
    <pre class="code">{esc(json.dumps(result, indent=2))}</pre>
    """
    return service_shell(team, service_by_key("nosql"), inner, query)  # type: ignore[arg-type]


def render_backup(team: str, query: dict[str, list[str]], body: bytes, headers: dict[str, str]) -> tuple[int, str, str]:
    file_name = q_one(query, "file", "index.txt")
    predictable = f"{team}-backup-{current_round() % 1000:03d}.manifest"
    random_name = hashlib.sha256(f"{SECRET}:{team}:backup".encode()).hexdigest()[:12] + ".manifest"
    active_name = random_name if patched(team, "backup") else predictable
    files = {
        "index.txt": f"Latest backup object: {active_name if patched(team, 'backup') else team + '-backup-###.manifest'}",
        active_name: f"backup manifest\nteam={team}\nservice=backup\nflag={flag_for(team, 'backup')}",
    }
    content = files.get(file_name, "not found")
    inner = f"""
    <div class="card">
      <form>
        <label>Backup file</label>
        <div class="row"><input name="file" value="{esc(file_name)}"><button>Download</button></div>
      </form>
    </div>
    <pre class="code">{esc(content)}</pre>
    """
    return service_shell(team, service_by_key("backup"), inner, query)  # type: ignore[arg-type]


def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def render_crypto(team: str, query: dict[str, list[str]], body: bytes, headers: dict[str, str]) -> tuple[int, str, str]:
    key = hashlib.sha1(team.encode()).hexdigest()[:3].encode()
    flag = flag_for(team, "crypto").encode()
    ciphertext = base64.b64encode(xor_bytes(flag, key)).decode()
    answer = q_one(query, "answer")
    if patched(team, "crypto"):
        ciphertext = base64.b64encode(hmac.new(SECRET.encode(), flag, hashlib.sha256).digest()).decode()
        message = "Ciphertext is authenticated; plaintext oracle disabled."
    else:
        message = "Submit recovered plaintext to claim."
    if answer:
        message = "Correct." if answer == flag.decode() else "Incorrect plaintext."
        if answer == flag.decode():
            message += f" Claim accepted: {flag.decode()}"
    inner = f"""
    <div class="card">
      <p>Locker ciphertext:</p>
      <pre class="code">{esc(ciphertext)}</pre>
      <form>
        <label>Recovered plaintext</label>
        <div class="row"><input name="answer" value="{esc(answer)}"><button>Claim</button></div>
      </form>
    </div>
    <pre class="code">{esc(message)}</pre>
    """
    return service_shell(team, service_by_key("crypto"), inner, query)  # type: ignore[arg-type]


def render_redeem(team: str, query: dict[str, list[str]], body: bytes, headers: dict[str, str]) -> tuple[int, str, str]:
    code = q_one(query, "code", "WELCOME")
    count = int(get_state(team, "redeem", code, "0") or "0")
    if code != "WELCOME":
        message = "Unknown code."
    elif patched(team, "redeem"):
        if count >= 1:
            message = "Code already redeemed."
        else:
            put_state(team, "redeem", code, "1")
            message = "First redemption accepted. Bonus points credited."
    else:
        if count >= 1:
            message = f"Duplicate redemption accepted by stale cache: {flag_for(team, 'redeem')}"
        else:
            put_state(team, "redeem", code, "1")
            message = "First redemption accepted. Try again after the cache warms up."
    inner = f"""
    <div class="card">
      <form>
        <label>Redeem code</label>
        <div class="row"><input name="code" value="{esc(code)}"><button>Redeem</button></div>
      </form>
    </div>
    <pre class="code">{esc(message)}</pre>
    """
    return service_shell(team, service_by_key("redeem"), inner, query)  # type: ignore[arg-type]


SERVICE_RENDERERS: dict[str, Callable[[str, dict[str, list[str]], bytes, dict[str, str]], tuple[int, str, str]]] = {
    "memo": render_memo,
    "archive": render_archive,
    "token": render_token,
    "default": render_default,
    "shop": render_shop,
    "tickets": render_tickets,
    "render": render_badge,
    "robot": render_robot,
    "cookies": render_cookies,
    "nosql": render_nosql,
    "backup": render_backup,
    "crypto": render_crypto,
    "redeem": render_redeem,
}


def scoreboard() -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            "SELECT attacker, COALESCE(SUM(points), 0) AS attack FROM submissions GROUP BY attacker"
        ).fetchall()
        attack = {row["attacker"]: row["attack"] for row in rows}
        patched_rows = conn.execute(
            "SELECT team, COUNT(*) AS patched_count FROM patches WHERE enabled = 1 GROUP BY team"
        ).fetchall()
        defense = {row["team"]: row["patched_count"] * 2 for row in patched_rows}
        penalty_rows = conn.execute(
            "SELECT team, COALESCE(SUM(points), 0) AS penalty FROM penalties GROUP BY team"
        ).fetchall()
        penalties = {row["team"]: row["penalty"] for row in penalty_rows}
    data = []
    for team in TEAMS:
        attack_points = int(attack.get(team, 0))
        defense_points = int(defense.get(team, 0))
        penalty_points = int(penalties.get(team, 0))
        data.append(
            {
                "team": team,
                "attack": attack_points,
                "defense": defense_points,
                "penalty": penalty_points,
                "total": attack_points + defense_points - penalty_points,
            }
        )
    return sorted(data, key=lambda row: row["total"], reverse=True)


def patch_matrix() -> dict[str, dict[str, bool]]:
    with db() as conn:
        rows = conn.execute("SELECT team, service, enabled FROM patches").fetchall()
    result = {team: {service.key: False for service in SERVICES} for team in TEAMS}
    for row in rows:
        result[row["team"]][row["service"]] = bool(row["enabled"])
    return result


def home_page(team: str) -> tuple[int, str, str]:
    score_rows = "".join(
        f"<tr><td>{i + 1}</td><td>{esc(row['team'])}</td><td>{row['attack']}</td><td>{row['defense']}</td><td>{row['penalty']}</td><td><strong>{row['total']}</strong></td></tr>"
        for i, row in enumerate(scoreboard())
    )
    service_count = len(SERVICES)
    phase = current_phase()
    submit_note = "Live attack-defense is open." if phase == "live" else "Flag submission opens when the phase changes to live."
    body = f"""
    <div class="hero">
      <section class="panel">
        <h1>本地 Attack-Defense 靶場</h1>
        <p>這個靶場模擬 FindTheFlag / Attack with Defense：攻擊別隊服務取得 flag，提交得分；同時替自己的服務開啟 patch，取得防守分並阻擋同類攻擊。</p>
        <div class="meta">
          <span class="pill">teams: {len(TEAMS)}</span>
          <span class="pill">services: {service_count}</span>
          <span class="pill {'ok' if phase == 'live' else 'warn'}">phase: {esc(phase)}</span>
          <span class="pill">round: <span id="round">{current_round()}</span></span>
          <span class="pill warn">next flags: <span id="remain">{seconds_remaining()}</span>s</span>
        </div>
        <div class="row">
          <a class="button" href="/play/targets">Open targets</a>
          <a class="button secondary" href="/play/defense">Harden own services</a>
        </div>
      </section>
      <section class="panel">
        <h2>Team</h2>
        <div class="notice">Logged in as <strong>{esc(team)}</strong>. <a href="/play/logout">Logout</a></div>
        <h2>Submit flag</h2>
        <p class="compact">{esc(submit_note)}</p>
        <form id="submit-form">
          <label>Flag</label><input name="flag" placeholder="FTF{{victim_service_round_hash}}">
          <button>Submit</button>
        </form>
        <div id="submit-result" class="result"></div>
      </section>
    </div>
    <h2>Scoreboard</h2>
    <table><thead><tr><th>#</th><th>Team</th><th>Attack</th><th>Defense</th><th>Penalty</th><th>Total</th></tr></thead><tbody>{score_rows}</tbody></table>
    <h2>Services</h2>
    <div class="service-grid">
      {''.join(service_card(service) for service in SERVICES)}
    </div>
    <script>
      async function tick() {{
        const res = await fetch('/api/state');
        const data = await res.json();
        document.querySelector('#round').textContent = data.round;
        document.querySelector('#remain').textContent = data.seconds_remaining;
      }}
      setInterval(tick, 1000);
      document.querySelector('#submit-form').addEventListener('submit', async (event) => {{
        event.preventDefault();
        const data = Object.fromEntries(new FormData(event.target).entries());
        const res = await fetch('/api/submit', {{method:'POST', headers:{{'Content-Type':'application/json'}}, body:JSON.stringify(data)}});
        const body = await res.json();
        document.querySelector('#submit-result').textContent = body.message;
      }});
    </script>
    """
    return page("Scoreboard", body)


def service_card(service: Service) -> str:
    return f"""
    <article class="card service-card">
      <div>
        <h3>{esc(service.name)}</h3>
        <p class="compact">{esc(service.objective)}</p>
        <div class="meta"><span class="pill">{esc(service.category)}</span><span class="pill">{esc(service.difficulty)}</span></div>
      </div>
      <div class="row">
        <a class="button secondary" href="/play/team/alpha/{esc(service.key)}">Alpha target</a>
        <a class="button secondary" href="/play/targets#{esc(service.key)}">All teams</a>
      </div>
    </article>
    """


def targets_page(team: str, phase: str) -> tuple[int, str, str]:
    sections = []
    visible_teams = [team] if phase == "hardening" else TEAMS
    for service in SERVICES:
        links = "".join(
            f'<a class="button secondary" href="/play/team/{esc(target_team)}/{esc(service.key)}">{esc(target_team)}</a>'
            for target_team in visible_teams
        )
        sections.append(
            f"""
            <article class="card service-card" id="{esc(service.key)}">
              <div>
                <h3>{esc(service.name)}</h3>
                <p class="compact">{esc(service.objective)}</p>
                <div class="meta"><span class="pill">{esc(service.category)}</span><span class="pill">{esc(service.difficulty)}</span></div>
              </div>
              <div class="row">{links}</div>
            </article>
            """
        )
    body = f"""
    <h1>Targets</h1>
    <p>{'Hardening phase: 目前網路隔離，只能檢查與修補自己隊伍服務。' if phase == 'hardening' else 'Live phase: 互聯已開放，可攻擊其他隊伍服務，同時繼續防守自己的服務。'}</p>
    <div class="notice">管理頁不是攻擊目標，碰觸管理頁會被扣分。</div>
    <div class="service-grid">{''.join(sections)}</div>
    """
    return page("Targets", body)


def defense_page() -> tuple[int, str, str]:
    matrix = patch_matrix()
    rows = []
    for team in TEAMS:
        cells = []
        for service in SERVICES:
            enabled = matrix[team][service.key]
            cells.append(
                f"""
                <td>
                  <button class="{'secondary' if enabled else 'danger'}" data-team="{esc(team)}" data-service="{esc(service.key)}" data-enabled="{str(enabled).lower()}">
                    {'patched' if enabled else 'patch'}
                  </button>
                  <div class="compact">{esc(service.patch_name)}</div>
                </td>
                """
            )
        rows.append(f"<tr><th>{esc(team)}</th>{''.join(cells)}</tr>")
    header = "".join(f"<th>{esc(service.name)}</th>" for service in SERVICES)
    body = f"""
    <h1>Defense</h1>
    <p>Patch 開關模擬各隊對服務的修補。開啟後該服務的對應漏洞會被擋下，並提供少量防守分。</p>
    <div style="overflow:auto">
      <table><thead><tr><th>Team</th>{header}</tr></thead><tbody>{''.join(rows)}</tbody></table>
    </div>
    <div id="defense-result" class="result"></div>
    <script>
      document.querySelectorAll('button[data-team]').forEach((button) => {{
        button.addEventListener('click', async () => {{
          const enabled = button.dataset.enabled !== 'true';
          const res = await fetch('/admin/api/patch', {{
            method:'POST',
            headers:{{'Content-Type':'application/json'}},
            body:JSON.stringify({{team:button.dataset.team, service:button.dataset.service, enabled}})
          }});
          const data = await res.json();
          document.querySelector('#defense-result').textContent = data.message;
          setTimeout(() => location.reload(), 250);
        }});
      }});
    </script>
    """
    return page("Defense", body, area="admin")


def team_defense_page(team: str) -> tuple[int, str, str]:
    matrix = patch_matrix()
    phase = current_phase()
    cards = []
    for service in SERVICES:
        enabled = matrix[team][service.key]
        cards.append(
            f"""
            <article class="card service-card">
              <div>
                <h3>{esc(service.name)}</h3>
                <p class="compact">{esc(service.patch_name)}</p>
                <div class="meta">
                  <span class="pill">{esc(service.category)}</span>
                  <span class="pill {'ok' if enabled else 'warn'}">{'patched' if enabled else 'vulnerable'}</span>
                </div>
              </div>
              <button class="{'secondary' if enabled else 'danger'}" data-service="{esc(service.key)}" data-enabled="{str(enabled).lower()}">
                {'disable patch' if enabled else 'apply patch'}
              </button>
            </article>
            """
        )
    body = f"""
    <h1>Own Defense</h1>
    <div class="notice">Logged in as <strong>{esc(team)}</strong>. Phase: <strong>{esc(phase)}</strong>. 你只能修補自己隊伍的服務。</div>
    <div class="service-grid">{''.join(cards)}</div>
    <div id="defense-result" class="result"></div>
    <script>
      document.querySelectorAll('button[data-service]').forEach((button) => {{
        button.addEventListener('click', async () => {{
          const enabled = button.dataset.enabled !== 'true';
          const res = await fetch('/api/team/patch', {{
            method:'POST',
            headers:{{'Content-Type':'application/json'}},
            body:JSON.stringify({{service:button.dataset.service, enabled}})
          }});
          const data = await res.json();
          document.querySelector('#defense-result').textContent = data.message;
          if (data.ok) setTimeout(() => location.reload(), 250);
        }});
      }});
    </script>
    """
    return page("Own Defense", body)


def operator_page() -> tuple[int, str, str]:
    matrix = patch_matrix()
    rows = []
    for team in TEAMS:
        for service in SERVICES:
            rows.append(
                f"<tr><td>{esc(team)}</td><td>{esc(service.name)}</td><td>{flag_for(team, service.key)}</td><td>{'patched' if matrix[team][service.key] else 'vulnerable'}</td></tr>"
            )
    body = f"""
    <h1>Operator</h1>
    <div class="notice alert">這頁是靶場主持人用的答案表，正式練習時不要給參賽者看。</div>
    <h2>Current Round Flags</h2>
    <table><thead><tr><th>Team</th><th>Service</th><th>Flag</th><th>State</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
    """
    return page("Operator", body, area="admin")


def admin_dashboard_page() -> tuple[int, str, str]:
    phase = current_phase()
    scoring = scoring_config()
    score_rows = "".join(
        f"<tr><td>{esc(row['team'])}</td><td>{row['attack']}</td><td>{row['defense']}</td><td>{row['penalty']}</td><td><strong>{row['total']}</strong></td></tr>"
        for row in scoreboard()
    )
    with db() as conn:
        penalty_rows = conn.execute(
            "SELECT team, reason, path, points, created_at FROM penalties ORDER BY created_at DESC LIMIT 30"
        ).fetchall()
        submission_rows = conn.execute(
            "SELECT attacker, victim, service, round, flag, points, created_at FROM submissions ORDER BY created_at DESC LIMIT 30"
        ).fetchall()
    penalties_html = "".join(
        f"<tr><td>{esc(row['team'])}</td><td>{esc(row['reason'])}</td><td>{esc(row['path'])}</td><td>-{row['points']}</td><td>{time.strftime('%H:%M:%S', time.localtime(row['created_at']))}</td></tr>"
        for row in penalty_rows
    ) or "<tr><td colspan='5'>No penalties.</td></tr>"
    submissions_html = "".join(
        f"<tr><td>{esc(row['attacker'])}</td><td>{esc(row['victim'])}</td><td>{esc(row['service'])}</td><td>{row['round']}</td><td>{esc(row['flag'])}</td><td>+{row['points']}</td><td>{time.strftime('%H:%M:%S', time.localtime(row['created_at']))}</td></tr>"
        for row in submission_rows
    ) or "<tr><td colspan='7'>No accepted submissions.</td></tr>"
    credentials_html = "".join(
        f"<tr><td>{esc(team)}</td><td><code>{esc(password)}</code></td></tr>"
        for team, password in TEAM_PASSWORDS.items()
    )
    body = f"""
    <h1>Admin Dashboard</h1>
    <div class="notice">管理端不包含刻意漏洞。未登入碰觸管理 URL 會記錄為攻擊管理頁，能辨識隊伍時會扣 {scoring['admin_access_penalty']} 分。目前 phase: <strong>{esc(phase)}</strong></div>
    <div class="card">
      <h3>Phase Control</h3>
      <form method="post" action="/admin/phase" class="row">
        <button name="phase" value="hardening" class="secondary">Hardening</button>
        <button name="phase" value="live">Live</button>
        <button name="phase" value="ended" class="danger">Ended</button>
      </form>
      <p class="compact">Hardening: 網路隔離，只能看/修自己的服務。Live: 開放跨隊攻擊與提交。Ended: 關閉提交與修補。</p>
    </div>
    <div class="grid">
      <article class="card"><h3>Defense control</h3><p>替隊伍服務開關 patch。</p><a class="button" href="/admin/defense">Open defense</a></article>
      <article class="card"><h3>Operator flags</h3><p>主持人答案表，勿投放給參賽者。</p><a class="button" href="/admin/operator">Open operator</a></article>
      <article class="card"><h3>Scoring</h3><p>Attack +{scoring['attack_flag_points']}, late +{scoring['patched_flag_points']}, admin -{scoring['admin_access_penalty']}.</p><a class="button" href="/admin/scoring">Adjust scoring</a></article>
      <article class="card"><h3>Team arena</h3><p>參賽者入口檢查。</p><a class="button secondary" href="/play">Open team view</a></article>
    </div>
    <h2>Scoreboard</h2>
    <table><thead><tr><th>Team</th><th>Attack</th><th>Defense</th><th>Penalty</th><th>Total</th></tr></thead><tbody>{score_rows}</tbody></table>
    <h2>Team Credentials</h2>
    <table><thead><tr><th>Team</th><th>Password</th></tr></thead><tbody>{credentials_html}</tbody></table>
    <h2>Accepted Submissions</h2>
    <table><thead><tr><th>Attacker</th><th>Victim</th><th>Service</th><th>Round</th><th>Flag</th><th>Points</th><th>Time</th></tr></thead><tbody>{submissions_html}</tbody></table>
    <h2>Penalty Log</h2>
    <table><thead><tr><th>Team</th><th>Reason</th><th>Path</th><th>Points</th><th>Time</th></tr></thead><tbody>{penalties_html}</tbody></table>
    """
    return page("Admin", body, area="admin")


def admin_login_page(message: str = "") -> tuple[int, str, str]:
    body = f"""
    <h1>Admin Login</h1>
    <div class="notice">主持人管理區。參賽者不應嘗試登入或掃描管理路徑。</div>
    <div class="card">
      <form method="post" action="/admin/login">
        <label>Admin password</label>
        <input type="password" name="password" autocomplete="current-password">
        <button>Login</button>
      </form>
      {'<p class="result">' + esc(message) + '</p>' if message else ''}
    </div>
    """
    return page("Admin Login", body, area="admin")


def admin_scoring_page(message: str = "") -> tuple[int, str, str]:
    config = scoring_config()
    rows = [
        ("attack_flag_points", "Valid stolen flag"),
        ("patched_flag_points", "Flag submitted after target patch"),
        ("availability_points", "Service alive per checker round"),
        ("integrity_points", "Flag/function integrity per checker round"),
        ("admin_access_penalty", "Unauthorized admin page access penalty"),
        ("infra_attack_penalty", "Infrastructure attack penalty"),
        ("checker_timeout_seconds", "Checker timeout seconds"),
    ]
    inputs = "".join(
        f"""
        <label>{esc(label)}</label>
        <input type="number" min="0" step="1" name="{esc(key)}" value="{config[key]}">
        """
        for key, label in rows
    )
    body = f"""
    <h1>Scoring</h1>
    <div class="notice">比賽前可在這裡做最後調整。變更會立即影響後續提交與扣分；已經記錄的提交不會 retroactively 重算。</div>
    <div class="card">
      <form method="post" action="/admin/scoring">
        {inputs}
        <button>Save scoring</button>
      </form>
      {'<p class="result">' + esc(message) + '</p>' if message else ''}
    </div>
    <h2>Recommended Baseline</h2>
    <pre class="code">Attack flag: 10
Patched/late flag: 4
Availability per service/round: 2
Integrity per service/round: 2
Admin page access: -15
Infrastructure attack: -50
Checker timeout: 3 seconds</pre>
    """
    return page("Scoring", body, area="admin")


def team_login_page(message: str = "") -> tuple[int, str, str]:
    body = f"""
    <h1>Team Login</h1>
    <div class="notice">請使用主持人發給你的隊伍帳號密碼登入。登入後才能開始提交 flags。</div>
    <div class="card">
      <form method="post" action="/play/login">
        <label>Team</label>
        <select name="team">{team_options()}</select>
        <label>Password</label>
        <input type="password" name="password" autocomplete="current-password">
        <button>Login</button>
      </form>
      {'<p class="result">' + esc(message) + '</p>' if message else ''}
    </div>
    """
    return page("Team Login", body)


def api_state() -> dict[str, Any]:
    return {
        "phase": current_phase(),
        "round": current_round(),
        "seconds_remaining": seconds_remaining(),
        "teams": TEAMS,
        "services": [service.__dict__ for service in SERVICES],
        "scoreboard": scoreboard(),
        "patches": patch_matrix(),
    }


def submit_flag(attacker: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    flag = str(payload.get("flag", "")).strip()
    if attacker not in TEAMS:
        return 400, {"ok": False, "message": "Unknown attacker team."}
    match = re.fullmatch(r"FTF\{([a-z]+)_([a-z]+)_(\d+)_([0-9a-f]{18})\}", flag)
    if not match:
        return 400, {"ok": False, "message": "Flag format is invalid."}
    victim, service, round_raw, _digest = match.groups()
    round_no = int(round_raw)
    if victim not in TEAMS or not service_by_key(service):
        return 400, {"ok": False, "message": "Unknown victim or service."}
    if victim == attacker:
        return 400, {"ok": False, "message": "Self-submitted flags do not score."}
    valid = any(flag == flag_for(victim, service, r) for r in range(current_round() - 2, current_round() + 1))
    if not valid:
        return 400, {"ok": False, "message": "Flag is expired or incorrect."}
    scoring = scoring_config()
    if patched(victim, service):
        points = scoring["patched_flag_points"]
        note = "accepted for reduced points because target patched after capture"
    else:
        points = scoring["attack_flag_points"]
        note = "accepted"
    try:
        with db() as conn:
            conn.execute(
                "INSERT INTO submissions(attacker, victim, service, round, flag, points, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (attacker, victim, service, round_no, flag, points, time.time()),
            )
    except sqlite3.IntegrityError:
        return 409, {"ok": False, "message": "Duplicate flag for this attacker/victim/service/round."}
    return 200, {"ok": True, "message": f"{note}: +{points} points for {attacker}."}


def parse_form_or_json(headers: dict[str, str], body: bytes) -> dict[str, Any]:
    content_type = headers.get("content-type", "")
    if "application/json" in content_type:
        return json.loads(body.decode() or "{}")
    parsed = urllib.parse.parse_qs(body.decode())
    if "raw" in parsed:
        raw = parsed["raw"][0]
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"raw": raw}
    return {key: values[0] if values else "" for key, values in parsed.items()}


class ArenaHandler(BaseHTTPRequestHandler):
    server_version = "FindTheFlagAD/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[{time.strftime('%H:%M:%S')}] {self.address_string()} {fmt % args}")

    def read_body(self) -> bytes:
        length = int(self.headers.get("content-length", "0") or "0")
        return self.rfile.read(length) if length else b""

    def header_map(self) -> dict[str, str]:
        return {key.lower(): value for key, value in self.headers.items()}

    def send_text(self, status: int, content_type: str, text: str, extra_headers: dict[str, str] | None = None) -> None:
        raw = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def send_json(self, status: int, data: dict[str, Any]) -> None:
        self.send_text(status, "application/json; charset=utf-8", json.dumps(data, ensure_ascii=False))

    def redirect(self, location: str, extra_headers: dict[str, str] | list[tuple[str, str]] | None = None) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        if extra_headers:
            items = extra_headers.items() if isinstance(extra_headers, dict) else extra_headers
            for key, value in items:
                self.send_header(key, value)
        self.end_headers()

    def parse_team_service(self, path: str) -> tuple[str, str, list[str]] | None:
        parts = path.strip("/").split("/")
        if len(parts) >= 3 and parts[0] == "team":
            return parts[1], parts[2], parts[3:]
        if len(parts) >= 4 and parts[0] == "play" and parts[1] == "team":
            return parts[2], parts[3], parts[4:]
        return None

    def require_admin(self, path: str, query: dict[str, list[str]]) -> bool:
        if is_admin(self.header_map()):
            return True
        team = team_from_request(query, self.header_map())
        self.respond(admin_forbidden_page(team, path))
        return False

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        path = parsed.path.rstrip("/") or "/"
        if path == "/":
            return self.redirect("/play")
        if path == "/play/login":
            return self.respond(team_login_page())
        if path == "/play/logout":
            return self.redirect(
                "/play/login",
                [
                    ("Set-Cookie", "team_session=; Path=/; Max-Age=0"),
                    ("Set-Cookie", "team=; Path=/; Max-Age=0"),
                ],
            )
        if path == "/play":
            team = current_team(self.header_map())
            if not team:
                return self.redirect("/play/login")
            return self.respond(home_page(team))
        if path == "/play/defense":
            team = current_team(self.header_map())
            if not team:
                return self.redirect("/play/login")
            return self.respond(team_defense_page(team))
        if path == "/targets":
            return self.redirect("/play/targets")
        if path == "/play/targets":
            team = current_team(self.header_map())
            if not team:
                return self.redirect("/play/login")
            return self.respond(targets_page(team, current_phase()))
        if path in {"/defense", "/admin/defense"}:
            if path == "/defense":
                return self.redirect("/admin/defense")
            if not self.require_admin(path, query):
                return
            return self.respond(defense_page())
        if path in {"/operator", "/admin/operator"}:
            if path == "/operator":
                return self.redirect("/admin/operator")
            if not self.require_admin(path, query):
                return
            return self.respond(operator_page())
        if path == "/admin/login":
            return self.respond(admin_login_page())
        if path == "/admin/scoring":
            if not self.require_admin(path, query):
                return
            return self.respond(admin_scoring_page())
        if path == "/admin":
            if not self.require_admin(path, query):
                return
            return self.respond(admin_dashboard_page())
        if path == "/api/state":
            return self.send_json(200, api_state())
        if path.startswith("/team/"):
            return self.redirect(f"/play{path}")
        parsed_team = self.parse_team_service(path)
        if parsed_team:
            logged_in_team = current_team(self.header_map())
            if path.startswith("/play/team/") and not logged_in_team:
                return self.redirect("/play/login")
            team, service_key, extra = parsed_team
            if path.startswith("/play/team/") and current_phase() == "hardening" and team != logged_in_team:
                return self.respond(page("Network isolated", "<h1>Network isolated</h1><div class='notice'>Hardening phase 尚未開放跨隊互聯，只能檢查自己的服務。</div>", HTTPStatus.FORBIDDEN))
            if path.startswith("/play/team/") and current_phase() == "ended":
                return self.respond(page("Game ended", "<h1>Game ended</h1><div class='notice'>比賽已結束，隊伍靶標已關閉。</div>", HTTPStatus.FORBIDDEN))
            if team in TEAMS and service_key == "cookies" and len(extra) == 1 and extra[0] == "set-user":
                return self.redirect(f"/play/team/{team}/cookies", {"Set-Cookie": "role=guest; Path=/"})
            renderer = SERVICE_RENDERERS.get(service_key)
            if team in TEAMS and renderer:
                return self.respond(renderer(team, query, b"", self.header_map()))
        self.respond(page("Not found", "<h1>Not found</h1>", HTTPStatus.NOT_FOUND))

    def do_HEAD(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        path = parsed.path.rstrip("/") or "/"
        if path == "/defense":
            return self.redirect("/admin/defense")
        if path == "/operator":
            return self.redirect("/admin/operator")
        admin_paths = {"/admin", "/admin/scoring", "/admin/defense", "/admin/operator"}
        if path in admin_paths and not is_admin(self.header_map()):
            response = admin_forbidden_page(team_from_request(query, self.header_map()), path)
        elif path in {"/", "/play"}:
            team = current_team(self.header_map())
            response = home_page(team) if team else team_login_page()
        elif path in {"/targets", "/play/targets"}:
            team = current_team(self.header_map())
            response = targets_page(team, current_phase()) if team else team_login_page()
        elif path == "/play/defense":
            team = current_team(self.header_map())
            response = team_defense_page(team) if team else team_login_page()
        elif path == "/admin":
            response = admin_dashboard_page()
        elif path == "/admin/login":
            response = admin_login_page()
        elif path == "/admin/scoring":
            response = admin_scoring_page()
        elif path == "/play/login":
            response = team_login_page()
        elif path in {"/defense", "/admin/defense"}:
            response = defense_page()
        elif path in {"/operator", "/admin/operator"}:
            response = operator_page()
        else:
            response = page("Not found", "<h1>Not found</h1>", HTTPStatus.NOT_FOUND)
        status, content_type, text = response
        raw = text.encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        body = self.read_body()
        headers = self.header_map()
        if path == "/play/login":
            payload = parse_form_or_json(headers, body)
            team = str(payload.get("team", ""))
            password = str(payload.get("password", ""))
            if team in TEAMS and hmac.compare_digest(password, TEAM_PASSWORDS[team]):
                return self.redirect(
                    "/play",
                    [
                        ("Set-Cookie", f"team_session={team_session_cookie(team)}; Path=/; HttpOnly; SameSite=Lax"),
                        ("Set-Cookie", f"team={team}; Path=/; SameSite=Lax"),
                    ],
                )
            return self.respond(team_login_page("Team or password incorrect."))
        if path == "/admin/login":
            payload = parse_form_or_json(headers, body)
            password = str(payload.get("password", ""))
            if hmac.compare_digest(password, ADMIN_PASSWORD):
                return self.redirect("/admin", {"Set-Cookie": f"admin_session={admin_session_cookie()}; Path=/; HttpOnly; SameSite=Lax"})
            return self.respond(admin_login_page("Password incorrect."))
        if path == "/admin/phase":
            if not self.require_admin(path, urllib.parse.parse_qs(parsed.query)):
                return
            payload = parse_form_or_json(headers, body)
            phase = str(payload.get("phase", ""))
            if phase not in PHASES:
                return self.respond(page("Bad phase", "<h1>Unknown phase</h1>", HTTPStatus.BAD_REQUEST, area="admin"))
            set_phase(phase)
            return self.redirect("/admin")
        if path == "/admin/scoring":
            if not self.require_admin(path, urllib.parse.parse_qs(parsed.query)):
                return
            payload = parse_form_or_json(headers, body)
            set_scoring_config(payload)
            return self.respond(admin_scoring_page("Scoring saved."))
        if path == "/api/submit":
            attacker = current_team(headers)
            if not attacker:
                return self.send_json(401, {"ok": False, "message": "Login required before submitting flags."})
            if current_phase() != "live":
                return self.send_json(403, {"ok": False, "message": "Flag submission is only open during the live phase."})
            try:
                payload = parse_form_or_json(headers, body)
            except Exception as exc:
                return self.send_json(400, {"ok": False, "message": f"Bad request: {exc}"})
            status, response = submit_flag(attacker, payload)
            return self.send_json(status, response)
        if path == "/api/team/patch":
            team = current_team(headers)
            if not team:
                return self.send_json(401, {"ok": False, "message": "Login required before patching."})
            if current_phase() == "ended":
                return self.send_json(403, {"ok": False, "message": "Patching is closed after the game ends."})
            try:
                payload = parse_form_or_json(headers, body)
            except Exception as exc:
                return self.send_json(400, {"ok": False, "message": f"Bad request: {exc}"})
            service = str(payload.get("service", ""))
            if not service_by_key(service):
                return self.send_json(400, {"ok": False, "message": "Unknown service."})
            enabled = bool(payload.get("enabled"))
            set_patch(team, service, enabled)
            return self.send_json(200, {"ok": True, "message": f"{team}/{service} is now {'patched' if enabled else 'vulnerable'}."})
        if path in {"/api/patch", "/admin/api/patch"}:
            if path == "/api/patch":
                return self.send_json(403, {"ok": False, "message": "Patch API moved to /admin/api/patch."})
            if not self.require_admin(path, urllib.parse.parse_qs(parsed.query)):
                return
            try:
                payload = parse_form_or_json(headers, body)
            except Exception as exc:
                return self.send_json(400, {"ok": False, "message": f"Bad request: {exc}"})
            team = str(payload.get("team", ""))
            service = str(payload.get("service", ""))
            if team not in TEAMS or not service_by_key(service):
                return self.send_json(400, {"ok": False, "message": "Unknown team or service."})
            enabled = bool(payload.get("enabled"))
            set_patch(team, service, enabled)
            return self.send_json(200, {"ok": True, "message": f"{team}/{service} is now {'patched' if enabled else 'vulnerable'}."})
        parsed_team = self.parse_team_service(path)
        if parsed_team:
            team, service_key, _extra = parsed_team
            renderer = SERVICE_RENDERERS.get(service_key)
            if team in TEAMS and renderer:
                try:
                    payload = parse_form_or_json(headers, body)
                except Exception:
                    payload = {}
                raw_for_renderer = json.dumps(payload).encode()
                return self.respond(renderer(team, {}, raw_for_renderer, headers))
        self.respond(page("Not found", "<h1>Not found</h1>", HTTPStatus.NOT_FOUND))

    def respond(self, response: tuple[int, str, str]) -> None:
        status, content_type, text = response
        self.send_text(int(status), content_type, text)


def main() -> None:
    init_db()
    host = os.environ.get("FTF_HOST", "127.0.0.1")
    port = int(os.environ.get("FTF_PORT", "8088"))
    httpd = ThreadingHTTPServer((host, port), ArenaHandler)
    print(f"FindTheFlag AD arena running at http://{host}:{port}")
    print(f"Team arena: http://{host}:{port}/play")
    print(f"Admin login: http://{host}:{port}/admin/login")
    print(f"Admin password file: {ADMIN_PASSWORD_PATH}")
    print(f"Team password file: {TEAM_PASSWORDS_PATH}")
    print("Local training target only. Do not expose it publicly.")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
