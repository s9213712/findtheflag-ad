#!/usr/bin/env python3
"""
Distributed FindTheFlag admin server.

This server is the central authority for a distributed Attack-Defense event:
team heartbeat, flag reporting, flag submission, scoring, and admin views.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import re
import shutil
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "distributed_admin.sqlite3"
ADMIN_PASSWORD_PATH = DATA_DIR / "admin_password.txt"
TEAMS_PATH = BASE_DIR / "configs" / "teams.json"

ROUND_SECONDS = int(os.environ.get("FTF_ROUND_SECONDS", "300"))
HEARTBEAT_TIMEOUT_SECONDS = int(os.environ.get("FTF_HEARTBEAT_TIMEOUT_SECONDS", "90"))
CHECKER_INTERVAL_SECONDS = int(os.environ.get("FTF_CHECKER_INTERVAL_SECONDS", "30"))
DB_LOCK = threading.RLock()
PHASES = {"setup", "hardening", "live", "ended"}
SERVICE_CATALOG = {
    "default": {
        "name": "Default Admin",
        "category": "Auth / Default credentials",
        "description": "Vendor admin console starts with admin/admin.",
    },
    "token": {
        "name": "Token Forge",
        "category": "Auth / Weak token",
        "description": "Unsigned base64 role token can be forged.",
    },
    "shop": {
        "name": "Coupon Shop",
        "category": "Logic",
        "description": "Coupon and quantity logic can underflow restricted item price.",
    },
    "memo": {
        "name": "Memo Search",
        "category": "Data / SQL injection",
        "description": "Search query is interpolated into a report database query.",
    },
    "archive": {
        "name": "Archive Viewer",
        "category": "Files / Canonicalization",
        "description": "Document lookup decodes paths after a shallow traversal filter.",
    },
    "vault": {
        "name": "Recovery Vault",
        "category": "Auth / Predictable recovery",
        "description": "Admin recovery code is derived from public match state.",
    },
    "cipher": {
        "name": "Cipher Session",
        "category": "Crypto / Malleability",
        "description": "Encrypted session data is trusted without authentication.",
    },
    "proxy": {
        "name": "Internal Proxy",
        "category": "SSRF / Parser confusion",
        "description": "Proxy allowlist validates raw URL text differently from the backend resolver.",
    },
    "waf": {
        "name": "WAF Gateway",
        "category": "HTTP / Parser discrepancy",
        "description": "Gateway and application disagree on duplicate parameter precedence.",
    },
    "supply": {
        "name": "Supply Update",
        "category": "Supply chain / Manifest validation",
        "description": "Update manifest integrity check omits trust-critical install fields.",
    },
    "edge": {
        "name": "Edge Session",
        "category": "Memory / Session disclosure",
        "description": "Diagnostic read length can expose adjacent session cache data.",
    },
    "media": {
        "name": "Media Packager",
        "category": "Files / URL parsing",
        "description": "Poster asset validation and packager path resolution disagree about fragments.",
    },
    "agent": {
        "name": "Agent Tools",
        "category": "AI agent / Tool boundary",
        "description": "Tool guard validates only the first action while dispatcher executes the full chain.",
    },
    "saml": {
        "name": "SAML Gateway",
        "category": "Auth / Signature wrapping",
        "description": "Verifier signs one role claim but authorizer consumes another.",
    },
    "hook": {
        "name": "OAuth Relay",
        "category": "Auth / Redirect parsing",
        "description": "Redirect prefix allowlist runs before URL authority parsing.",
    },
    "ledger": {
        "name": "Points Ledger",
        "category": "Business logic / Incomplete signing",
        "description": "Transaction signature omits amount and recipient.",
    },
}
DEFAULT_SCORING = {
    "attack_flag_points": 10,
    "availability_points": 2,
    "integrity_points": 2,
    "admin_access_penalty": 15,
    "infra_attack_penalty": 50,
    "checker_timeout_seconds": int(os.environ.get("FTF_CHECKER_TIMEOUT_SECONDS", "3")),
}


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def now() -> float:
    return time.time()


def current_round() -> int:
    return int(now() // ROUND_SECONDS)


def round_remaining() -> int:
    return ROUND_SECONDS - int(now() % ROUND_SECONDS)


def ensure_secret_file(path: Path, nbytes: int = 18) -> str:
    DATA_DIR.mkdir(exist_ok=True)
    if not path.exists():
        path.write_text(base64.urlsafe_b64encode(os.urandom(nbytes)).decode().rstrip("="), encoding="utf-8")
    return path.read_text(encoding="utf-8").strip()


ADMIN_PASSWORD = ensure_secret_file(ADMIN_PASSWORD_PATH, 12)


def load_teams() -> dict[str, dict[str, str]]:
    if not TEAMS_PATH.exists():
        TEAMS_PATH.parent.mkdir(exist_ok=True)
        TEAMS_PATH.write_text("{}", encoding="utf-8")
    data = json.loads(TEAMS_PATH.read_text(encoding="utf-8"))
    return {str(team): {"secret": str(cfg["secret"]), "public_base_url": str(cfg.get("public_base_url", ""))} for team, cfg in data.items()}


def teams() -> dict[str, dict[str, str]]:
    return load_teams()


def save_teams(data: dict[str, dict[str, str]]) -> None:
    with DB_LOCK:
        TEAMS_PATH.parent.mkdir(exist_ok=True)
        ordered = {team: data[team] for team in sorted(data)}
        TEAMS_PATH.write_text(json.dumps(ordered, indent=2), encoding="utf-8")


def generate_secret(nbytes: int = 24) -> str:
    return base64.urlsafe_b64encode(os.urandom(nbytes)).decode().rstrip("=")


def valid_team_id(team: str) -> bool:
    return bool(re.fullmatch(r"[a-z0-9-]{2,32}", team))


def listen_endpoint(public_base_url: str, fallback_port: int) -> tuple[str, int]:
    parsed = urllib.parse.urlparse(public_base_url)
    if parsed.hostname and parsed.port:
        return parsed.hostname, parsed.port
    return "127.0.0.1", fallback_port


def selected_services() -> list[str]:
    raw = get_setting("selected_services", "default")
    services = [service for service in raw.split(",") if service in SERVICE_CATALOG]
    return services or ["default"]


def set_selected_services(services: list[str]) -> None:
    valid = [service for service in services if service in SERVICE_CATALOG]
    if not valid:
        valid = ["default"]
    set_setting("selected_services", ",".join(dict.fromkeys(valid)))


def generate_team_configs() -> None:
    config_dir = BASE_DIR / "configs"
    config_dir.mkdir(exist_ok=True)
    for stale in config_dir.glob("*.team_config.json"):
        stale.unlink()
    for index, (team, cfg) in enumerate(teams().items()):
        fallback_port = 9100 + index
        public_base_url = cfg.get("public_base_url") or f"http://127.0.0.1:{fallback_port}"
        host, port = listen_endpoint(public_base_url, fallback_port)
        data = {
            "team_id": team,
            "team_secret": cfg["secret"],
            "admin_url": f"http://{os.environ.get('FTF_ADMIN_HOST', '127.0.0.1')}:{os.environ.get('FTF_ADMIN_PORT', '8088')}",
            "public_base_url": public_base_url,
            "host": host,
            "port": port,
            "reporting_enabled": True,
            "round_seconds": ROUND_SECONDS,
            "heartbeat_interval_seconds": int(os.environ.get("FTF_TEAM_HEARTBEAT_INTERVAL_SECONDS", "30")),
            "admin_timeout_seconds": int(os.environ.get("FTF_TEAM_ADMIN_TIMEOUT_SECONDS", "3")),
            "services": selected_services(),
        }
        (config_dir / f"{team}.team_config.json").write_text(json.dumps(data, indent=2), encoding="utf-8")


def team_starter_html(team: str, cfg: dict[str, Any]) -> str:
    public_url = str(cfg["public_base_url"])
    admin_url = str(cfg["admin_url"])
    return f"""<!doctype html>
<html lang="zh-Hant">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FindTheFlag Team {esc(team)}</title>
  <style>
    body {{ margin:0; font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; background:#f5f7fa; color:#17212b; }}
    header {{ background:#102631; color:white; padding:18px 22px; border-bottom:4px solid #d8a331; }}
    main {{ max-width:900px; margin:0 auto; padding:22px; }}
    .card {{ background:white; border:1px solid #d9e0e8; border-radius:8px; padding:16px; margin:14px 0; }}
    code,pre {{ font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }}
    pre {{ background:#101827; color:#d8f3ff; padding:12px; border-radius:6px; overflow:auto; }}
    a.button {{ display:inline-flex; background:#176b87; color:white; text-decoration:none; border-radius:6px; padding:9px 12px; font-weight:700; }}
  </style>
</head>
<body>
  <header><strong>FindTheFlag Team Package: {esc(team)}</strong></header>
  <main>
    <div class="card">
      <h1>{esc(team)} Initialization</h1>
      <p>This page is the local handoff page for the hardening window.</p>
      <p><a class="button" href="{esc(public_url)}">Open Team Server</a></p>
    </div>
    <div class="card">
      <h2>Start Server</h2>
      <pre>FTF_TEAM_CONFIG=team_config.json python3 team_server.py</pre>
    </div>
    <div class="card">
      <h2>Endpoints</h2>
      <p>Team server: <code>{esc(public_url)}</code></p>
      <p>Admin server: <code>{esc(admin_url)}</code></p>
    </div>
    <div class="card">
      <h2>Submit During Live</h2>
      <pre>FTF_TEAM_CONFIG=team_config.json python3 submit_flag.py 'FTF{{...}}'</pre>
    </div>
  </main>
</body>
</html>
"""


def generate_team_packages() -> None:
    generate_team_configs()
    output_dir = BASE_DIR / "generated" / "team_packages"
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    for team in teams():
        cfg = json.loads((BASE_DIR / "configs" / f"{team}.team_config.json").read_text(encoding="utf-8"))
        package_dir = output_dir / team
        package_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(BASE_DIR / "team_server.py", package_dir / "team_server.py")
        shutil.copy2(BASE_DIR / "submit_flag.py", package_dir / "submit_flag.py")
        (package_dir / "submit_flag.py").chmod(0o755)
        shutil.copy2(BASE_DIR / "configs" / f"{team}.team_config.json", package_dir / "team_config.json")
        (package_dir / "public").mkdir(exist_ok=True)
        (package_dir / "public" / "index.html").write_text(team_starter_html(team, cfg), encoding="utf-8")
        (package_dir / "README.md").write_text(
            f"# Team Package: {team}\n\nEnabled services:\n\n{chr(10).join('- ' + service for service in cfg.get('services', ['default']))}\n\nRun:\n\n```bash\nFTF_TEAM_CONFIG=team_config.json python3 team_server.py\n```\n\nTeam URL:\n\n```text\n{cfg['public_base_url']}\n```\n\nSubmit:\n\n```bash\nFTF_TEAM_CONFIG=team_config.json python3 submit_flag.py 'FTF{{...}}'\n```\n",
            encoding="utf-8",
        )
        (package_dir / "public" / "index.html").write_text(
            f"<!doctype html><meta charset='utf-8'><title>{esc(team)} package</title><h1>{esc(team)} Team Package</h1><p>Start:</p><pre>FTF_TEAM_CONFIG=team_config.json python3 team_server.py</pre><p>Team URL: <code>{esc(cfg['public_base_url'])}</code></p>",
            encoding="utf-8",
        )


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def init_db() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    with DB_LOCK, db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS heartbeats (
                team TEXT PRIMARY KEY,
                public_base_url TEXT NOT NULL,
                phase_seen TEXT NOT NULL,
                services_json TEXT NOT NULL,
                received_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS flag_reports (
                team TEXT NOT NULL,
                service TEXT NOT NULL,
                round INTEGER NOT NULL,
                flag TEXT NOT NULL,
                received_at REAL NOT NULL,
                PRIMARY KEY (team, service, round)
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
            CREATE TABLE IF NOT EXISTS availability_scores (
                team TEXT NOT NULL,
                service TEXT NOT NULL,
                round INTEGER NOT NULL,
                points INTEGER NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY (team, service, round)
            );
            CREATE TABLE IF NOT EXISTS integrity_scores (
                team TEXT NOT NULL,
                service TEXT NOT NULL,
                round INTEGER NOT NULL,
                points INTEGER NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY (team, service, round)
            );
            CREATE TABLE IF NOT EXISTS penalties (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                team TEXT NOT NULL,
                reason TEXT NOT NULL,
                points INTEGER NOT NULL,
                created_at REAL NOT NULL
            );
            """
        )
        conn.execute("INSERT OR IGNORE INTO settings(key, value) VALUES ('phase', 'setup')")
        conn.execute("INSERT OR IGNORE INTO settings(key, value) VALUES ('selected_services', 'default')")
        for key, value in DEFAULT_SCORING.items():
            conn.execute(
                "INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)",
                (f"scoring.{key}", str(value)),
            )


def get_setting(key: str, default: str = "") -> str:
    with db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    with DB_LOCK, db() as conn:
        conn.execute(
            "INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


def phase() -> str:
    value = get_setting("phase", "setup")
    return value if value in PHASES else "setup"


def scoring_config() -> dict[str, int]:
    config = {}
    for key, default in DEFAULT_SCORING.items():
        try:
            value = int(get_setting(f"scoring.{key}", str(default)))
        except ValueError:
            value = default
        config[key] = max(0, value)
    return config


def parse_cookies(header: str | None) -> dict[str, str]:
    if not header:
        return {}
    cookie = SimpleCookie()
    cookie.load(header)
    return {key: morsel.value for key, morsel in cookie.items()}


def sign_session() -> str:
    body = str(int(now()))
    sig = hmac.new(ADMIN_PASSWORD.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def valid_session(cookie: str) -> bool:
    if "." not in cookie:
        return False
    body, sig = cookie.rsplit(".", 1)
    expected = hmac.new(ADMIN_PASSWORD.encode(), body.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected)


def verify_team_signature(team: str, raw_body: bytes, signature: str) -> bool:
    cfg = teams().get(team)
    if not cfg:
        return False
    expected = hmac.new(cfg["secret"].encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def checker_signature(team: str, raw_body: bytes) -> str:
    cfg = teams()[team]
    return hmac.new(cfg["secret"].encode(), raw_body, hashlib.sha256).hexdigest()


def parse_flag(flag: str) -> tuple[str, str, int] | None:
    match = re.fullmatch(r"FTF\{([a-z0-9-]+)_([a-z]+)_(\d+)_([0-9a-f]{18})\}", flag.strip())
    if not match:
        return None
    victim, service, round_raw, _digest = match.groups()
    return victim, service, int(round_raw)


def scoreboard() -> list[dict[str, Any]]:
    with db() as conn:
        attack_rows = conn.execute("SELECT attacker, COALESCE(SUM(points), 0) AS points FROM submissions GROUP BY attacker").fetchall()
        availability_rows = conn.execute("SELECT team, COALESCE(SUM(points), 0) AS points FROM availability_scores GROUP BY team").fetchall()
        integrity_rows = conn.execute("SELECT team, COALESCE(SUM(points), 0) AS points FROM integrity_scores GROUP BY team").fetchall()
        penalty_rows = conn.execute("SELECT team, COALESCE(SUM(points), 0) AS points FROM penalties GROUP BY team").fetchall()
    attack = {row["attacker"]: int(row["points"]) for row in attack_rows}
    availability = {row["team"]: int(row["points"]) for row in availability_rows}
    integrity = {row["team"]: int(row["points"]) for row in integrity_rows}
    penalties = {row["team"]: int(row["points"]) for row in penalty_rows}
    rows = []
    for team in teams():
        heartbeat = last_heartbeat(team)
        connected = bool(heartbeat and now() - heartbeat["received_at"] <= HEARTBEAT_TIMEOUT_SECONDS)
        row = {
            "team": team,
            "attack": attack.get(team, 0),
            "availability": availability.get(team, 0),
            "integrity": integrity.get(team, 0),
            "penalty": penalties.get(team, 0),
            "connected": connected,
        }
        row["total"] = row["attack"] + row["availability"] + row["integrity"] - row["penalty"]
        rows.append(row)
    return sorted(rows, key=lambda item: item["total"], reverse=True)


def reset_match_state() -> None:
    with DB_LOCK, db() as conn:
        conn.execute("DELETE FROM heartbeats")
        conn.execute("DELETE FROM flag_reports")
        conn.execute("DELETE FROM submissions")
        conn.execute("DELETE FROM availability_scores")
        conn.execute("DELETE FROM integrity_scores")
        conn.execute("DELETE FROM penalties")
        conn.execute("INSERT INTO settings(key, value) VALUES ('phase', 'hardening') ON CONFLICT(key) DO UPDATE SET value = 'hardening'")


def last_heartbeat(team: str) -> sqlite3.Row | None:
    with db() as conn:
        return conn.execute("SELECT * FROM heartbeats WHERE team = ?", (team,)).fetchone()


def run_checker(team: str, public_base_url: str, round_no: int) -> None:
    if not public_base_url:
        public_base_url = teams().get(team, {}).get("public_base_url", "")
    if not public_base_url:
        return
    payload = {"round": round_no}
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    request = urllib.request.Request(
        public_base_url.rstrip("/") + "/__checker/flags",
        data=raw,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Checker-Signature": checker_signature(team, raw),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=max(1, scoring_config()["checker_timeout_seconds"])) as response:
            data = json.loads(response.read().decode())
    except Exception:
        return
    if data.get("team_id") != team or int(data.get("round", -1)) != round_no:
        return
    flags = data.get("flags", {})
    if not isinstance(flags, dict):
        return
    scoring = scoring_config()
    with DB_LOCK, db() as conn:
        for service in selected_services():
            flag = str(flags.get(service, ""))
            if parse_flag(flag) != (team, service, round_no):
                continue
            conn.execute(
                """
                INSERT INTO flag_reports(team, service, round, flag, received_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(team, service, round) DO UPDATE SET flag = excluded.flag, received_at = excluded.received_at
                """,
                (team, service, round_no, flag, now()),
            )
            conn.execute(
                """
                INSERT OR IGNORE INTO availability_scores(team, service, round, points, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (team, service, round_no, scoring["availability_points"], now()),
            )
            conn.execute(
                """
                INSERT OR IGNORE INTO integrity_scores(team, service, round, points, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (team, service, round_no, scoring["integrity_points"], now()),
            )


def checker_loop() -> None:
    while True:
        try:
            if phase() == "live":
                round_no = current_round()
                for team, cfg in teams().items():
                    heartbeat = last_heartbeat(team)
                    public_base_url = str(heartbeat["public_base_url"]) if heartbeat else cfg.get("public_base_url", "")
                    run_checker(team, public_base_url, round_no)
        except Exception as exc:
            print(f"checker error: {exc}")
        time.sleep(CHECKER_INTERVAL_SECONDS)


def page(title: str, body: str, status: int = 200) -> tuple[int, str, str]:
    doc = f"""<!doctype html>
<html lang="zh-Hant">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{esc(title)} - FTF Admin</title>
  <style>
    body {{ margin:0; font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; background:#f5f7fa; color:#17212b; }}
    header {{ background:#102631; color:white; padding:16px 22px; border-bottom:4px solid #d8a331; }}
    nav {{ display:flex; gap:14px; flex-wrap:wrap; margin-top:8px; }}
    nav a {{ color:white; }}
    main {{ max-width:1200px; margin:0 auto; padding:22px; }}
    h1 {{ margin:0 0 14px; }}
    .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(230px,1fr)); gap:12px; }}
    .card, table, .notice {{ background:white; border:1px solid #d9e0e8; border-radius:8px; padding:14px; }}
    table {{ width:100%; border-collapse:collapse; padding:0; overflow:hidden; }}
    th,td {{ border-bottom:1px solid #d9e0e8; padding:9px 10px; text-align:left; font-size:14px; }}
    th {{ background:#edf3f7; }}
    input,select {{ width:100%; padding:9px; border:1px solid #b8c4d0; border-radius:6px; }}
    label {{ display:block; font-weight:700; margin:10px 0 5px; }}
    button,.button {{ display:inline-flex; background:#176b87; color:white; border:0; border-radius:6px; padding:9px 12px; font-weight:700; text-decoration:none; cursor:pointer; }}
    .secondary {{ background:#e5edf2; color:#173447; }}
    .danger {{ background:#c6532f; }}
    .row {{ display:flex; gap:10px; flex-wrap:wrap; align-items:end; }}
    .row > * {{ flex:1 1 160px; }}
    .ok {{ color:#247a45; font-weight:700; }}
    .bad {{ color:#b42318; font-weight:700; }}
    code {{ font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }}
  </style>
</head>
<body>
  <header>
    <strong>Distributed FindTheFlag Admin</strong>
    <nav>
      <a href="/admin">Dashboard</a>
      <a href="/admin/teams">Teams</a>
      <a href="/admin/flags">Flags</a>
      <a href="/admin/submissions">Submissions</a>
      <a href="/admin/scoring">Scoring</a>
      <a href="/admin/penalties">Penalties</a>
      <a href="/admin/export">Export</a>
    </nav>
  </header>
  <main>{body}</main>
</body>
</html>"""
    return status, "text/html; charset=utf-8", doc


def login_page(message: str = "") -> tuple[int, str, str]:
    return page(
        "Login",
        f"""
        <h1>Admin Login</h1>
        <div class="card">
          <form method="post" action="/admin/login">
            <label>Password</label>
            <input type="password" name="password">
            <button>Login</button>
          </form>
          {'<p class="bad">' + esc(message) + '</p>' if message else ''}
        </div>
        """,
    )


def dashboard_page() -> tuple[int, str, str]:
    rows = "".join(
        f"<tr><td>{esc(row['team'])}</td><td>{row['attack']}</td><td>{row['availability']}</td><td>{row['integrity']}</td><td>{row['penalty']}</td><td><strong>{row['total']}</strong></td><td class=\"{'ok' if row['connected'] else 'bad'}\">{'connected' if row['connected'] else 'missing'}</td></tr>"
        for row in scoreboard()
    )
    return page(
        "Dashboard",
        f"""
        <h1>Dashboard</h1>
        <div class="notice">Phase: <strong>{esc(phase())}</strong> | Round: <strong>{current_round()}</strong> | Next flags in: <strong>{round_remaining()}s</strong></div>
        <div class="card">
          <form method="post" action="/admin/phase" class="row">
            <button name="phase" value="setup" class="secondary">Setup</button>
            <button name="phase" value="hardening" class="secondary">Hardening</button>
            <button name="phase" value="live">Live</button>
            <button name="phase" value="ended" class="danger">Ended</button>
          </form>
        </div>
        <div class="card">
          <form method="post" action="/admin/reset" class="row">
            <button class="danger">Reset match state</button>
          </form>
          <p>Clears heartbeats, flag reports, submissions, availability, integrity, and penalties; phase returns to hardening.</p>
        </div>
        <h2>Scoreboard</h2>
        <table><thead><tr><th>Team</th><th>Attack</th><th>Availability</th><th>Integrity</th><th>Penalty</th><th>Total</th><th>Heartbeat</th></tr></thead><tbody>{rows}</tbody></table>
        """,
    )


def public_scoreboard_page() -> tuple[int, str, str]:
    rows = "".join(
        f"<tr><td>{esc(row['team'])}</td><td>{row['attack']}</td><td>{row['availability']}</td><td>{row['integrity']}</td><td>{row['penalty']}</td><td><strong>{row['total']}</strong></td><td class=\"{'ok' if row['connected'] else 'bad'}\">{'connected' if row['connected'] else 'missing'}</td></tr>"
        for row in scoreboard()
    )
    return page(
        "Scoreboard",
        f"""
        <h1>Scoreboard</h1>
        <div class="notice">Phase: <strong>{esc(phase())}</strong> | Round: <strong>{current_round()}</strong> | Next flags in: <strong>{round_remaining()}s</strong></div>
        <table><thead><tr><th>Team</th><th>Attack</th><th>Availability</th><th>Integrity</th><th>Penalty</th><th>Total</th><th>Heartbeat</th></tr></thead><tbody>{rows}</tbody></table>
        <script>setTimeout(() => location.reload(), 5000);</script>
        """,
    )


def teams_page() -> tuple[int, str, str]:
    rows = []
    enabled = set(selected_services())
    service_checks = "".join(
        f"""
        <label>
          <input type="checkbox" name="services" value="{esc(key)}" {'checked' if key in enabled else ''}>
          {esc(meta['name'])} <small>({esc(meta['category'])})</small>
        </label>
        <p>{esc(meta['description'])}</p>
        """
        for key, meta in SERVICE_CATALOG.items()
    )
    for team, cfg in teams().items():
        hb = last_heartbeat(team)
        age = "never" if not hb else f"{int(now() - hb['received_at'])}s ago"
        rows.append(
            f"""
            <tr>
              <td>{esc(team)}</td>
              <td><code>{esc(cfg['secret'])}</code></td>
              <td>
                <form method="post" action="/admin/teams" class="row">
                  <input type="hidden" name="action" value="update">
                  <input type="hidden" name="team" value="{esc(team)}">
                  <input name="public_base_url" value="{esc(cfg['public_base_url'])}">
                  <button>Save</button>
                </form>
              </td>
              <td>{age}</td>
              <td>
                <form method="post" action="/admin/teams" class="row">
                  <input type="hidden" name="team" value="{esc(team)}">
                  <button name="action" value="rotate" class="secondary">Rotate secret</button>
                  <button name="action" value="delete" class="danger">Delete</button>
                </form>
              </td>
            </tr>
            """
        )
    return page(
        "Teams",
        f"""
        <h1>Teams</h1>
        <div class="card">
          <h2>Create Team</h2>
          <form method="post" action="/admin/teams" class="row">
            <input type="hidden" name="action" value="create">
            <div><label>Team ID</label><input name="team" placeholder="red1"></div>
            <div><label>Public URL</label><input name="public_base_url" placeholder="http://red1-host:9100"></div>
            <div><button>Create</button></div>
          </form>
          <p>Team ID 可用 lowercase letters、digits、hyphen，長度 2-32；不要用底線。</p>
        </div>
        <div class="card">
          <h2>Generate Packages</h2>
          <form method="post" action="/admin/teams" class="row">
            <input type="hidden" name="action" value="generate">
            <div style="flex-basis:100%">
              <h3>Enabled Vulnerability Services</h3>
              {service_checks}
            </div>
            <button name="action" value="generate">Generate team configs and packages</button>
          </form>
          <p>輸出到 <code>{esc(BASE_DIR / 'generated' / 'team_packages')}</code>。</p>
        </div>
        <table><thead><tr><th>Team</th><th>Secret</th><th>Public URL</th><th>Heartbeat</th><th>Actions</th></tr></thead><tbody>{''.join(rows) or '<tr><td colspan="5">No teams.</td></tr>'}</tbody></table>
        """,
    )


def flags_page() -> tuple[int, str, str]:
    with db() as conn:
        rows = conn.execute("SELECT team, service, round, flag, received_at FROM flag_reports ORDER BY round DESC, team, service LIMIT 200").fetchall()
    body_rows = "".join(
        f"<tr><td>{esc(row['team'])}</td><td>{esc(row['service'])}</td><td>{row['round']}</td><td><code>{esc(row['flag'])}</code></td><td>{time.strftime('%H:%M:%S', time.localtime(row['received_at']))}</td></tr>"
        for row in rows
    ) or "<tr><td colspan='5'>No flag reports yet.</td></tr>"
    return page("Flags", f"<h1>Flag Reports</h1><table><thead><tr><th>Team</th><th>Service</th><th>Round</th><th>Flag</th><th>Received</th></tr></thead><tbody>{body_rows}</tbody></table>")


def submissions_page() -> tuple[int, str, str]:
    with db() as conn:
        rows = conn.execute("SELECT attacker, victim, service, round, flag, points, created_at FROM submissions ORDER BY created_at DESC LIMIT 200").fetchall()
    body_rows = "".join(
        f"<tr><td>{esc(row['attacker'])}</td><td>{esc(row['victim'])}</td><td>{esc(row['service'])}</td><td>{row['round']}</td><td><code>{esc(row['flag'])}</code></td><td>+{row['points']}</td><td>{time.strftime('%H:%M:%S', time.localtime(row['created_at']))}</td></tr>"
        for row in rows
    ) or "<tr><td colspan='7'>No submissions yet.</td></tr>"
    return page("Submissions", f"<h1>Submissions</h1><table><thead><tr><th>Attacker</th><th>Victim</th><th>Service</th><th>Round</th><th>Flag</th><th>Points</th><th>Time</th></tr></thead><tbody>{body_rows}</tbody></table>")


def scoring_page(message: str = "") -> tuple[int, str, str]:
    cfg = scoring_config()
    inputs = "".join(
        f"<label>{esc(key)}</label><input type='number' min='0' name='{esc(key)}' value='{value}'>"
        for key, value in cfg.items()
    )


def penalties_page(message: str = "") -> tuple[int, str, str]:
    team_options = "".join(f"<option value='{esc(team)}'>{esc(team)}</option>" for team in teams())
    with db() as conn:
        rows = conn.execute("SELECT team, reason, points, created_at FROM penalties ORDER BY created_at DESC LIMIT 200").fetchall()
    body_rows = "".join(
        f"<tr><td>{esc(row['team'])}</td><td>{esc(row['reason'])}</td><td>-{row['points']}</td><td>{time.strftime('%H:%M:%S', time.localtime(row['created_at']))}</td></tr>"
        for row in rows
    ) or "<tr><td colspan='4'>No penalties.</td></tr>"
    return page(
        "Penalties",
        f"""
        <h1>Penalties</h1>
        <div class="card">
          <form method="post" action="/admin/penalties" class="row">
            <div><label>Team</label><select name="team">{team_options}</select></div>
            <div><label>Points</label><input type="number" min="1" name="points" value="{scoring_config()['infra_attack_penalty']}"></div>
            <div><label>Reason</label><input name="reason" placeholder="admin page attack"></div>
            <div><button class="danger">Add penalty</button></div>
          </form>
          {'<p class="ok">' + esc(message) + '</p>' if message else ''}
        </div>
        <table><thead><tr><th>Team</th><th>Reason</th><th>Points</th><th>Time</th></tr></thead><tbody>{body_rows}</tbody></table>
        """,
    )


def export_state() -> dict[str, Any]:
    with db() as conn:
        flag_rows = conn.execute("SELECT team, service, round, flag, received_at FROM flag_reports ORDER BY round, team, service").fetchall()
        submission_rows = conn.execute("SELECT attacker, victim, service, round, flag, points, created_at FROM submissions ORDER BY created_at").fetchall()
        penalty_rows = conn.execute("SELECT team, reason, points, created_at FROM penalties ORDER BY created_at").fetchall()
    return {
        "exported_at": int(now()),
        "phase": phase(),
        "round": current_round(),
        "services": selected_services(),
        "scoring": scoring_config(),
        "scoreboard": scoreboard(),
        "flags": [dict(row) for row in flag_rows],
        "submissions": [dict(row) for row in submission_rows],
        "penalties": [dict(row) for row in penalty_rows],
    }
    return page(
        "Scoring",
        f"""
        <h1>Scoring</h1>
        <div class="card"><form method="post" action="/admin/scoring">{inputs}<button>Save</button></form>{'<p class="ok">' + esc(message) + '</p>' if message else ''}</div>
        """,
    )


def api_state() -> dict[str, Any]:
    return {
        "phase": phase(),
        "round": current_round(),
        "round_remaining": round_remaining(),
        "services": selected_services(),
        "scoreboard": scoreboard(),
    }


def accept_heartbeat(team: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    if team not in teams():
        return 403, {"ok": False, "message": "unknown team"}
    round_no = current_round()
    public_base_url = str(payload.get("public_base_url", ""))
    with DB_LOCK, db() as conn:
        conn.execute(
            """
            INSERT INTO heartbeats(team, public_base_url, phase_seen, services_json, received_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(team) DO UPDATE SET
              public_base_url = excluded.public_base_url,
              phase_seen = excluded.phase_seen,
              services_json = excluded.services_json,
              received_at = excluded.received_at
            """,
            (
                team,
                public_base_url,
                str(payload.get("phase_seen", "")),
                json.dumps(payload.get("services", {}), sort_keys=True),
                now(),
            ),
        )
    return 200, {"ok": True, "phase": phase(), "round": round_no, "round_seconds": ROUND_SECONDS}


def accept_flags(team: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    if phase() != "live":
        return 403, {"ok": False, "message": "flag reports only accepted during live"}
    report_round = int(payload.get("round", -1))
    flags = payload.get("flags", {})
    if not isinstance(flags, dict):
        return 400, {"ok": False, "message": "flags must be an object"}
    allowed_rounds = {current_round(), current_round() - 1, current_round() + 1}
    if report_round not in allowed_rounds:
        return 400, {"ok": False, "message": "round outside allowed skew"}
    services = selected_services()
    missing = [service for service in services if service not in flags]
    if missing:
        return 400, {"ok": False, "message": f"missing service flags: {', '.join(missing)}"}
    with DB_LOCK, db() as conn:
        for service in services:
            flag = str(flags[service])
            parsed = parse_flag(flag)
            if parsed != (team, service, report_round):
                return 400, {"ok": False, "message": f"bad flag for {service}"}
            conn.execute(
                """
                INSERT INTO flag_reports(team, service, round, flag, received_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(team, service, round) DO UPDATE SET flag = excluded.flag, received_at = excluded.received_at
                """,
                (team, service, report_round, flag, now()),
            )
    return 200, {"ok": True, "message": "flags accepted"}


def submit_flag(attacker: str, flag: str) -> tuple[int, dict[str, Any]]:
    if phase() != "live":
        return 403, {"ok": False, "message": "submissions are only open during live"}
    parsed = parse_flag(flag)
    if not parsed:
        return 400, {"ok": False, "message": "invalid flag format"}
    victim, service, round_no = parsed
    if attacker not in teams():
        return 403, {"ok": False, "message": "unknown attacker"}
    if victim not in teams() or service not in selected_services():
        return 400, {"ok": False, "message": "unknown victim or service"}
    if victim == attacker:
        return 400, {"ok": False, "message": "self flags do not score"}
    with DB_LOCK, db() as conn:
        row = conn.execute(
            "SELECT flag FROM flag_reports WHERE team = ? AND service = ? AND round = ?",
            (victim, service, round_no),
        ).fetchone()
        if not row or not hmac.compare_digest(row["flag"], flag):
            return 400, {"ok": False, "message": "flag not reported by victim or incorrect"}
        points = scoring_config()["attack_flag_points"]
        try:
            conn.execute(
                "INSERT INTO submissions(attacker, victim, service, round, flag, points, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (attacker, victim, service, round_no, flag, points, now()),
            )
        except sqlite3.IntegrityError:
            existing = conn.execute(
                "SELECT points FROM submissions WHERE attacker = ? AND victim = ? AND service = ? AND round = ?",
                (attacker, victim, service, round_no),
            ).fetchone()
            prior_points = int(existing["points"]) if existing else points
            return 200, {"ok": True, "duplicate": True, "message": f"already accepted earlier: +{prior_points} points for {attacker}"}
    return 200, {"ok": True, "message": f"accepted: +{points} points for {attacker}"}


def parse_body(headers: dict[str, str], body: bytes) -> dict[str, Any]:
    content_type = headers.get("content-type", "")
    if "application/json" in content_type:
        return json.loads(body.decode() or "{}")
    parsed = urllib.parse.parse_qs(body.decode())
    return {key: values[0] if values else "" for key, values in parsed.items()}


def parse_multi_body(headers: dict[str, str], body: bytes) -> dict[str, list[str]]:
    content_type = headers.get("content-type", "")
    if "application/json" in content_type:
        data = json.loads(body.decode() or "{}")
        return {key: value if isinstance(value, list) else [str(value)] for key, value in data.items()}
    return urllib.parse.parse_qs(body.decode())


class ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True


class AdminHandler(BaseHTTPRequestHandler):
    server_version = "FTFDistributedAdmin/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[{time.strftime('%H:%M:%S')}] {self.address_string()} {fmt % args}")

    def headers_map(self) -> dict[str, str]:
        return {key.lower(): value for key, value in self.headers.items()}

    def read_body(self) -> bytes:
        length = int(self.headers.get("content-length", "0") or "0")
        return self.rfile.read(length) if length else b""

    def is_admin(self) -> bool:
        return valid_session(parse_cookies(self.headers.get("cookie")).get("admin_session", ""))

    def respond(self, response: tuple[int, str, str]) -> None:
        status, content_type, text = response
        raw = text.encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def redirect(self, location: str, cookies: list[str] | None = None) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        for cookie in cookies or []:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def send_json(self, status: int, data: dict[str, Any]) -> None:
        raw = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def require_admin(self) -> bool:
        if self.is_admin():
            return True
        self.respond(login_page("Login required."))
        return False

    def do_GET(self) -> None:
        path = urllib.parse.urlparse(self.path).path.rstrip("/") or "/"
        if path == "/":
            return self.redirect("/admin")
        if path == "/api/state":
            return self.send_json(200, api_state())
        if path == "/scoreboard":
            return self.respond(public_scoreboard_page())
        if path == "/admin/login":
            return self.respond(login_page())
        if path.startswith("/admin") and not self.require_admin():
            return
        if path == "/admin":
            return self.respond(dashboard_page())
        if path == "/admin/teams":
            return self.respond(teams_page())
        if path == "/admin/flags":
            return self.respond(flags_page())
        if path == "/admin/submissions":
            return self.respond(submissions_page())
        if path == "/admin/scoring":
            return self.respond(scoring_page())
        if path == "/admin/penalties":
            return self.respond(penalties_page())
        if path == "/admin/export":
            return self.send_json(200, export_state())
        return self.respond(page("Not found", "<h1>Not found</h1>", HTTPStatus.NOT_FOUND))

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        body = self.read_body()
        headers = self.headers_map()
        if path == "/admin/login":
            payload = parse_body(headers, body)
            if hmac.compare_digest(str(payload.get("password", "")), ADMIN_PASSWORD):
                return self.redirect("/admin", [f"admin_session={sign_session()}; Path=/; HttpOnly; SameSite=Lax"])
            return self.respond(login_page("Password incorrect."))
        if path == "/api/team/heartbeat":
            team = self.headers.get("X-Team-Id", "")
            sig = self.headers.get("X-Team-Signature", "")
            if not verify_team_signature(team, body, sig):
                return self.send_json(403, {"ok": False, "message": "bad signature"})
            status, response = accept_heartbeat(team, json.loads(body.decode() or "{}"))
            return self.send_json(status, response)
        if path == "/api/team/flags":
            team = self.headers.get("X-Team-Id", "")
            sig = self.headers.get("X-Team-Signature", "")
            if not verify_team_signature(team, body, sig):
                return self.send_json(403, {"ok": False, "message": "bad signature"})
            status, response = accept_flags(team, json.loads(body.decode() or "{}"))
            return self.send_json(status, response)
        if path == "/api/submit":
            attacker = self.headers.get("X-Team-Id", "")
            sig = self.headers.get("X-Team-Signature", "")
            if not verify_team_signature(attacker, body, sig):
                return self.send_json(403, {"ok": False, "message": "bad signature"})
            payload = json.loads(body.decode() or "{}")
            status, response = submit_flag(attacker, str(payload.get("flag", "")))
            return self.send_json(status, response)
        if path.startswith("/admin") and not self.require_admin():
            return
        if path == "/admin/phase":
            payload = parse_body(headers, body)
            value = str(payload.get("phase", ""))
            if value not in PHASES:
                return self.respond(page("Bad phase", "<h1>Bad phase</h1>", HTTPStatus.BAD_REQUEST))
            set_setting("phase", value)
            return self.redirect("/admin")
        if path == "/admin/reset":
            reset_match_state()
            return self.redirect("/admin")
        if path == "/admin/scoring":
            payload = parse_body(headers, body)
            for key in DEFAULT_SCORING:
                if key in payload:
                    try:
                        value = max(0, int(str(payload[key])))
                    except ValueError:
                        continue
                    set_setting(f"scoring.{key}", str(value))
            return self.respond(scoring_page("Saved."))
        if path == "/admin/penalties":
            payload = parse_body(headers, body)
            team = str(payload.get("team", ""))
            if team not in teams():
                return self.respond(page("Bad team", "<h1>Unknown team</h1>", HTTPStatus.BAD_REQUEST))
            try:
                points = max(1, int(str(payload.get("points", "0"))))
            except ValueError:
                return self.respond(page("Bad points", "<h1>Bad points</h1>", HTTPStatus.BAD_REQUEST))
            reason = str(payload.get("reason", "")).strip() or "manual penalty"
            with DB_LOCK, db() as conn:
                conn.execute(
                    "INSERT INTO penalties(team, reason, points, created_at) VALUES (?, ?, ?, ?)",
                    (team, reason, points, now()),
                )
            return self.respond(penalties_page("Penalty added."))
        if path == "/admin/teams":
            multi_payload = parse_multi_body(headers, body)
            payload = {key: values[0] if values else "" for key, values in multi_payload.items()}
            action = str(payload.get("action", ""))
            team = str(payload.get("team", "")).strip().lower()
            data = teams()
            if action == "create":
                if not valid_team_id(team):
                    return self.respond(page("Bad team", "<h1>Bad team id</h1><p>Use lowercase letters, digits, and hyphen only; length 2-32.</p>", HTTPStatus.BAD_REQUEST))
                if team in data:
                    return self.respond(page("Team exists", "<h1>Team already exists</h1>", HTTPStatus.CONFLICT))
                data[team] = {
                    "secret": generate_secret(),
                    "public_base_url": str(payload.get("public_base_url", "")),
                }
                save_teams(data)
                return self.redirect("/admin/teams")
            if action == "update":
                if team not in data:
                    return self.respond(page("Not found", "<h1>Unknown team</h1>", HTTPStatus.NOT_FOUND))
                data[team]["public_base_url"] = str(payload.get("public_base_url", ""))
                save_teams(data)
                return self.redirect("/admin/teams")
            if action == "rotate":
                if team not in data:
                    return self.respond(page("Not found", "<h1>Unknown team</h1>", HTTPStatus.NOT_FOUND))
                data[team]["secret"] = generate_secret()
                save_teams(data)
                return self.redirect("/admin/teams")
            if action == "delete":
                if team in data:
                    del data[team]
                    save_teams(data)
                return self.redirect("/admin/teams")
            if action == "generate":
                set_selected_services(multi_payload.get("services", []))
                generate_team_packages()
                return self.redirect("/admin/teams")
            return self.respond(page("Bad action", "<h1>Bad action</h1>", HTTPStatus.BAD_REQUEST))
        return self.respond(page("Not found", "<h1>Not found</h1>", HTTPStatus.NOT_FOUND))


def main() -> None:
    init_db()
    host = os.environ.get("FTF_ADMIN_HOST", "127.0.0.1")
    port = int(os.environ.get("FTF_ADMIN_PORT", "8088"))
    threading.Thread(target=checker_loop, daemon=True).start()
    print(f"Distributed admin running at http://{host}:{port}")
    print(f"Admin password file: {ADMIN_PASSWORD_PATH}")
    print(f"Teams config: {TEAMS_PATH}")
    ReusableThreadingHTTPServer((host, port), AdminHandler).serve_forever()


if __name__ == "__main__":
    main()
