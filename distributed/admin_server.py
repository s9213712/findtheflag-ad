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
    "server_down_penalty_points": 10,
    "server_down_penalty_window_seconds": 600,
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
    submit_url = admin_url.rstrip("/") + "/team/login"
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
    a.secondary {{ background:#e5edf2; color:#173447; }}
  </style>
</head>
<body>
  <header><strong>FindTheFlag Team Package: {esc(team)}</strong></header>
  <main>
    <div class="card">
      <h1>{esc(team)} Initialization</h1>
      <p>This page is the local handoff page for the hardening window.</p>
      <p>
        <a class="button" href="{esc(public_url)}">Open Team Server</a>
        <a class="button secondary" href="{esc(submit_url)}">Submit Flags</a>
      </p>
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
      <p>Use the web submit portal:</p>
      <pre>{esc(submit_url)}</pre>
      <p>Backup CLI path:</p>
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
            f"# Team Package: {team}\n\nEnabled services:\n\n{chr(10).join('- ' + service for service in cfg.get('services', ['default']))}\n\nRun:\n\n```bash\nFTF_TEAM_CONFIG=team_config.json python3 team_server.py\n```\n\nTeam URL:\n\n```text\n{cfg['public_base_url']}\n```\n\nWeb submit portal:\n\n```text\n{cfg['admin_url'].rstrip('/')}/team/login\n```\n\nSubmit with backup CLI:\n\n```bash\nFTF_TEAM_CONFIG=team_config.json python3 submit_flag.py 'FTF{{...}}'\n```\n",
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
            CREATE TABLE IF NOT EXISTS server_down_penalties (
                team TEXT NOT NULL,
                window INTEGER NOT NULL,
                points INTEGER NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY (team, window)
            );
            CREATE TABLE IF NOT EXISTS violation_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                team TEXT NOT NULL,
                kind TEXT NOT NULL,
                severity TEXT NOT NULL,
                note TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS disqualifications (
                team TEXT PRIMARY KEY,
                reason TEXT NOT NULL,
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


def sign_team_session(team: str) -> str:
    body = f"{team}:{int(now())}"
    sig = hmac.new(ADMIN_PASSWORD.encode(), f"team:{body}".encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def valid_team_session(cookie: str) -> str | None:
    if "." not in cookie:
        return None
    body, sig = cookie.rsplit(".", 1)
    if ":" not in body:
        return None
    team, _issued = body.split(":", 1)
    expected = hmac.new(ADMIN_PASSWORD.encode(), f"team:{body}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    return team if team in teams() else None


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


def disqualified_teams() -> dict[str, sqlite3.Row]:
    with db() as conn:
        rows = conn.execute("SELECT team, reason, created_at FROM disqualifications").fetchall()
    return {row["team"]: row for row in rows}


def is_disqualified(team: str) -> bool:
    return team in disqualified_teams()


def disqualify_team(team: str, reason: str) -> None:
    with DB_LOCK, db() as conn:
        conn.execute(
            """
            INSERT INTO disqualifications(team, reason, created_at)
            VALUES (?, ?, ?)
            ON CONFLICT(team) DO UPDATE SET reason = excluded.reason, created_at = excluded.created_at
            """,
            (team, reason, now()),
        )


def record_violation(team: str, kind: str, note: str, severity: str = "warning") -> int:
    with DB_LOCK, db() as conn:
        conn.execute(
            "INSERT INTO violation_events(team, kind, severity, note, created_at) VALUES (?, ?, ?, ?, ?)",
            (team, kind, severity, note, now()),
        )
        count = conn.execute(
            "SELECT COUNT(*) FROM violation_events WHERE team = ? AND kind = ?",
            (team, kind),
        ).fetchone()[0]
    if kind == "admin_attack" and count >= 2:
        disqualify_team(team, "second admin-page attack")
    return int(count)


def rule_status(team: str) -> dict[str, Any]:
    dq = disqualified_teams().get(team)
    with db() as conn:
        rows = conn.execute(
            "SELECT kind, COUNT(*) AS count FROM violation_events WHERE team = ? GROUP BY kind",
            (team,),
        ).fetchall()
    return {
        "disqualified": bool(dq),
        "disqualification_reason": dq["reason"] if dq else "",
        "violations": {row["kind"]: int(row["count"]) for row in rows},
    }


def scoreboard() -> list[dict[str, Any]]:
    with db() as conn:
        attack_rows = conn.execute("SELECT attacker, COALESCE(SUM(points), 0) AS points FROM submissions GROUP BY attacker").fetchall()
        availability_rows = conn.execute("SELECT team, COALESCE(SUM(points), 0) AS points FROM availability_scores GROUP BY team").fetchall()
        integrity_rows = conn.execute("SELECT team, COALESCE(SUM(points), 0) AS points FROM integrity_scores GROUP BY team").fetchall()
        penalty_rows = conn.execute("SELECT team, COALESCE(SUM(points), 0) AS points FROM penalties GROUP BY team").fetchall()
    dq = disqualified_teams()
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
            "disqualified": team in dq,
            "disqualification_reason": dq[team]["reason"] if team in dq else "",
        }
        row["total"] = row["attack"] + row["availability"] + row["integrity"] - row["penalty"]
        rows.append(row)
    return sorted(rows, key=lambda item: (item["disqualified"], -item["total"], item["team"]))


def reset_match_state() -> None:
    with DB_LOCK, db() as conn:
        conn.execute("DELETE FROM heartbeats")
        conn.execute("DELETE FROM flag_reports")
        conn.execute("DELETE FROM submissions")
        conn.execute("DELETE FROM availability_scores")
        conn.execute("DELETE FROM integrity_scores")
        conn.execute("DELETE FROM penalties")
        conn.execute("DELETE FROM server_down_penalties")
        conn.execute("DELETE FROM violation_events")
        conn.execute("DELETE FROM disqualifications")
        conn.execute("INSERT INTO settings(key, value) VALUES ('phase', 'hardening') ON CONFLICT(key) DO UPDATE SET value = 'hardening'")


def last_heartbeat(team: str) -> sqlite3.Row | None:
    with db() as conn:
        return conn.execute("SELECT * FROM heartbeats WHERE team = ?", (team,)).fetchone()


def record_server_down_penalties() -> None:
    if phase() != "live":
        return
    scoring = scoring_config()
    window_seconds = max(60, int(scoring.get("server_down_penalty_window_seconds", 600)))
    points = int(scoring.get("server_down_penalty_points", 10))
    if points <= 0:
        return
    window = int(now() // window_seconds)
    current = now()
    dq = set(disqualified_teams())
    with DB_LOCK, db() as conn:
        for team in teams():
            if team in dq:
                continue
            heartbeat = conn.execute("SELECT received_at FROM heartbeats WHERE team = ?", (team,)).fetchone()
            connected = bool(heartbeat and current - heartbeat["received_at"] <= HEARTBEAT_TIMEOUT_SECONDS)
            if connected:
                continue
            cursor = conn.execute(
                "INSERT OR IGNORE INTO server_down_penalties(team, window, points, created_at) VALUES (?, ?, ?, ?)",
                (team, window, points, current),
            )
            if cursor.rowcount:
                conn.execute(
                    "INSERT INTO penalties(team, reason, points, created_at) VALUES (?, ?, ?, ?)",
                    (team, f"server down or unreachable during live window {window}", points, current),
                )


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
                record_server_down_penalties()
        except Exception as exc:
            print(f"checker error: {exc}")
        time.sleep(CHECKER_INTERVAL_SECONDS)


def page(title: str, body: str, status: int = 200, area: str = "admin") -> tuple[int, str, str]:
    if area == "team":
        nav = """
      <a href="/team">Team Home</a>
      <a href="/team/submit">Submit Flag</a>
      <a href="/scoreboard">Scoreboard</a>
      <a href="/team/logout">Logout</a>
        """
        brand = "FindTheFlag Team Portal"
    else:
        nav = """
      <a href="/admin">Dashboard</a>
      <a href="/admin/setup">Setup Guide</a>
      <a href="/admin/teams">Teams</a>
      <a href="/admin/flags">Flags</a>
      <a href="/admin/submissions">Submissions</a>
      <a href="/admin/scoring">Scoring</a>
      <a href="/admin/penalties">Penalties</a>
      <a href="/admin/export">Export</a>
      <a href="/scoreboard">Public Scoreboard</a>
        """
        brand = "Distributed FindTheFlag Admin"
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
    input[type="checkbox"] {{ width:auto; }}
    label {{ display:block; font-weight:700; margin:10px 0 5px; }}
    button,.button {{ display:inline-flex; background:#176b87; color:white; border:0; border-radius:6px; padding:9px 12px; font-weight:700; text-decoration:none; cursor:pointer; }}
    .secondary {{ background:#e5edf2; color:#173447; }}
    .danger {{ background:#c6532f; }}
    .row {{ display:flex; gap:10px; flex-wrap:wrap; align-items:end; }}
    .row > * {{ flex:1 1 160px; }}
    .ok {{ color:#247a45; font-weight:700; }}
    .bad {{ color:#b42318; font-weight:700; }}
    .muted {{ color:#637083; }}
    .step {{ display:flex; gap:12px; align-items:flex-start; }}
    .step-num {{ width:28px; height:28px; border-radius:50%; background:#176b87; color:white; display:inline-flex; align-items:center; justify-content:center; font-weight:800; flex:0 0 auto; }}
    .pill {{ display:inline-flex; border:1px solid #cbd6df; border-radius:999px; padding:3px 8px; font-size:12px; background:#f7fafc; margin:2px; }}
    .empty {{ color:#637083; padding:18px; text-align:center; }}
    code,pre {{ font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }}
    pre {{ background:#101827; color:#d8f3ff; padding:12px; border-radius:6px; overflow:auto; }}
  </style>
</head>
<body>
  <header>
    <strong>{esc(brand)}</strong>
    <nav>
      {nav}
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


def error_page(
    title: str,
    message: str,
    status: int = 404,
    action_href: str = "/admin",
    action_label: str = "Back to dashboard",
    area: str = "admin",
) -> tuple[int, str, str]:
    return page(
        title,
        f"""
        <h1>{esc(title)}</h1>
        <div class="card">
          <p>{esc(message)}</p>
          <p><a class="button" href="{esc(action_href)}">{esc(action_label)}</a></p>
        </div>
        """,
        status,
        area=area,
    )


def setup_progress() -> dict[str, Any]:
    team_count = len(teams())
    selected = selected_services()
    package_dir = BASE_DIR / "generated" / "team_packages"
    package_count = len([item for item in package_dir.iterdir() if item.is_dir()]) if package_dir.exists() else 0
    return {
        "team_count": team_count,
        "selected_services": selected,
        "package_count": package_count,
        "phase": phase(),
    }


def setup_guide_page(message: str = "") -> tuple[int, str, str]:
    progress = setup_progress()
    team_ok = progress["team_count"] > 0
    package_ok = progress["package_count"] >= progress["team_count"] > 0
    service_pills = "".join(f"<span class='pill'>{esc(service)}</span>" for service in progress["selected_services"])
    return page(
        "Setup Guide",
        f"""
        <h1>Competition Setup Guide</h1>
        <div class="notice">Follow these steps before opening the live attack-defense phase. Current phase: <strong>{esc(progress['phase'])}</strong>.</div>
        {'<div class="notice ok">' + esc(message) + '</div>' if message else ''}
        <div class="grid">
          <div class="card step">
            <span class="step-num">1</span>
            <div>
              <h2>Create teams</h2>
              <p>{'Ready' if team_ok else 'No teams yet'}: <strong>{progress['team_count']}</strong> team(s).</p>
              <p><a class="button" href="/admin/teams">Open teams</a></p>
            </div>
          </div>
          <div class="card step">
            <span class="step-num">2</span>
            <div>
              <h2>Select services</h2>
              <p>Enabled services:</p>
              <p>{service_pills or '<span class="muted">No services selected.</span>'}</p>
              <p><a class="button secondary" href="/admin/teams">Choose challenge set</a></p>
            </div>
          </div>
          <div class="card step">
            <span class="step-num">3</span>
            <div>
              <h2>Generate packages</h2>
              <p>{'Ready' if package_ok else 'Packages not ready'}: <strong>{progress['package_count']}</strong> package(s).</p>
              <p>Give each team only its own folder from <code>{esc(BASE_DIR / 'generated' / 'team_packages')}</code>.</p>
            </div>
          </div>
          <div class="card step">
            <span class="step-num">4</span>
            <div>
              <h2>Run phases</h2>
              <p>Use hardening for the offline window, then live for attack-defense scoring.</p>
              <form method="post" action="/admin/phase" class="row">
                <button name="phase" value="hardening" class="secondary">Start hardening</button>
                <button name="phase" value="live">Start live</button>
              </form>
            </div>
          </div>
        </div>
        <div class="card">
          <h2>Operator checklist</h2>
          <p><span class="pill">Admin stays private</span><span class="pill">Teams receive own package only</span><span class="pill">No network between teams during hardening</span><span class="pill">Team servers connect to admin during live</span></p>
        </div>
        """,
    )


def dashboard_page() -> tuple[int, str, str]:
    rows = "".join(
        f"<tr><td>{esc(row['team'])}</td><td>{row['attack']}</td><td>{row['availability']}</td><td>{row['integrity']}</td><td>{row['penalty']}</td><td><strong>{row['total']}</strong></td><td class=\"{'bad' if row['disqualified'] else 'ok'}\">{'DQ: ' + esc(row['disqualification_reason']) if row['disqualified'] else 'active'}</td><td class=\"{'ok' if row['connected'] else 'bad'}\">{'connected' if row['connected'] else 'missing'}</td></tr>"
        for row in scoreboard()
    ) or "<tr><td colspan='8' class='empty'>No teams yet. Start with Setup Guide or Teams.</td></tr>"
    progress = setup_progress()
    return page(
        "Dashboard",
        f"""
        <h1>Dashboard</h1>
        <div class="notice">Phase: <strong>{esc(phase())}</strong> | Round: <strong>{current_round()}</strong> | Next flags in: <strong>{round_remaining()}s</strong></div>
        <div class="grid">
          <div class="card"><h2>Teams</h2><p><strong>{progress['team_count']}</strong> configured</p><p><a class="button secondary" href="/admin/teams">Manage teams</a></p></div>
          <div class="card"><h2>Packages</h2><p><strong>{progress['package_count']}</strong> generated</p><p><a class="button secondary" href="/admin/setup">Setup guide</a></p></div>
          <div class="card"><h2>Services</h2><p><strong>{len(progress['selected_services'])}</strong> enabled</p><p><a class="button secondary" href="/admin/teams">Choose services</a></p></div>
        </div>
        <div class="card">
          <h2>Phase Control</h2>
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
        <table><thead><tr><th>Team</th><th>Attack</th><th>Availability</th><th>Integrity</th><th>Penalty</th><th>Total</th><th>Rule Status</th><th>Heartbeat</th></tr></thead><tbody>{rows}</tbody></table>
        """,
    )


def public_scoreboard_page() -> tuple[int, str, str]:
    rows = "".join(
        f"<tr><td>{esc(row['team'])}</td><td>{row['attack']}</td><td>{row['availability']}</td><td>{row['integrity']}</td><td>{row['penalty']}</td><td><strong>{row['total']}</strong></td><td class=\"{'bad' if row['disqualified'] else 'ok'}\">{'DQ' if row['disqualified'] else 'active'}</td><td class=\"{'ok' if row['connected'] else 'bad'}\">{'connected' if row['connected'] else 'missing'}</td></tr>"
        for row in scoreboard()
    )
    return page(
        "Scoreboard",
        f"""
        <h1>Scoreboard</h1>
        <div class="notice">Phase: <strong>{esc(phase())}</strong> | Round: <strong>{current_round()}</strong> | Next flags in: <strong>{round_remaining()}s</strong></div>
        <table><thead><tr><th>Team</th><th>Attack</th><th>Availability</th><th>Integrity</th><th>Penalty</th><th>Total</th><th>Rule Status</th><th>Heartbeat</th></tr></thead><tbody>{rows}</tbody></table>
        <script>setTimeout(() => location.reload(), 5000);</script>
        """,
    )


def team_login_page(message: str = "") -> tuple[int, str, str]:
    team_options = "".join(f"<option value='{esc(team)}'>{esc(team)}</option>" for team in teams())
    if not team_options:
        team_options = "<option value=''>No teams configured yet</option>"
    return page(
        "Team Login",
        f"""
        <h1>Team Login</h1>
        <div class="notice">Use the Team ID and Team Secret from your team package. This portal is where teams submit stolen flags during live phase.</div>
        <div class="card">
          <form method="post" action="/team/login">
            <label>Team</label>
            <select name="team">{team_options}</select>
            <label>Team Secret</label>
            <input type="password" name="secret" autocomplete="current-password">
            <button>Login</button>
          </form>
          {'<p class="bad">' + esc(message) + '</p>' if message else ''}
        </div>
        """,
        area="team",
    )


def team_score(team: str) -> dict[str, Any]:
    for row in scoreboard():
        if row["team"] == team:
            return row
    return {"team": team, "attack": 0, "availability": 0, "integrity": 0, "penalty": 0, "connected": False, "total": 0}


def team_recent_submissions(team: str) -> str:
    with db() as conn:
        rows = conn.execute(
            "SELECT victim, service, round, flag, points, created_at FROM submissions WHERE attacker = ? ORDER BY created_at DESC LIMIT 20",
            (team,),
        ).fetchall()
    return "".join(
        f"<tr><td>{esc(row['victim'])}</td><td>{esc(row['service'])}</td><td>{row['round']}</td><td><code>{esc(row['flag'])}</code></td><td>+{row['points']}</td><td>{time.strftime('%H:%M:%S', time.localtime(row['created_at']))}</td></tr>"
        for row in rows
    ) or "<tr><td colspan='6' class='empty'>No accepted submissions yet.</td></tr>"


def team_home_page(team: str, message: str = "") -> tuple[int, str, str]:
    cfg = teams()[team]
    hb = last_heartbeat(team)
    hb_text = "never" if not hb else f"{int(now() - hb['received_at'])}s ago"
    score = team_score(team)
    rules = rule_status(team)
    admin_warnings = rules["violations"].get("admin_attack", 0)
    infra_warnings = rules["violations"].get("infra_file_control", 0)
    services = "".join(f"<span class='pill'>{esc(service)}</span>" for service in selected_services())
    return page(
        "Team Home",
        f"""
        <h1>Team {esc(team)}</h1>
        <div class="notice">Phase: <strong>{esc(phase())}</strong> | Round: <strong>{current_round()}</strong> | Next flags in: <strong>{round_remaining()}s</strong></div>
        {'<div class="notice ok">' + esc(message) + '</div>' if message else ''}
        <div class="grid">
          <div class="card"><h2>Total</h2><p><strong>{score['total']}</strong></p></div>
          <div class="card"><h2>Attack</h2><p><strong>{score['attack']}</strong></p></div>
          <div class="card"><h2>Availability</h2><p><strong>{score['availability']}</strong></p></div>
          <div class="card"><h2>Integrity</h2><p><strong>{score['integrity']}</strong></p></div>
          <div class="card"><h2>Penalty</h2><p><strong>-{score['penalty']}</strong></p></div>
          <div class="card"><h2>Heartbeat</h2><p class="{'ok' if score['connected'] else 'bad'}">{'connected' if score['connected'] else 'missing'}</p><p class="muted">{esc(hb_text)}</p></div>
          <div class="card"><h2>Rule Status</h2><p class="{'bad' if rules['disqualified'] else 'ok'}">{'DQ: ' + esc(rules['disqualification_reason']) if rules['disqualified'] else 'active'}</p><p class="muted">Admin warnings: {admin_warnings}; Infra warnings: {infra_warnings}</p></div>
        </div>
        <div class="card">
          <h2>Submit Stolen Flag</h2>
          <form method="post" action="/team/submit" class="row">
            <div style="flex:3 1 420px"><label>Flag</label><input name="flag" placeholder="FTF{{victim_service_round_digest}}"></div>
            <div><button>Submit flag</button></div>
          </form>
          <p class="muted">Submissions only score during live phase. Self flags do not score.</p>
        </div>
        <div class="card">
          <h2>Your Team Server</h2>
          <p><a class="button" href="{esc(cfg.get('public_base_url', ''))}">Open own target</a> <a class="button secondary" href="/scoreboard">Open scoreboard</a></p>
          <p>Enabled services: {services or '<span class="muted">No services selected.</span>'}</p>
        </div>
        <h2>Recent Accepted Submissions</h2>
        <table><thead><tr><th>Victim</th><th>Service</th><th>Round</th><th>Flag</th><th>Points</th><th>Time</th></tr></thead><tbody>{team_recent_submissions(team)}</tbody></table>
        """,
        area="team",
    )


def team_submit_page(team: str, message: str = "", ok: bool = False) -> tuple[int, str, str]:
    return page(
        "Submit Flag",
        f"""
        <h1>Submit Flag</h1>
        <div class="notice">Logged in as <strong>{esc(team)}</strong>. Paste a flag stolen from another team's service.</div>
        {'<div class="notice ' + ('ok' if ok else 'bad') + '">' + esc(message) + '</div>' if message else ''}
        <div class="card">
          <form method="post" action="/team/submit">
            <label>Stolen flag</label>
            <input name="flag" placeholder="FTF{{victim_service_round_digest}}" autofocus>
            <button>Submit flag</button>
          </form>
        </div>
        <h2>Recent Accepted Submissions</h2>
        <table><thead><tr><th>Victim</th><th>Service</th><th>Round</th><th>Flag</th><th>Points</th><th>Time</th></tr></thead><tbody>{team_recent_submissions(team)}</tbody></table>
        """,
        area="team",
    )


def teams_page() -> tuple[int, str, str]:
    rows = []
    enabled = set(selected_services())
    package_dir = BASE_DIR / "generated" / "team_packages"
    package_count = len([item for item in package_dir.iterdir() if item.is_dir()]) if package_dir.exists() else 0
    service_checks = "".join(
        f"""
        <label class="card" style="display:block">
          <input type="checkbox" name="services" value="{esc(key)}" {'checked' if key in enabled else ''}>
          <strong>{esc(meta['name'])}</strong> <span class="pill">{esc(meta['category'])}</span>
          <p class="muted">{esc(meta['description'])}</p>
        </label>
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
        <div class="notice">Create teams first, choose the challenge services, then generate packages. Give each team its Team ID and Team Secret; the same secret logs into <code>/team/login</code>. Generated packages: <strong>{package_count}</strong>.</div>
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
              <div class="grid">{service_checks}</div>
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
    ) or "<tr><td colspan='5' class='empty'>No flag reports yet. They appear after teams run their servers in live phase or after the checker succeeds.</td></tr>"
    return page(
        "Flags",
        f"""
        <h1>Flag Reports</h1>
        <div class="notice">Use this page as the operator answer table. During live, each team/service/round should appear here.</div>
        <table><thead><tr><th>Team</th><th>Service</th><th>Round</th><th>Flag</th><th>Received</th></tr></thead><tbody>{body_rows}</tbody></table>
        """,
    )


def submissions_page() -> tuple[int, str, str]:
    with db() as conn:
        rows = conn.execute("SELECT attacker, victim, service, round, flag, points, created_at FROM submissions ORDER BY created_at DESC LIMIT 200").fetchall()
    body_rows = "".join(
        f"<tr><td>{esc(row['attacker'])}</td><td>{esc(row['victim'])}</td><td>{esc(row['service'])}</td><td>{row['round']}</td><td><code>{esc(row['flag'])}</code></td><td>+{row['points']}</td><td>{time.strftime('%H:%M:%S', time.localtime(row['created_at']))}</td></tr>"
        for row in rows
    ) or "<tr><td colspan='7' class='empty'>No submissions yet. Teams can submit stolen flags only after the phase is live.</td></tr>"
    return page(
        "Submissions",
        f"""
        <h1>Submissions</h1>
        <div class="notice">Accepted attack submissions are listed here. Duplicate attacker/victim/service/round submissions do not score twice.</div>
        <table><thead><tr><th>Attacker</th><th>Victim</th><th>Service</th><th>Round</th><th>Flag</th><th>Points</th><th>Time</th></tr></thead><tbody>{body_rows}</tbody></table>
        """,
    )


def scoring_page(message: str = "") -> tuple[int, str, str]:
    cfg = scoring_config()
    inputs = "".join(
        f"<label>{esc(key)}</label><input type='number' min='0' name='{esc(key)}' value='{value}'>"
        for key, value in cfg.items()
    )
    return page(
        "Scoring",
        f"""
        <h1>Scoring</h1>
        <div class="notice">Adjust these values before the match starts. Changes apply to future scoring decisions and manual penalties.</div>
        <div class="card"><form method="post" action="/admin/scoring">{inputs}<button>Save scoring</button></form>{'<p class="ok">' + esc(message) + '</p>' if message else ''}</div>
        """,
    )


def penalties_page(message: str = "") -> tuple[int, str, str]:
    team_options = "".join(f"<option value='{esc(team)}'>{esc(team)}</option>" for team in teams())
    with db() as conn:
        rows = conn.execute("SELECT team, reason, points, created_at FROM penalties ORDER BY created_at DESC LIMIT 200").fetchall()
        violation_rows = conn.execute("SELECT team, kind, severity, note, created_at FROM violation_events ORDER BY created_at DESC LIMIT 200").fetchall()
        dq_rows = conn.execute("SELECT team, reason, created_at FROM disqualifications ORDER BY created_at DESC").fetchall()
    body_rows = "".join(
        f"<tr><td>{esc(row['team'])}</td><td>{esc(row['reason'])}</td><td>-{row['points']}</td><td>{time.strftime('%H:%M:%S', time.localtime(row['created_at']))}</td></tr>"
        for row in rows
    ) or "<tr><td colspan='4' class='empty'>No penalties. Manual penalties for admin/infrastructure attacks will appear here.</td></tr>"
    violation_body = "".join(
        f"<tr><td>{esc(row['team'])}</td><td>{esc(row['kind'])}</td><td>{esc(row['severity'])}</td><td>{esc(row['note'])}</td><td>{time.strftime('%H:%M:%S', time.localtime(row['created_at']))}</td></tr>"
        for row in violation_rows
    ) or "<tr><td colspan='5' class='empty'>No rule warnings yet.</td></tr>"
    dq_body = "".join(
        f"<tr><td>{esc(row['team'])}</td><td>{esc(row['reason'])}</td><td>{time.strftime('%H:%M:%S', time.localtime(row['created_at']))}</td></tr>"
        for row in dq_rows
    ) or "<tr><td colspan='3' class='empty'>No disqualified teams.</td></tr>"
    return page(
        "Penalties",
        f"""
        <h1>Penalties</h1>
        <div class="notice">Rules: server down/unreachable during live is -{scoring_config()['server_down_penalty_points']} every {scoring_config()['server_down_penalty_window_seconds']} seconds. Admin-page attack: first warning, second DQ. Host/file-control attack: warning.</div>
        <div class="card">
          <h2>Manual Score Penalty</h2>
          <form method="post" action="/admin/penalties" class="row">
            <input type="hidden" name="action" value="penalty">
            <div><label>Team</label><select name="team">{team_options}</select></div>
            <div><label>Points</label><input type="number" min="1" name="points" value="{scoring_config()['infra_attack_penalty']}"></div>
            <div><label>Reason</label><input name="reason" placeholder="admin page attack"></div>
            <div><button class="danger">Add penalty</button></div>
          </form>
          {'<p class="ok">' + esc(message) + '</p>' if message else ''}
        </div>
        <div class="card">
          <h2>Rule Warning / DQ</h2>
          <form method="post" action="/admin/penalties" class="row">
            <input type="hidden" name="action" value="violation">
            <div><label>Team</label><select name="team">{team_options}</select></div>
            <div><label>Violation</label><select name="kind">
              <option value="admin_attack">Admin page/API attack</option>
              <option value="infra_file_control">Path traversal / host file-control attack</option>
            </select></div>
            <div><label>Note</label><input name="note" placeholder="evidence or URL"></div>
            <div><button>Record warning</button></div>
          </form>
        </div>
        <h2>Disqualifications</h2>
        <table><thead><tr><th>Team</th><th>Reason</th><th>Time</th></tr></thead><tbody>{dq_body}</tbody></table>
        <h2>Rule Warnings</h2>
        <table><thead><tr><th>Team</th><th>Kind</th><th>Severity</th><th>Note</th><th>Time</th></tr></thead><tbody>{violation_body}</tbody></table>
        <h2>Score Penalties</h2>
        <table><thead><tr><th>Team</th><th>Reason</th><th>Points</th><th>Time</th></tr></thead><tbody>{body_rows}</tbody></table>
        """,
    )


def export_state() -> dict[str, Any]:
    with db() as conn:
        flag_rows = conn.execute("SELECT team, service, round, flag, received_at FROM flag_reports ORDER BY round, team, service").fetchall()
        submission_rows = conn.execute("SELECT attacker, victim, service, round, flag, points, created_at FROM submissions ORDER BY created_at").fetchall()
        penalty_rows = conn.execute("SELECT team, reason, points, created_at FROM penalties ORDER BY created_at").fetchall()
        server_down_rows = conn.execute("SELECT team, window, points, created_at FROM server_down_penalties ORDER BY created_at").fetchall()
        violation_rows = conn.execute("SELECT team, kind, severity, note, created_at FROM violation_events ORDER BY created_at").fetchall()
        dq_rows = conn.execute("SELECT team, reason, created_at FROM disqualifications ORDER BY created_at").fetchall()
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
        "server_down_penalties": [dict(row) for row in server_down_rows],
        "violations": [dict(row) for row in violation_rows],
        "disqualifications": [dict(row) for row in dq_rows],
    }


def export_page() -> tuple[int, str, str]:
    state = export_state()
    return page(
        "Export",
        f"""
        <h1>Export</h1>
        <div class="notice">This page summarizes the match export without showing raw JSON. Use the download link when you need the machine-readable file.</div>
        <div class="grid">
          <div class="card"><h2>Phase</h2><p><strong>{esc(state['phase'])}</strong></p></div>
          <div class="card"><h2>Round</h2><p><strong>{state['round']}</strong></p></div>
          <div class="card"><h2>Teams</h2><p><strong>{len(state['scoreboard'])}</strong></p></div>
          <div class="card"><h2>Services</h2><p><strong>{len(state['services'])}</strong></p></div>
          <div class="card"><h2>Flags</h2><p><strong>{len(state['flags'])}</strong></p></div>
          <div class="card"><h2>Submissions</h2><p><strong>{len(state['submissions'])}</strong></p></div>
          <div class="card"><h2>Warnings</h2><p><strong>{len(state['violations'])}</strong></p></div>
          <div class="card"><h2>Disqualified</h2><p><strong>{len(state['disqualifications'])}</strong></p></div>
        </div>
        <div class="card">
          <h2>Download</h2>
          <p><a class="button" href="/admin/export.json">Download JSON export</a></p>
        </div>
        """,
    )


def api_landing_page() -> tuple[int, str, str]:
    return page(
        "API",
        """
        <h1>API Status</h1>
        <div class="notice">These endpoints are for team servers and submit helpers. Browser users should normally use the admin pages.</div>
        <div class="grid">
          <div class="card"><h2>GET /api/state</h2><p>Current phase, round, services, and scoreboard. Add <code>?format=json</code> for raw JSON.</p></div>
          <div class="card"><h2>POST /api/team/heartbeat</h2><p>Signed team heartbeat endpoint.</p></div>
          <div class="card"><h2>POST /api/team/flags</h2><p>Signed team flag report endpoint.</p></div>
          <div class="card"><h2>POST /api/submit</h2><p>Signed stolen-flag submission endpoint.</p></div>
        </div>
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
    if is_disqualified(attacker):
        return 403, {"ok": False, "message": "team is disqualified and cannot submit flags"}
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

    def current_team(self) -> str | None:
        return valid_team_session(parse_cookies(self.headers.get("cookie")).get("team_session", ""))

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

    def wants_json(self, parsed: urllib.parse.ParseResult) -> bool:
        query = urllib.parse.parse_qs(parsed.query)
        accept = self.headers.get("Accept", "")
        return query.get("format", [""])[0] == "json" or "application/json" in accept

    def require_admin(self, path: str = "/admin") -> bool:
        if self.is_admin():
            return True
        team = self.current_team()
        if team:
            count = record_violation(team, "admin_attack", f"accessed {path}")
            if count >= 2:
                self.respond(error_page("Disqualified", "Your team accessed the admin area a second time and is disqualified.", HTTPStatus.FORBIDDEN, "/team", "Back to team home", area="team"))
            else:
                self.respond(error_page("Admin Area Warning", "This is the admin console. Your team has received one warning; a second admin-page/API attack causes disqualification.", HTTPStatus.FORBIDDEN, "/team", "Back to team home", area="team"))
            return False
        self.respond(login_page("Login required."))
        return False

    def require_team(self) -> str | None:
        team = self.current_team()
        if team:
            return team
        self.respond(team_login_page("Login required."))
        return None

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        if path == "/":
            return self.redirect("/team/login")
        if path == "/api/state":
            if self.wants_json(parsed):
                return self.send_json(200, api_state())
            return self.respond(api_landing_page())
        if path.startswith("/api"):
            return self.respond(api_landing_page())
        if path == "/scoreboard":
            return self.respond(public_scoreboard_page())
        if path == "/team/login":
            return self.respond(team_login_page())
        if path == "/team/logout":
            return self.redirect("/team/login", ["team_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"])
        if path == "/team":
            team = self.require_team()
            if not team:
                return
            return self.respond(team_home_page(team))
        if path == "/team/submit":
            team = self.require_team()
            if not team:
                return
            return self.respond(team_submit_page(team))
        if path.startswith("/team"):
            team = self.require_team()
            if not team:
                return
            return self.respond(error_page("Team page not found", "Use Team Home or Submit Flag to continue.", HTTPStatus.NOT_FOUND, "/team", "Back to team home", area="team"))
        if path == "/admin/login":
            return self.respond(login_page())
        if path.startswith("/admin") and not self.require_admin(path):
            return
        if path == "/admin":
            return self.respond(dashboard_page())
        if path == "/admin/setup":
            return self.respond(setup_guide_page())
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
            return self.respond(export_page())
        if path == "/admin/export.json":
            return self.send_json(200, export_state())
        return self.respond(error_page("Page not found", "That page is not part of the competition console. Use the navigation links above to continue.", HTTPStatus.NOT_FOUND))

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        body = self.read_body()
        headers = self.headers_map()
        if path == "/team/login":
            payload = parse_body(headers, body)
            team = str(payload.get("team", "")).strip().lower()
            secret = str(payload.get("secret", ""))
            cfg = teams().get(team)
            if cfg and hmac.compare_digest(secret, cfg["secret"]):
                return self.redirect("/team", [f"team_session={sign_team_session(team)}; Path=/; HttpOnly; SameSite=Lax"])
            return self.respond(team_login_page("Team or secret incorrect."))
        if path == "/team/submit":
            team = self.require_team()
            if not team:
                return
            payload = parse_body(headers, body)
            status, response = submit_flag(team, str(payload.get("flag", "")))
            ok = bool(response.get("ok")) and status < 400
            return self.respond(team_submit_page(team, str(response.get("message", "Submitted.")), ok=ok))
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
        if path.startswith("/admin") and not self.require_admin(path):
            return
        if path == "/admin/phase":
            payload = parse_body(headers, body)
            value = str(payload.get("phase", ""))
            if value not in PHASES:
                return self.respond(error_page("Bad phase", "Choose one of setup, hardening, live, or ended.", HTTPStatus.BAD_REQUEST))
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
                return self.respond(error_page("Unknown team", "Create the team first, then add a manual penalty.", HTTPStatus.BAD_REQUEST, "/admin/penalties", "Back to penalties"))
            action = str(payload.get("action", "penalty"))
            if action == "violation":
                kind = str(payload.get("kind", ""))
                if kind not in {"admin_attack", "infra_file_control"}:
                    return self.respond(error_page("Bad violation", "Choose admin attack or host/file-control attack.", HTTPStatus.BAD_REQUEST, "/admin/penalties", "Back to penalties"))
                default_note = "admin page/API attack" if kind == "admin_attack" else "path traversal or host file-control attack"
                note = str(payload.get("note", "")).strip() or default_note
                count = record_violation(team, kind, note)
                if kind == "admin_attack" and count >= 2:
                    return self.respond(penalties_page(f"{team} disqualified for second admin-page attack."))
                return self.respond(penalties_page(f"Warning recorded for {team}."))
            try:
                points = max(1, int(str(payload.get("points", "0"))))
            except ValueError:
                return self.respond(error_page("Bad points", "Penalty points must be a positive integer.", HTTPStatus.BAD_REQUEST, "/admin/penalties", "Back to penalties"))
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
                    return self.respond(error_page("Bad team ID", "Use lowercase letters, digits, and hyphen only; length 2-32. Do not use underscores.", HTTPStatus.BAD_REQUEST, "/admin/teams", "Back to teams"))
                if team in data:
                    return self.respond(error_page("Team already exists", "Choose a different team ID or update the existing team's public URL.", HTTPStatus.CONFLICT, "/admin/teams", "Back to teams"))
                data[team] = {
                    "secret": generate_secret(),
                    "public_base_url": str(payload.get("public_base_url", "")),
                }
                save_teams(data)
                return self.redirect("/admin/teams")
            if action == "update":
                if team not in data:
                    return self.respond(error_page("Unknown team", "The team no longer exists. Refresh the teams page and try again.", HTTPStatus.NOT_FOUND, "/admin/teams", "Back to teams"))
                data[team]["public_base_url"] = str(payload.get("public_base_url", ""))
                save_teams(data)
                return self.redirect("/admin/teams")
            if action == "rotate":
                if team not in data:
                    return self.respond(error_page("Unknown team", "The team no longer exists. Refresh the teams page and try again.", HTTPStatus.NOT_FOUND, "/admin/teams", "Back to teams"))
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
            return self.respond(error_page("Bad team action", "The submitted form action was not recognized. Return to Teams and try again.", HTTPStatus.BAD_REQUEST, "/admin/teams", "Back to teams"))
        return self.respond(error_page("Page not found", "That action is not part of the competition console.", HTTPStatus.NOT_FOUND))


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
