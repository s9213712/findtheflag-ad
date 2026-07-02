#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import urllib.parse


BASE_DIR = Path(__file__).resolve().parent
TEAMS_PATH = BASE_DIR / "configs" / "teams.json"
DB_PATH = BASE_DIR / "data" / "distributed_admin.sqlite3"
SERVICE_CATALOG = {
    "default",
    "token",
    "shop",
    "memo",
    "archive",
    "vault",
    "cipher",
    "proxy",
    "waf",
    "supply",
    "edge",
    "media",
    "agent",
    "saml",
    "hook",
    "ledger",
}
ROUND_SECONDS = int(os.environ.get("FTF_ROUND_SECONDS", "300"))
HEARTBEAT_INTERVAL_SECONDS = int(os.environ.get("FTF_TEAM_HEARTBEAT_INTERVAL_SECONDS", "30"))
ADMIN_TIMEOUT_SECONDS = int(os.environ.get("FTF_TEAM_ADMIN_TIMEOUT_SECONDS", "3"))


def selected_services() -> list[str]:
    if DB_PATH.exists():
        conn = sqlite3.connect(DB_PATH)
        row = conn.execute("SELECT value FROM settings WHERE key = 'selected_services'").fetchone()
        conn.close()
        if row:
            services = [service for service in row[0].split(",") if service in SERVICE_CATALOG]
            if services:
                return services
    return ["default"]


def listen_endpoint(public_base_url: str, fallback_port: int) -> tuple[str, int]:
    parsed = urllib.parse.urlparse(public_base_url)
    if parsed.hostname and parsed.port:
        return parsed.hostname, parsed.port
    return "127.0.0.1", fallback_port


def main() -> None:
    teams = json.loads(TEAMS_PATH.read_text(encoding="utf-8"))
    services = selected_services()
    for stale in (BASE_DIR / "configs").glob("*.team_config.json"):
        stale.unlink()
    for index, (team, cfg) in enumerate(teams.items()):
        path = BASE_DIR / "configs" / f"{team}.team_config.json"
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
            "heartbeat_interval_seconds": HEARTBEAT_INTERVAL_SECONDS,
            "admin_timeout_seconds": ADMIN_TIMEOUT_SECONDS,
            "services": services,
        }
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(path)


if __name__ == "__main__":
    main()
