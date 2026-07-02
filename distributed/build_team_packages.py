#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import urllib.parse
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
CONFIG_DIR = BASE_DIR / "configs"
OUTPUT_DIR = BASE_DIR / "generated" / "team_packages"
TEAMS_PATH = CONFIG_DIR / "teams.json"
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


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def team_readme(team: str, config: dict[str, object]) -> str:
    public_url = str(config["public_base_url"])
    admin_url = str(config["admin_url"])
    return f"""# Team Package: {team}

這是 `{team}` 隊的初始化部署資料。不要把這包交給其他隊。

## Files

- `team_server.py`：隊伍靶機伺服器，四隊程式完全相同。
- `submit_flag.py`：提交 stolen flag 的工具。
- `team_config.json`：本隊專屬設定，包含 `TEAM_ID` 與 `TEAM_SECRET`。
- `public/index.html`：給隊員看的本地起始頁。

## Start During Hardening

```bash
cd this-package
FTF_TEAM_CONFIG=team_config.json python3 team_server.py
```

隊伍本機入口：

```text
{public_url}
```

管理員伺服器：

```text
{admin_url}
```

## Submit A Flag During Live

```bash
FTF_TEAM_CONFIG=team_config.json python3 submit_flag.py 'FTF{{victim_service_round_digest}}'
```

## Rules

- Hardening 前 30 分鐘可離線修改與強化自己的服務。
- 不能刪除 flag 產生、回報、heartbeat 或 checker 需要的正常功能。
- Live 後必須維持 team server 連到 admin server。
- 每 5 分鐘會更新一輪 flag。
- 同一漏洞若沒修，每輪都可能被其他隊重複拿分。
"""


def starter_html(team: str, config: dict[str, object]) -> str:
    public_url = str(config["public_base_url"])
    admin_url = str(config["admin_url"])
    return f"""<!doctype html>
<html lang="zh-Hant">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FindTheFlag Team {team}</title>
  <style>
    body {{
      margin: 0;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f5f7fa;
      color: #17212b;
    }}
    header {{
      background: #102631;
      color: white;
      padding: 18px 22px;
      border-bottom: 4px solid #d8a331;
    }}
    main {{
      max-width: 900px;
      margin: 0 auto;
      padding: 22px;
    }}
    .card {{
      background: white;
      border: 1px solid #d9e0e8;
      border-radius: 8px;
      padding: 16px;
      margin: 14px 0;
    }}
    code, pre {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }}
    pre {{
      background: #101827;
      color: #d8f3ff;
      padding: 12px;
      border-radius: 6px;
      overflow: auto;
    }}
    a.button {{
      display: inline-flex;
      background: #176b87;
      color: white;
      text-decoration: none;
      border-radius: 6px;
      padding: 9px 12px;
      font-weight: 700;
    }}
  </style>
</head>
<body>
  <header>
    <strong>FindTheFlag Team Package: {team}</strong>
  </header>
  <main>
    <div class="card">
      <h1>{team} Initialization</h1>
      <p>這頁是給隊伍 hardening 階段使用的起始資料。正式攻防入口是你啟動的 team server。</p>
      <p><a class="button" href="{public_url}">Open Team Server</a></p>
    </div>

    <div class="card">
      <h2>Start Server</h2>
      <pre>FTF_TEAM_CONFIG=team_config.json python3 team_server.py</pre>
    </div>

    <div class="card">
      <h2>Endpoints</h2>
      <p>Team server: <code>{public_url}</code></p>
      <p>Admin server: <code>{admin_url}</code></p>
    </div>

    <div class="card">
      <h2>Submit During Live</h2>
      <pre>FTF_TEAM_CONFIG=team_config.json python3 submit_flag.py 'FTF{{...}}'</pre>
    </div>
  </main>
</body>
</html>
"""


def build_package(team: str) -> None:
    config_path = CONFIG_DIR / f"{team}.team_config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    package_dir = OUTPUT_DIR / team
    package_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy2(BASE_DIR / "team_server.py", package_dir / "team_server.py")
    shutil.copy2(BASE_DIR / "submit_flag.py", package_dir / "submit_flag.py")
    (package_dir / "submit_flag.py").chmod(0o755)
    shutil.copy2(config_path, package_dir / "team_config.json")

    write_text(package_dir / "README.md", team_readme(team, config))
    write_text(package_dir / "public" / "index.html", starter_html(team, config))


def main() -> None:
    teams_data = json.loads(TEAMS_PATH.read_text(encoding="utf-8"))
    services = selected_services()
    if OUTPUT_DIR.exists():
        shutil.rmtree(OUTPUT_DIR)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for stale in CONFIG_DIR.glob("*.team_config.json"):
        stale.unlink()
    for index, (team, cfg) in enumerate(teams_data.items()):
        fallback_port = 9100 + index
        public_base_url = cfg.get("public_base_url") or f"http://127.0.0.1:{fallback_port}"
        host, port = listen_endpoint(public_base_url, fallback_port)
        config = {
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
        (CONFIG_DIR / f"{team}.team_config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    teams = sorted(teams_data)
    if not teams:
        raise SystemExit("No teams found. Create teams in configs/teams.json or through the admin UI first.")
    for team in teams:
        build_package(team)
        print(OUTPUT_DIR / team)


if __name__ == "__main__":
    main()
