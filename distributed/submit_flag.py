#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import urllib.request
from pathlib import Path


def signed_post(config: dict[str, object], path: str, payload: dict[str, object]) -> None:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    signature = hmac.new(str(config["team_secret"]).encode(), raw, hashlib.sha256).hexdigest()
    req = urllib.request.Request(
        str(config["admin_url"]).rstrip("/") + path,
        data=raw,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Team-Id": str(config["team_id"]),
            "X-Team-Signature": signature,
        },
    )
    with urllib.request.urlopen(req, timeout=5) as response:
        print(response.read().decode())


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: FTF_TEAM_CONFIG=/path/team_config.json python3 submit_flag.py 'FTF{...}'")
    config_path = Path(os.environ.get("FTF_TEAM_CONFIG", "team_config.json"))
    config = json.loads(config_path.read_text(encoding="utf-8"))
    signed_post(config, "/api/submit", {"flag": sys.argv[1].strip()})


if __name__ == "__main__":
    main()
