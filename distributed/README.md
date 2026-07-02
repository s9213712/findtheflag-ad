# Distributed FindTheFlag MVP

這個目錄是正式分散式 Attack-Defense 賽制的第一版可跑實作。

## Files

- `admin_server.py`：主持人中央伺服器
- `team_server.py`：發給每隊的同一份隊伍伺服器
- `configs/teams.json`：admin 端隊伍 secret 與 public URL
- `configs/*.team_config.json`：每隊自己的 team server config
- `make_team_configs.py`：從 `teams.json` 產生每隊 config
- `build_team_packages.py`：建立比賽時產生發給各隊的初始化包

## Local Smoke Run

啟動 admin：

```bash
cd /home/s92137/findtheflag-ad/distributed
python3 admin_server.py
```

第一次啟動會產生：

```text
data/admin_password.txt
configs/teams.json
```

隊伍名稱與數量由管理員在 `/admin/teams` 建立；也可以直接編輯：

```text
configs/teams.json
```

Team ID 建議使用 lowercase letters、digits、hyphen，例如 `red1`、`blue-team`；不要使用底線。

產生每隊 config：

```bash
python3 make_team_configs.py
```

建立要發給各隊的初始化 packages：

```bash
python3 build_team_packages.py
```

也可以在管理介面 `/admin/teams` 多選要放入本場比賽的漏洞服務，然後按 Generate packages。每隊 package 的 `team_config.json` 會包含：

```json
{
  "services": ["default", "token", "shop"]
}
```

輸出位置：

```text
distributed/generated/team_packages/<team>/
```

每隊只拿自己的 package。不要發 `configs/teams.json`。

啟動某隊 team server：

```bash
FTF_TEAM_CONFIG=/home/s92137/findtheflag-ad/distributed/configs/<team-id>.team_config.json python3 team_server.py
```

管理端：

```text
http://127.0.0.1:8088/admin
```

隊伍端範例：

```text
http://127.0.0.1:9100
```

## Current MVP Behavior

- Admin 可切 phase：`setup`, `hardening`, `live`, `ended`
- Team server 每 30 秒 heartbeat
- Live phase 時 team server 每 5 分鐘回報 current flags
- 測試時可用 `FTF_ROUND_SECONDS`、`FTF_TEAM_HEARTBEAT_INTERVAL_SECONDS`、`FTF_CHECKER_INTERVAL_SECONDS`、`FTF_CHECKER_TIMEOUT_SECONDS` 調整回合、回報與 checker 時間
- Admin 儲存 victim 回報的 flags
- Admin live 階段會用簽章 checker endpoint 主動驗證每隊 flags，availability/integrity 以 checker 結果為準
- 攻擊方提交 flag 時，admin 比對 victim 回報值
- 同一 attacker/victim/service/round 只計一次
- Checker 成功連到隊伍並取回正確 flag 會給 availability/integrity 分
- `/admin/penalties` 可手動登錄違規扣分
- `/admin/export` 可匯出賽後 JSON
- 目前服務：`default`, `token`, `shop`

## Submit Flags

隊伍可用 helper 提交：

```bash
FTF_TEAM_CONFIG=/home/s92137/findtheflag-ad/distributed/configs/<team-id>.team_config.json \
  python3 submit_flag.py 'FTF{victim_default_...}'
```

底層 API 需要用 team secret 簽 body：

```http
POST /api/submit
X-Team-Id: <attacker-team-id>
X-Team-Signature: HMAC_SHA256(team_secret, raw_body)
Content-Type: application/json

{"flag":"FTF{victim_default_...}"}
```

## Next Implementation Steps

- 搬入更多服務題目
- 增加 team-local hardening UI
- 把 team server package 打包成發給各隊的壓縮檔
- 加 live network allowlist / allowed target ports documentation
