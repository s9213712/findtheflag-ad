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
  "services": [
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
    "ledger"
  ]
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
- Team server/web 在 live 階段 unreachable 時，每 10 分鐘自動扣 10 分
- `/admin/penalties` 可手動登錄違規扣分、admin attack warning、host/file-control warning
- Admin page/API attack 第一次警告，第二次直接出局
- 以 path traversal 等方式控制對方主機或伺服器檔案，登錄 warning；嚴重或重複可由主持人加罰或出局
- `/admin/export` 可匯出賽後 JSON
- 目前服務：`default`, `token`, `shop`, `memo`, `archive`, `vault`, `cipher`, `proxy`, `waf`, `supply`, `edge`, `media`, `agent`, `saml`, `hook`, `ledger`

## Challenge Families

這些服務是安全靶場化的 toy implementations，用來練 A/D hardening，不是對真實產品的 exploit：

- `default`：預設帳密
- `token`：未簽章角色 token
- `shop`：商業邏輯/折扣下溢
- `memo`：SQL injection 資料外洩
- `archive`：路徑 canonicalization / encoded traversal
- `vault`：可預測 recovery code
- `cipher`：加密但未驗證的可竄改 session
- `proxy`：SSRF / allowlist parser confusion
- `waf`：WAF 與後端 duplicate parameter precedence 差異
- `supply`：供應鏈 manifest 簽章未涵蓋 trust-critical 欄位
- `edge`：session diagnostic overread / token disclosure
- `media`：media asset URL fragment / path parser confusion
- `agent`：AI agent tool guard 與 dispatcher 邊界錯誤
- `saml`：signature wrapping / duplicate claim authorization
- `hook`：OAuth redirect prefix validation confusion
- `ledger`：交易簽章未涵蓋 amount / recipient 的商業邏輯漏洞

設計參考：

- ENOWARS 類服務/checker 分離、put/get flag 概念
- DEF CON CTF 類 Attack-Defense「防守自己的服務，同時打別隊服務」模式
- 近期公開研究中的 WAF parser discrepancy 類型
- 近期 supply-chain incident 常見的 manifest、workflow、package trust 邊界
- 近期 edge/VPN gateway token disclosure、auth bypass、path traversal 類通報趨勢
- hackme_web 分支中大量存在的檔案分享、路徑解析、代理轉發、AI agent/tool boundary、交易/點數簽章類風險面，已抽象成靶場題型

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

- 增加 team-local hardening UI
- 把 team server package 打包成發給各隊的壓縮檔
- 加 live network allowlist / allowed target ports documentation
