# Distributed Attack-Defense Competition Spec

這份規格描述正式分散式賽制：每隊拿到同一份伺服器程式碼，各自部署到自己的機器；前 30 分鐘離線建置與強化；後 60 分鐘進入 live 攻防，隊伍伺服器需要持續連到管理員伺服器回報狀態與 flags。

## Roles

### Admin Server

主持人中央伺服器，負責：

- 管理隊伍清單與隊伍密鑰。
- 控制 phase：`setup`, `hardening`, `live`, `ended`。
- 接收每隊 server heartbeat。
- 接收每隊每 5 分鐘回報的 current flags。
- 接收攻擊方提交的 stolen flags。
- 根據 victim team 回報的 flag 判定提交是否正確。
- 計算 attack、availability、integrity、penalty。
- 顯示 scoreboard、team health、flag rounds、submission log。

### Team Server

每隊自行部署的同一份靶機程式，負責：

- 跑所有題目服務。
- 在 hardening 階段讓隊伍本地修補。
- 在 live 階段每 5 分鐘更新 flags。
- 向 admin server 回報：
  - heartbeat
  - service health
  - current flag round
  - 每個 service 的 current flag hash 或完整 flag
- 維持服務可被其他隊伍攻擊。

### Teams

每隊負責：

- 用同一份 server code 部署自己的 team server。
- hardening 期間修補漏洞，但不能破壞正常功能或刪除 flag。
- live 期間攻擊其他隊伍並保護自己的服務。
- 維持 team server 與 admin server 連線。

## Timeline

### Phase 0: Setup

主持人準備：

- 同一份 team server package。
- 每隊一份 config：

```text
TEAM_ID=alpha
TEAM_SECRET=<unique shared secret>
ADMIN_URL=http://admin-host:8088
PUBLIC_BASE_URL=http://alpha-host:9000
```

每隊拿到：

- 同一份程式碼。
- 自己的 `.env` 或 `team_config.json`。
- hardening 開始時間。
- live 開始時間。

### Phase 1: Hardening, 30 Minutes

網路規則：

- Team server 不需要連 admin server。
- 隊伍之間網路隔離。
- 隊伍只能本地測試自己的服務。

允許：

- 建置服務。
- 修補漏洞。
- 改密碼、加驗證、補 SQLi、補 LFI、補 IDOR。
- 加 logging、monitoring、rate limit。

禁止：

- 刪除 flag 產生或儲存機制。
- 讓 checker 不能正常取得合法 flag。
- 關閉服務。
- 永遠回 403/404/500。
- 改掉題目正常功能。
- 修改 team identity 或偽裝其他隊。
- 移除 heartbeat/reporting agent。

hardening 階段不計 attack 分，不接受 flag submission。

### Phase 2: Live Attack-Defense, 60 Minutes

網路規則：

- admin server 開放。
- team server 必須可連 admin server。
- 各隊之間互通，可以攻擊對方 public service。

live 行為：

- 每 5 分鐘是一個 flag round。
- 每隊每個 service 在每個 round 產生新 flag。
- team server 需回報該 round 的 flags 給 admin server。
- 攻擊方偷到 victim flag 後提交到 admin server。
- admin server 比對 victim team 回報的 flag，正確才給分。
- 隊伍在 live 階段可以同時即時 harden 自己服務與 attack 他隊；不需要切換模式。

同一攻擊管道可每 round 重複得分：

- 如果 bravo 的 `default` 服務一直沒修，alpha 每 5 分鐘都能偷到新的 `bravo/default` flag。
- 每個 attacker/victim/service/round 最多計一次。
- 多隊可在同一 round 攻擊同一 victim/service 並各自得分。

### Phase 3: Ended

- 停止接受 flag submission。
- 停止計算新的 availability/integrity。
- scoreboard 凍結。
- admin 匯出結果。

## Flag Model

每個 flag 必須包含：

```text
FTF{victim_team_service_round_digest}
```

例如：

```text
FTF{bravo_default_42_a91f0c2d8e7b4c31aa}
```

建議由 team server 用 `TEAM_SECRET` 產生：

```text
digest = HMAC_SHA256(TEAM_SECRET, team_id + service + round)
flag = FTF{team_service_round_digest[:18]}
```

admin 驗證方式有兩種：

1. Team server 回報完整 flag。
2. Team server 回報 flag hash，admin 儲存 hash，比對 submission hash。

建議初版使用完整 flag，方便主持人 debug；正式高強度版改用 hash。

## Team Server Reporting Protocol

### Heartbeat

Team server 每 30 秒向 admin 回報：

```http
POST /api/team/heartbeat
Content-Type: application/json
X-Team-Id: alpha
X-Team-Signature: <hmac>
```

```json
{
  "team_id": "alpha",
  "timestamp": 1720000000,
  "public_base_url": "http://alpha-host:9000",
  "phase_seen": "live",
  "services": {
    "memo": {"status": "up", "latency_ms": 42},
    "default": {"status": "up", "latency_ms": 37}
  }
}
```

Signature:

```text
HMAC_SHA256(TEAM_SECRET, raw_request_body)
```

### Flag Report

Team server 每 5 分鐘回報一次本 round 所有 service flags：

```http
POST /api/team/flags
Content-Type: application/json
X-Team-Id: alpha
X-Team-Signature: <hmac>
```

```json
{
  "team_id": "alpha",
  "round": 42,
  "generated_at": 1720000000,
  "flags": {
    "memo": "FTF{alpha_memo_42_...}",
    "default": "FTF{alpha_default_42_...}",
    "archive": "FTF{alpha_archive_42_...}"
  }
}
```

Admin acceptance rules:

- Team ID must match signature.
- Round must be current or within small clock skew allowance.
- Every required service must report exactly one flag.
- Missing service flag means integrity failure for that service/round.

### Admin Checker

Live 階段 admin server 會主動呼叫每隊 team server 的 checker endpoint：

```http
POST /__checker/flags
Content-Type: application/json
X-Checker-Signature: HMAC_SHA256(TEAM_SECRET, raw_body)
```

```json
{"round": 42}
```

Team server 回傳該 round 的 flags。Admin 只有在成功連到隊伍並驗證 flag 格式、team、service、round 都正確時，才給該 service/round 的 availability 與 integrity 分。Team server 自行回報 flags 仍可用於提交比對與 debug，但正式計分以 admin checker 結果為準。

## Flag Submission Protocol

Teams submit stolen flags to admin:

```http
POST /api/submit
Content-Type: application/json
Authorization: Bearer <team-login-session-or-api-token>
```

```json
{
  "flag": "FTF{bravo_default_42_a91f0c2d8e7b4c31aa}"
}
```

Admin validates:

- Attacker is authenticated.
- Flag format is valid.
- Victim team exists.
- Victim is not attacker.
- Service exists.
- Round is accepted.
- Victim team reported matching flag for that service/round.
- Attacker has not already scored attacker/victim/service/round.

If valid:

```text
attack += attack_flag_points
```

## Scoring

Recommended default:

```text
Attack:
  valid stolen flag: +10
  same attacker/victim/service/round only once

Availability:
  service reachable during checker round: +2

Integrity:
  service returns correct own current flag through legal checker path: +2

Penalties:
  admin page/API attack: -15
  infrastructure attack: -50 or disqualification
  team identity tampering: -50 or disqualification
```

Total:

```text
total = attack + availability + integrity - penalty
```

## Challenge Service Selection

主持人可在賽前於管理頁多選本場要放入隊伍 package 的漏洞服務。所有隊伍拿到相同 `team_server.py` 與相同服務清單，只有 `team_config.json` 內的隊伍 ID、secret、port/public URL 不同。

Current catalog:

```text
default  - default credentials
token    - unsigned role token
shop     - business logic underflow
memo     - SQL injection
archive  - encoded traversal / canonicalization confusion
vault    - predictable recovery code
cipher   - malleable encrypted session
proxy    - SSRF / URL parser confusion
waf      - duplicate parameter parser discrepancy
supply   - incomplete manifest signature coverage
edge     - session diagnostic overread
media    - media asset URL fragment confusion
agent    - AI agent tool boundary confusion
saml     - signature wrapping / duplicate claim auth
hook     - OAuth redirect prefix parser confusion
ledger   - incomplete transaction signature coverage
```

這些服務參考官方 A/D 題常見 service/checker 模式與近期公開漏洞趨勢，並把 hackme_web 類大型網站常見的檔案分享、路徑解析、代理轉發、AI/tool 邊界、交易/點數簽章風險抽象成可控靶場題。

## Server Crash / Disconnect Handling

### Team Server Disconnects From Admin

If admin does not receive heartbeat within threshold:

```text
heartbeat timeout: 90 seconds
```

Then:

- Mark team as disconnected.
- No availability points for missed checker rounds.
- No integrity points for missing flag reports.
- Continue accepting stolen flags against the last valid victim round only until that round expires.

Recommended:

```text
missed heartbeat warning: 60s
disconnected: 90s
hard fail: 150s
```

### Service Crash

Checker result per service/round:

```text
connection refused: availability 0, integrity 0
timeout > checker_timeout_seconds: availability 0, integrity 0
HTTP 5xx: availability 0, integrity 0
checker endpoint blocked: availability may be 1/2 or 0, integrity 0
wrong/missing flag: availability maybe +2, integrity 0
```

### Whole Server Crash

If the whole team host is unreachable:

```text
all services availability = 0 for that checker round
all services integrity = 0 for that checker round
heartbeat missed
flag report missing
```

No extra fixed penalty is needed unless crash is caused by illegal behavior. The team naturally loses points every round it is down.

## Anti-Abuse Rules

### Cannot Delete Flags

Teams may patch vulnerabilities, but must preserve:

- flag generation
- flag storage or runtime availability
- legal checker path
- service normal behavior
- heartbeat/reporting agent

If a team removes flag access:

```text
availability may still be up
integrity = 0
repeat every affected round
```

If intentional tampering is confirmed:

```text
additional penalty or disqualification
```

### Cannot Block Everyone

Teams cannot solve defense by blocking all traffic.

Allowed:

- input validation
- authentication fixes where intended
- rate limiting within published limits
- patching known vulnerable logic

Not allowed:

- block all non-local IPs
- block all other teams
- require unknown credentials for public challenge surface
- return fake flags
- disable challenge endpoints

### Cannot Attack Infrastructure

Forbidden targets:

- admin server
- scoreboard
- flag submission API
- team reporting API
- VPN/router/firewall infrastructure
- checker infrastructure

Penalty:

```text
first confirmed attempt: -50
serious/repeated: disqualification
```

## Network Design

### Hardening

Firewall/VLAN:

```text
team -> internet: optional/blocked by policy
team -> admin: blocked
team -> other teams: blocked
admin -> team: blocked or checker disabled
```

### Live

Firewall/VLAN:

```text
team -> admin: allowed
team -> other teams: allowed on challenge ports
admin -> team: allowed on checker/health ports
team -> infrastructure admin ports: blocked
```

Recommended:

- Each team gets a fixed subnet or host IP.
- Only challenge ports are reachable between teams.
- SSH/admin ports are restricted to team members and organizers.

## Operational Checklist

### Before Competition

- Freeze team server package.
- Generate team configs and secrets.
- Test each package boots offline.
- Test admin verifies heartbeat signatures.
- Test flag report for all services.
- Test one full round: generate, report, steal, submit, score.
- Publish scoring config before hardening starts.

### At Hardening Start

- Distribute packages/configs.
- Confirm teams can boot locally.
- Keep admin/reporting network closed.
- Teams harden for 30 minutes.

### At Live Start

- Open network paths.
- Admin switches phase to `live`.
- Team servers begin heartbeat and flag reporting.
- Checker starts availability/integrity rounds.
- Flag submissions open.

### During Live

- Monitor disconnected teams.
- Monitor missing flag reports.
- Monitor admin attack attempts.
- Avoid manual score edits unless dispute resolution requires it.

### After End

- Switch phase to `ended`.
- Export scoreboard, submissions, availability, integrity, penalties.
- Archive team configs and logs.

## Suggested Implementation Split

```text
admin_server.py
  /admin
  /admin/scoring
  /admin/teams
  /admin/flags
  /admin/penalties
  /admin/export
  /admin/health
  /api/team/heartbeat
  /api/team/flags
  /api/submit

team_server.py
  challenge services
  local hardening UI
  flag generator
  signed checker endpoint
  heartbeat reporter
  flag reporter
  checker-compatible legal flag endpoints
```

The same `team_server.py` is given to all teams. Only `team_config.json` differs per team.
