# Team Web

給參賽隊伍的入口資料。

## Distributed Team Packages

正式分散式賽制中，各隊初始化包由管理員在建立比賽時產生，不應長期放在管理網頁目錄內。

產生後的位置：

```text
distributed/generated/team_packages/<team>/
```

每隊一包：

```text
distributed/generated/team_packages/<team-id>/
```

每包內容：

```text
README.md
team_server.py
submit_flag.py
team_config.json
public/index.html
```

只把該隊自己的 package 發給該隊；不要把 `distributed/configs/teams.json` 發給隊伍，因為那裡有所有隊伍的 secret。

建立比賽或修改 team server/config 後，重新產生 packages：

```bash
python3 /home/s92137/findtheflag-ad/distributed/build_team_packages.py
```

## Give This To Teams

單機模擬版使用：

```text
Team login: http://HOST:8088/play/login
Targets:    http://HOST:8088/play/targets
```

單機模擬版預設隊名：

```text
alpha
bravo
charlie
delta
```

密碼由主持人從這個檔案分發：

```text
data/team_passwords.json
```

## Team Rules

- 先到 `/play/login` 用自己的隊伍帳密登入。
- Hardening phase 前 30 分鐘只會看到自己的服務，請到 `/play/defense` 修補。
- Live phase 開始後，到 `/play/targets` 攻擊其他隊伍的服務。
- 拿到 `FTF{...}` 後，在 `/play` 或服務頁提交。
- 後端會用登入 session 判定 attacker team，不採信前端自己填的隊伍。
- 不要用破壞服務、刪除 flag、讓正常功能失效的方式防守；正式賽會扣 availability/integrity 分。
- 不要攻擊 `/admin`、`/admin/defense`、`/admin/operator`。
- 未登入碰觸管理頁，若系統能辨識隊伍，會扣管理頁攻擊分。

## Team-Side Routes

- `/play`
- `/play/login`
- `/play/targets`
- `/play/defense`
- `/play/team/<victim-team>/<service>`
- `/api/submit`
- `/api/state`
