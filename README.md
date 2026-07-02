# FindTheFlag Attack with Defense Arena

本專案是一個本地練習用的 Attack-Defense CTF 靶場。它模擬多隊伍、多服務、定期輪換 flag、攻擊提交與防守 patch。

> 僅供本機或受控內網教學使用。這個服務刻意包含 CTF 漏洞，請不要直接公開到網際網路。

## Run

```bash
cd /home/s92137/findtheflag-ad
python3 app.py
```

預設入口：

```text
Team login:  http://127.0.0.1:8088/play/login
Admin login: http://127.0.0.1:8088/admin/login
```

可用環境變數調整：

```bash
FTF_HOST=127.0.0.1 FTF_PORT=8088 python3 app.py
```

## What Is Included

- 4 個模擬隊伍：`alpha`, `bravo`, `charlie`, `delta`
- 12 個靶標服務：
  - Memo SQL
  - Archive Box
  - Token Forge
  - Default Admin
  - Coupon Shop
  - Support Desk
  - Badge Renderer
  - Robot Fetcher
  - Cookie Portal
  - People API
  - Backup Index
  - XOR Locker
  - Redeem Race
- 每 120 秒輪換一次 flag
- `/play/login`：隊伍登入
- `/play`：隊伍 scoreboard 與 flag submit
- `/play/targets`：隊伍靶標列表
- `/admin/login`：主持人登入
- `/admin/scoring`：比賽前調整計分方式
- `/admin/defense`：主持人管理各隊服務 patch
- `/admin/operator`：主持人答案表與當輪 flags
- `/api/submit`：flag 提交 API

## Game Flow

1. 主持人從 `data/team_passwords.json` 發給每隊自己的帳號密碼。
2. 主持人從 `/admin` 將 phase 設成 `hardening`，開始 30 分鐘隔離修補。
3. 參賽者從 `/play/login` 登入，只能看自己的 `/play/team/<own-team>/<service>` 與 `/play/defense`。
4. 30 分鐘後，主持人從 `/admin` 將 phase 設成 `live`，開始 1 小時攻防。
5. 參賽者從 `/play/targets` 選擇其他隊伍的服務。
6. 找出該服務漏洞並取得 `FTF{...}` flag。
7. 到 `/play` 或服務頁提交 flag，後端會用登入 session 判定 attacker team。
8. 主持人可在 `/admin/scoring` 最後調整 attack、availability、integrity、penalty 分值。
9. 主持人從 `/admin` 監看 scoreboard、accepted submissions、penalties。
10. 結束時主持人將 phase 設成 `ended`，關閉提交與修補。

## Scoring Config

主持人可在 `/admin/scoring` 調整：

- valid stolen flag 分數
- target patched 後提交的 reduced flag 分數
- availability 每服務每輪分數
- integrity 每服務每輪分數
- unauthorized admin access 扣分
- infrastructure attack 扣分
- checker timeout 秒數

變更會影響後續提交與扣分；已記錄的提交不會自動重算。

## Phase Rules

- `hardening`：網路隔離，只能檢查與修補自己隊伍服務；不能跨隊攻擊，不能提交 flag。
- `live`：開放跨隊攻擊與提交；隊伍仍可在 `/play/defense` 修補自己的服務。
- `ended`：關閉隊伍靶標、提交與修補。

## Flag Integrity

正式比賽不能允許隊伍用「刪除 flag 或讓 checker 找不到 flag」來防守。這版靶場的 flag 由後端動態產生，隊伍不能刪除 flag store。

如果改成真實四隊各自部署服務，建議增加 checker：

- 每輪檢查每隊每服務是否仍能由合法路徑取得自己的 flag。
- flag missing、服務關閉、故意回傳假 flag，都扣 availability/integrity 分。
- patch 只能修漏洞，不應破壞正常功能。

## Notes

- 這是單機模擬版，所有隊伍和服務都跑在同一個 HTTP server。
- 有些漏洞是安全模擬，不會真的執行系統命令或連線外部網路。
- 管理頁不放故意漏洞；參賽者碰觸 `/admin/*` 會被視為攻擊管理頁並扣分。
- 若要重置靶場狀態，停止 server 後刪除 `data/arena.sqlite3` 再重新啟動。
- 若要重置帳密，刪除 `data/admin_password.txt` 或 `data/team_passwords.json` 再重新啟動。
