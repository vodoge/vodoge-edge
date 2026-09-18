-- 命令的「至多一次」台账。
--
-- 🔴 在此之前它只在内存里（`edge-agent` 的 `commands: BTreeMap`），而
--    `CommandExecutor` 的文档注释写着 "Accepts CommandDeliver, **persists
--    cmd_id**, executes at most once"。那句话不成立：进程一重启，那个 map
--    就是空的。
--
--    后果是实打实的一次重复计费。云端那侧对一条没有终态结果的命令**每 5 秒**
--    重推一次，一直推到过期为止（send_sms 的过期窗口生产上是 5–30 分钟），
--    而 systemd 是 `Restart=always` / `RestartSec=5`。所以：短信已经交给模组
--    发出去了 → agent 在写终态之前被 USB 重枚举拖死 → 5 秒后起来，map 空了
--    → 云端重推 → `first_seen` 又是真 → **同一条短信再发一次**。
--
--    收件人收到两条，而云端只看到一条命令 succeeded、一条消息 sent —— 控制台
--    上没有任何地方显示发重了。
--
--    生产上量到的证据（2026-09-18）：send_sms 的命令回执里有 120 条 accepted
--    和 **14 条 duplicate**，duplicate 都落在 accepted 之后 8–50 秒 —— 云端
--    确实在对还没有终态的短信命令重推，只是那 14 次进程恰好没死，内存里那份
--    台账接住了。
--
-- ⚠️ 只存判重需要的东西：cmd_id、走到哪一步、以及终态结果（重推时原样重放，
--    不重新执行）。命令参数不存 —— 里面可能有一次性凭据（eSIM 激活码、APN
--    口令），而这张表是明文落盘的。
CREATE TABLE IF NOT EXISTS command_journal (
    cmd_id          TEXT PRIMARY KEY,
    -- 'recorded' | 'executing' | 'terminal'
    phase           TEXT NOT NULL,
    -- 终态结果的 JSON，只有 phase='terminal' 时有。
    result          TEXT,
    result_sequence INTEGER,
    updated_at      INTEGER NOT NULL
);

-- 按时间清理用。
CREATE INDEX IF NOT EXISTS command_journal_age ON command_journal (updated_at);
