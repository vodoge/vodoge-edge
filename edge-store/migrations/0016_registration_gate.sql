-- 追溯执行的两个状态位。
--
-- 挂在 registered_modems 上而不是新开一张表：它们描述的正是「这一行还该不该
-- 在」，和这一行同生共死，DELETE 会自动带走它们。
--
-- 标记不是删除。一根被标记的模组仍然被管理、仍然被轮询、仍然出现在
-- managed_imeis 里。这是自动化「先说、后做」里的那个「说」。
ALTER TABLE registered_modems ADD COLUMN gate_failed_since INTEGER;
ALTER TABLE registered_modems ADD COLUMN gate_failed_reason TEXT;
ALTER TABLE registered_modems ADD COLUMN gate_failed_passes INTEGER NOT NULL DEFAULT 0;

-- 被追溯执行摘掉的纳管记录。
--
-- 0015 说 registered_by 存在的理由是「why is this being managed 是别人对一个
-- 没人记得添加过的模组问的第一个问题」。自动解绑会把那个答案从库里彻底抹掉，
-- 而这张表就是答案的去处 —— 它回答的是那个问题的镜像：为什么这根不再被管了。
--
-- 只有追溯执行写这里。面板和云端的手动 unregister 不写：那是人做的决定，
-- 人知道原因，而且它不该在重新纳管时被自动复原（见 register_modem 里对
-- registered_at 的处理）。
CREATE TABLE IF NOT EXISTS registration_retirements (
    imei TEXT PRIMARY KEY,
    -- 原封不动搬过来的纳管履历。
    registered_at INTEGER NOT NULL,
    registered_by TEXT NOT NULL,
    family TEXT,
    usb_device TEXT,
    -- 摘掉的时刻与理由。
    retired_at INTEGER NOT NULL,
    reason TEXT NOT NULL,
    detail TEXT,
    matrix_version TEXT
);
