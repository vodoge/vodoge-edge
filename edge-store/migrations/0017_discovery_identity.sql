-- 候选行上的身份事实：这一根是什么型号、卡归属哪个网。
--
-- 🔴 为什么必须挂在**候选表**上，而不是从 local_modems 读。
--
-- `local_modems` 按设计只装已纳管的模组：poll 循环在 `is_managed` 为假时就
-- `continue` 了（edge-bin/src/main.rs 那处的注释写着理由 ——「未纳管的模组
-- 不能进 DeviceState，否则云端会替运维凭空建一行」）。那个设计是对的，不该动。
--
-- 错的是把纳管两道闸的输入接到了 inventory 上：闸 2 要 (型号, 运营商画像)，
-- 而一根从没被纳管过的模组在 inventory 里根本没有行 —— 于是「先被纳管才能被
-- 纳管」，面板和云端的纳管按钮对任何新硬件都必然失败，而且再等多少轮都一样。
-- 现有那几根不受影响（它们早有 inventory 行），所以这个洞在机队上是隐形的。
--
-- 候选表才是「见过、还没纳管」这件事的记录，闸的输入本来就该从这里取。
ALTER TABLE local_modem_discoveries ADD COLUMN family TEXT;
ALTER TABLE local_modem_discoveries ADD COLUMN home_mcc INTEGER;
ALTER TABLE local_modem_discoveries ADD COLUMN home_mnc INTEGER;

-- ⚠️ 这三列的写入规则和 local_modems.family 一样：**读不到就不覆盖**。
--
-- 2026-09-05 在生产库里查到过两行 family='0'（一根 UFI103S 对型号查询答了
-- 「0」），根因是当时的 upsert 无条件覆盖。同一个坑不再踩第二次：写入侧用
-- CASE WHEN 挡住空串和 'unknown'，归属网用 COALESCE 保住上一次读到的值。
--
-- 归属网尤其要保：AT-only 那条路要多轮才读得出 IMSI，中间几轮是 NULL。
-- 如果每轮都覆盖，闸 2 的输入就会在「有」和「无」之间反复横跳，纳管按钮
-- 时灵时不灵 —— 那比一直失败更难查。
