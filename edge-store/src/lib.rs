//! SQLite persistence for the edge agent.
//!
//! Schema migrations are versioned integers. Upgrade and rollback are both
//! tested so a failed edge update can return to the previous database.

use std::{error::Error, fmt, path::Path};

mod outbox;

use rusqlite::{params, Connection, OptionalExtension};

pub use outbox::{
    CapacityAlert, CapacityOutcome, CapacityOverflow, DurableOutbox, QueueError,
    DEFAULT_MAX_RECORDS,
};

/// Where each module was last seen on the USB bus.
///
/// Separate from `local_modems` because it answers a different question and
/// has a different key discipline: `local_modems` is what the offline panel
/// shows, while this is the aim of a destructive recovery and therefore has
/// to be unambiguous. The unique index on `usb_device` is the point — two
/// rows claiming one bus position would be exactly the state in which a
/// reset could land on the wrong stick, so the newest observation evicts the
/// older claim rather than sitting beside it.
const MODEM_USB_SITES: &str = "\
CREATE TABLE IF NOT EXISTS modem_usb_sites (
    imei       TEXT PRIMARY KEY,
    usb_device TEXT NOT NULL,
    vendor_id  TEXT NOT NULL,
    product_id TEXT NOT NULL,
    seen_at    INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS modem_usb_sites_device
    ON modem_usb_sites (usb_device);
";

/// Which received fragments have already been stored, by our own reckoning.
///
/// The modem's read flag used to be the answer to that question by omission:
/// the collector asked only for unread messages, so anything already read was
/// treated as dealt with. It is not our flag. One `AT+CMGR` — from the
/// console's AT terminal, from a diagnostic, from our own troubleshooting —
/// flips it, and on 2026-08-23 that made a stored message invisible to five
/// consecutive collection passes while `AT+CPMS?` still counted it in the
/// store: lost to the operator for good, and holding a storage slot for good.
///
/// So the collector now reads everything the modem holds and this table, which
/// nothing outside this process can touch, decides what is new. `copies`
/// rather than a bare row because the service centre does deliver the same
/// message twice, and both deliveries are real messages.
const INGESTED_SMS: &str = "\
CREATE TABLE IF NOT EXISTS ingested_sms (
    imei        TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    copies      INTEGER NOT NULL,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    PRIMARY KEY (imei, fingerprint)
);
CREATE INDEX IF NOT EXISTS ingested_sms_age
    ON ingested_sms (imei, last_seen);
";

/// `0015_registered_modems.sql` 在迁移序列里的位置。
///
/// 具名导出，是因为测试需要「回滚到注册表迁移之前」，而它此前写的是
/// `latest - 1` —— 那个表达式把「0015 是最后一条」这个事实编进了算式。
/// 加上 0016 之后 `latest - 1` 变成了 15，回滚不再跨过 0015，两条关于
/// 「升级会自动纳管旧 agent 管着的模组」的测试**静默变空**：它们照常绿，
/// 断言的却是一次没发生过的迁移。
///
/// 这个文件里已经有过一次同样的教训：那两条测试的注释写着「An earlier
/// version of this test rolled back to 0, which drops `local_modems` too,
/// so there was nothing to adopt and it asserted nothing.」——
/// 同一个失效形状，换了一个算错的数字。
/// 这一趟到底**问没问**卡号。
///
/// QMI 那条路真的读 EF_ICCID，所以 `LocalModem.iccid == None` 的意思是
/// 「卡不在」，照写、让它变空是对的 —— 否则拔掉的卡永远拔不掉。
///
/// AT 那条路只在模组答得了 `+QCCID` / `+CCID` 时才问得到。问不到时
/// `None` 的意思是「没问成」，不是「没卡」。
///
/// 🔴 两者共用一条规则的代价是会花钱的：QMI 口一挂、轮询降级到 AT，
/// `local_modems.iccid` 被抹成空 → 卡策略按 ICCID 查、查不到就是「没有
/// 声明」→ `unwrap_or_default()` 放行 → 一张写着「套餐不含发短信」的卡
/// 变成能发，而且没有日志也没有告警。这正是这个仓库反复在防的那个形状：
/// **一次读失败塌陷成了一个合法值**。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CardRead {
    /// 问过了。`iccid` 就是答案，`None` = 卡不在。
    Answered,
    /// 这一趟没问成。已存的卡号不许被覆盖。
    Unasked,
}

pub const REGISTRY_MIGRATION: i64 = 15;

/// 0017 给候选表加身份三列的那一条。
///
/// 具名而不是 `latest - 1`：0016 落地时那个算式就已经把「注册表迁移是最后
/// 一条」写死过一次（见 registered_modems.rs 里的注释），同一个坑不再踩。
pub const DISCOVERY_IDENTITY_MIGRATION: i64 = 17;

const MIGRATIONS: &[&str] = &[
    include_str!("../migrations/0001_init.sql"),
    include_str!("../migrations/0002_cursor.sql"),
    include_str!("../migrations/0003_local_inbox.sql"),
    include_str!("../migrations/0004_modem_network.sql"),
    include_str!("../migrations/0005_modem_home.sql"),
    MODEM_USB_SITES,
    INGESTED_SMS,
    include_str!("../migrations/0008_modem_discovery.sql"),
    include_str!("../migrations/0009_manual_modem_profiles.sql"),
    include_str!("../migrations/0010_card_policies.sql"),
    include_str!("../migrations/0011_modem_identity.sql"),
    include_str!("../migrations/0012_card_capability.sql"),
    include_str!("../migrations/0013_apn_contexts.sql"),
    include_str!("../migrations/0014_capability_matrix.sql"),
    include_str!("../migrations/0015_registered_modems.sql"),
    include_str!("../migrations/0016_registration_gate.sql"),
    include_str!("../migrations/0017_discovery_identity.sql"),
];

/// An opened edge database with migrations applied.
pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        // ⚠️ WAL 设不上不是致命的（回退到 rollback journal 仍然能用），但
        //    **必须留痕**：并发写的表现会完全不同，而紧邻上一行的
        //    `busy_timeout` 是用 `?` 传播的——同一个函数里两种处理方式，其中
        //    一种什么都不说，排查并发问题时会白找很久。
        if let Err(error) = conn.pragma_update(None, "journal_mode", "WAL") {
            eprintln!("store: WAL not enabled, falling back to rollback journal: {error}");
        }
        let mut store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        let mut store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    /// 这张表现在存不存在。
    ///
    /// 给测试钉住迁移的**前提**用：只断言结果的话，一次编号漂移就能让
    /// 「回滚到某版本之前」悄悄变成「回滚到它之后」，而断言照常通过。
    pub fn has_table(&self, name: &str) -> Result<bool, StoreError> {
        let count: i64 = self.conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            params![name],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    pub fn schema_version(&self) -> Result<i64, StoreError> {
        let version = self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))?;
        Ok(version)
    }

    pub fn migrate(&mut self) -> Result<(), StoreError> {
        let mut version = self.schema_version()?;
        while (version as usize) < MIGRATIONS.len() {
            self.conn.execute_batch(MIGRATIONS[version as usize])?;
            version += 1;
            self.conn
                .pragma_update(None, "user_version", version)?;
        }
        Ok(())
    }

    pub fn rollback_to(&mut self, target: i64) -> Result<(), StoreError> {
        let current = self.schema_version()?;
        if target < 0 || target > current {
            return Err(StoreError::InvalidTarget {
                current,
                target,
            });
        }
        if target < current {
            self.conn
                .execute_batch("DROP TABLE IF EXISTS registered_modems;")?;
            // 0016 建的。和上面那张同生共死：回滚到 16 以下之后它不该还在，
            // 否则一条 CREATE TABLE IF NOT EXISTS 会在重放时静默变成空操作，
            // 而它携带的列定义就再也不会被验证。
            self.conn
                .execute_batch("DROP TABLE IF EXISTS registration_retirements;")?;
            self.conn.execute_batch("DROP TABLE IF EXISTS card_policies;")?;
            self.conn
                .execute_batch("DROP TABLE IF EXISTS manual_modem_profiles;")?;
            self.conn.execute_batch("DROP TABLE IF EXISTS ingested_sms;")?;
            self.conn.execute_batch("DROP TABLE IF EXISTS modem_usb_sites;")?;
            self.conn
                .execute_batch("DROP TABLE IF EXISTS local_modem_discoveries;")?;
            self.conn.execute_batch("DROP TABLE IF EXISTS local_messages;")?;
            self.conn.execute_batch("DROP TABLE IF EXISTS local_modems;")?;
            self.conn.execute_batch("DROP TABLE IF EXISTS uplink_gaps;")?;
            self.conn.execute_batch("DROP TABLE IF EXISTS uplink_outbox;")?;
            self.conn.execute_batch("DROP TABLE IF EXISTS uplink_cursor;")?;
            self.conn.pragma_update(None, "user_version", 0)?;
            let mut store_version = 0i64;
            while store_version < target {
                self.conn
                    .execute_batch(MIGRATIONS[store_version as usize])?;
                store_version += 1;
                self.conn
                    .pragma_update(None, "user_version", store_version)?;
            }
        }
        Ok(())
    }

    pub fn enqueue(
        &self,
        seq: i64,
        envelope_id: &str,
        kind: &str,
        payload: &[u8],
        protected: bool,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO uplink_outbox (seq, envelope_id, kind, payload, protected)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![seq, envelope_id, kind, payload, protected as i64],
        )?;
        Ok(())
    }

    pub fn ack_through(&self, seq: i64) -> Result<usize, StoreError> {
        let deleted = self
            .conn
            .execute("DELETE FROM uplink_outbox WHERE seq <= ?1", params![seq])?;
        Ok(deleted)
    }

    pub fn next_seq(&self) -> Result<i64, StoreError> {
        let max: Option<i64> = self
            .conn
            .query_row("SELECT MAX(seq) FROM uplink_outbox", [], |row| row.get(0))?;
        Ok(max.unwrap_or(0) + 1)
    }

    pub fn cursor(&self) -> Result<(u64, u64), StoreError> {
        let row: (i64, i64) = self.conn.query_row(
            "SELECT committed_through, last_allocated FROM uplink_cursor WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok((row.0 as u64, row.1 as u64))
    }

    pub fn set_cursor(&self, committed_through: u64, last_allocated: u64) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE uplink_cursor SET committed_through = ?1, last_allocated = ?2 WHERE id = 1",
            params![committed_through as i64, last_allocated as i64],
        )?;
        Ok(())
    }

    pub fn load_outbox(&self) -> Result<Vec<OutboxRow>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT seq, envelope_id, kind, payload, protected FROM uplink_outbox ORDER BY seq ASC",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok(OutboxRow {
                    seq: row.get::<_, i64>(0)? as u64,
                    envelope_id: row.get(1)?,
                    kind: row.get(2)?,
                    payload: row.get(3)?,
                    protected: row.get::<_, i64>(4)? != 0,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn delete_sequences(&self, sequences: &[u64]) -> Result<(), StoreError> {
        for sequence in sequences {
            self.conn
                .execute("DELETE FROM uplink_outbox WHERE seq = ?1", params![*sequence as i64])?;
        }
        Ok(())
    }

    pub fn insert_gap(
        &self,
        gap_id: &str,
        ranges: &str,
        reason: &str,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO uplink_gaps (gap_id, ranges, reason, accepted) VALUES (?1, ?2, ?3, 0)",
            params![gap_id, ranges, reason],
        )?;
        Ok(())
    }

    pub fn mark_gap_accepted(&self, gap_id: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE uplink_gaps SET accepted = 1 WHERE gap_id = ?1",
            params![gap_id],
        )?;
        Ok(())
    }

    pub fn insert_local_message(&self, message: &LocalMessage) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO local_messages (seq, peer, body, bearer, direction, received_at, modem_imei)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(seq) DO UPDATE SET
                peer = excluded.peer,
                body = excluded.body,
                bearer = excluded.bearer,
                direction = excluded.direction,
                received_at = excluded.received_at,
                modem_imei = excluded.modem_imei",
            params![
                message.seq as i64,
                message.peer,
                message.body,
                message.bearer,
                message.direction,
                message.received_at,
                message.modem_imei,
            ],
        )?;
        Ok(())
    }

    /// How many copies of one received fragment this module has already had
    /// stored. Zero for anything never seen.
    pub fn ingested_sms_copies(&self, imei: &str, fingerprint: &str) -> Result<u32, StoreError> {
        let copies: Option<i64> = self
            .conn
            .query_row(
                "SELECT copies FROM ingested_sms WHERE imei = ?1 AND fingerprint = ?2",
                params![imei, fingerprint],
                |row| row.get(0),
            )
            .optional()?;
        Ok(copies.unwrap_or(0).max(0) as u32)
    }

    /// Write down fragments that have just been stored.
    ///
    /// Called *after* the message is in the local inbox and in the durable
    /// outbox, and *before* the modem's copy is deleted — the same order the
    /// delete itself has to follow, and for the same reason. A ledger entry
    /// written early would suppress a message that never actually landed
    /// anywhere.
    ///
    /// One transaction so a pass is recorded whole: half a multipart message
    /// on the books would leave the other half to be stored a second time.
    pub fn record_ingested_sms(
        &self,
        imei: &str,
        fingerprints: &[String],
        now: i64,
    ) -> Result<(), StoreError> {
        let transaction = self.conn.unchecked_transaction()?;
        for fingerprint in fingerprints {
            transaction.execute(
                "INSERT INTO ingested_sms (imei, fingerprint, copies, first_seen, last_seen)
                 VALUES (?1, ?2, 1, ?3, ?3)
                 ON CONFLICT(imei, fingerprint) DO UPDATE SET
                    copies = ingested_sms.copies + 1,
                    last_seen = excluded.last_seen",
                params![imei, fingerprint, now],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Keep the newest `keep` fingerprints for one module and drop the rest.
    ///
    /// The ledger must outlive every message that could still be sitting on a
    /// modem, or pruning would let an old message be stored a second time. A
    /// modem store holds fifty entries and a fragment leaves it as soon as one
    /// delete succeeds, so a cap of thousands is not a compromise between
    /// safety and size — it is orders of magnitude past the point where a
    /// dropped entry could ever be met again.
    pub fn prune_ingested_sms(&self, imei: &str, keep: usize) -> Result<usize, StoreError> {
        let removed = self.conn.execute(
            "DELETE FROM ingested_sms
              WHERE imei = ?1
                AND rowid NOT IN (
                    SELECT rowid FROM ingested_sms
                     WHERE imei = ?1
                     ORDER BY last_seen DESC, rowid DESC
                     LIMIT ?2)",
            params![imei, keep as i64],
        )?;
        Ok(removed)
    }

    /// How many fingerprints are on the books for one module. For the panel
    /// and for tests; the collector never needs the whole set.
    pub fn ingested_sms_len(&self, imei: &str) -> Result<usize, StoreError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM ingested_sms WHERE imei = ?1",
            params![imei],
            |row| row.get(0),
        )?;
        Ok(count.max(0) as usize)
    }

    pub fn list_local_messages(&self) -> Result<Vec<LocalMessage>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT seq, peer, body, bearer, direction, received_at, modem_imei
               FROM local_messages
              ORDER BY received_at DESC, seq DESC
              LIMIT 200",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok(LocalMessage {
                    seq: row.get::<_, i64>(0)? as u64,
                    peer: row.get(1)?,
                    body: row.get(2)?,
                    bearer: row.get(3)?,
                    direction: row.get(4)?,
                    received_at: row.get(5)?,
                    modem_imei: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn upsert_local_modem(&self, modem: &LocalModem) -> Result<(), StoreError> {
        self.upsert_local_modem_with(modem, CardRead::Answered)
    }

    pub fn upsert_local_modem_with(
        &self,
        modem: &LocalModem,
        card: CardRead,
    ) -> Result<(), StoreError> {
        let iccid_rule = match card {
            CardRead::Answered => "iccid = excluded.iccid,",
            CardRead::Unasked => {
                "iccid = COALESCE(excluded.iccid, local_modems.iccid),"
            }
        };
        // SQL 里只有这一处随参数变，其余照旧是常量字符串。占位符仍然是
        // 位置绑定，`iccid_rule` 本身来自上面那个封闭的 match，不接受外部输入。
        self.conn.execute(
            &format!(
            "INSERT INTO local_modems
                (imei, family, firmware, msisdn, msisdn_iccid, apn_contexts,
                 iccid, state, last_seen, mcc, mnc, home_mcc, home_mnc, imsi,
                 discovery, manageable, control_port)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
             ON CONFLICT(imei) DO UPDATE SET
                -- 型号是身份，不是每轮的观测值 —— 它和正下方的 firmware
                -- 是同一类事实（只有把模块重刷才会变），而不是和 state /
                -- last_seen 同类。同一个 IMEI 的型号永远不变。
                --
                -- 但不能照抄 firmware 的 COALESCE：退化的读数不是 NULL，是一个
                -- 非空的降级串。ModemFamily::detect_name 在型号和固件都读回空串
                -- 时返回字面量 unknown，而那正是只走 AT 的 EC200U 在它那 15 分钟
                -- 的挂死里会发生的事。COALESCE 对 unknown 无效。
                --
                -- 只拦覆盖，不拦首次写入：一根从没被认出过的模组要能以 unknown
                -- 落一行，否则运维连它插着都看不到。
                --
                -- 也只拦这两个哨兵值。Other(_) 里的垃圾不在此列 —— 台架上真出现过
                -- family = 0（模组对型号查询答了 0），但代码分不出 0 和 SIM7600G，
                -- 后者是一个合法的、只是本 build 不认识的型号。在这一层猜哪个是
                -- 垃圾，会把不认识的硬件和模组答了废话混成一件事。那属于判定层：
                -- 追溯执行对 Other(_) 维持现状并告警，而不是解绑。
                --
                -- 代价具体：纳管第二道闸按 (family, carrier) 查规则，family 被抹成
                -- unknown 之后这一对在矩阵里必然缺席，于是判成从没测过。
                family = CASE
                             WHEN TRIM(excluded.family) IN ('', 'unknown')
                             THEN local_modems.family
                             ELSE excluded.family
                         END,
                -- Same policy as the card identity below: a pass that could
                -- not read one of these keeps the last that could. Firmware
                -- is only re-read on a probe that got that far, and the
                -- number is only re-read when the card underneath changes.
                firmware = COALESCE(excluded.firmware, local_modems.firmware),
                msisdn = COALESCE(excluded.msisdn, local_modems.msisdn),
                msisdn_iccid = COALESCE(excluded.msisdn_iccid, local_modems.msisdn_iccid),
                apn_contexts = COALESCE(excluded.apn_contexts, local_modems.apn_contexts),
                {iccid_rule}
                state = excluded.state,
                last_seen = excluded.last_seen,
                discovery = excluded.discovery,
                manageable = excluded.manageable,
                control_port = excluded.control_port,
                -- A poll taken while the modem is searching reports no network.
                -- Keeping the last known one stops the card's identity from
                -- blinking out every time it re-registers.
                mcc = COALESCE(excluded.mcc, local_modems.mcc),
                mnc = COALESCE(excluded.mnc, local_modems.mnc),
                -- A read that failed leaves the card's identity alone rather
                -- than blanking it; one bad poll must not lose what is known.
                home_mcc = COALESCE(excluded.home_mcc, local_modems.home_mcc),
                home_mnc = COALESCE(excluded.home_mnc, local_modems.home_mnc),
                imsi = COALESCE(excluded.imsi, local_modems.imsi)"
            ),
            params![
                modem.imei,
                modem.family,
                modem.firmware,
                modem.msisdn,
                modem.msisdn_iccid,
                modem.apn_contexts,
                modem.iccid,
                modem.state,
                modem.last_seen,
                modem.mcc,
                modem.mnc,
                modem.home_mcc,
                modem.home_mnc,
                modem.imsi,
                modem.discovery,
                modem.manageable as i64,
                modem.control_port,
            ],
        )?;
        Ok(())
    }

    /// Store the last probe result for a physical modem endpoint. Unlike the
    /// modem inventory this is allowed to have no IMEI: making a broken port
    /// visible is the point of the diagnostic list.
    pub fn upsert_local_modem_discovery(
        &self,
        discovery: &LocalModemDiscovery,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO local_modem_discoveries
                (candidate_key, usb_device, transport, control_port, vendor_id, product_id,
                 state, imei, detail, last_seen, family, home_mcc, home_mnc)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(candidate_key) DO UPDATE SET
                usb_device = excluded.usb_device,
                transport = excluded.transport,
                control_port = excluded.control_port,
                vendor_id = excluded.vendor_id,
                product_id = excluded.product_id,
                state = excluded.state,
                imei = excluded.imei,
                detail = excluded.detail,
                last_seen = excluded.last_seen,
                -- 读不到就不覆盖。生产库里出现过两行 family='0'，根因就是
                -- 当年这里是无条件覆盖（见 0017 迁移的注释）。
                family = CASE
                    WHEN excluded.family IS NULL
                      OR TRIM(excluded.family) IN ('', 'unknown')
                    THEN local_modem_discoveries.family
                    ELSE excluded.family
                END,
                -- 归属网要多轮才读得出，中间几轮是 NULL；覆盖会让闸 2 的
                -- 输入反复横跳，纳管按钮时灵时不灵。
                home_mcc = COALESCE(excluded.home_mcc, local_modem_discoveries.home_mcc),
                home_mnc = COALESCE(excluded.home_mnc, local_modem_discoveries.home_mnc)",
            params![
                discovery.candidate_key,
                discovery.usb_device,
                discovery.transport,
                discovery.control_port,
                discovery.vendor_id,
                discovery.product_id,
                discovery.state,
                discovery.imei,
                discovery.detail,
                discovery.last_seen,
                discovery.family,
                discovery.home_mcc,
                discovery.home_mnc,
            ],
        )?;
        Ok(())
    }

    /// Record where a module was just observed on the USB bus.
    ///
    /// Only ever called with an observation that was proven at the time — a
    /// module that answered QMI or AT — because this record is what a
    /// destructive recovery aims by when nothing answers any more.
    ///
    /// Any older row claiming the same bus position is deleted, not kept.
    /// Sticks do get re-enumerated onto other positions, and the alternative
    /// to eviction is two IMEIs pointing at one device: an aim that cannot be
    /// resolved is a refusal, but an aim that resolves to the wrong stick is
    /// a reset of somebody else's modem.
    pub fn remember_modem_usb_site(&self, site: &ModemUsbSite) -> Result<(), StoreError> {
        let transaction = self.conn.unchecked_transaction()?;
        transaction.execute(
            "DELETE FROM modem_usb_sites WHERE usb_device = ?1 AND imei <> ?2",
            params![site.usb_device, site.imei],
        )?;
        transaction.execute(
            "INSERT INTO modem_usb_sites (imei, usb_device, vendor_id, product_id, seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(imei) DO UPDATE SET
                usb_device = excluded.usb_device,
                vendor_id = excluded.vendor_id,
                product_id = excluded.product_id,
                seen_at = excluded.seen_at",
            params![
                site.imei,
                site.usb_device,
                site.vendor_id,
                site.product_id,
                site.seen_at,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// The last recorded bus position of one module, if there is one.
    pub fn modem_usb_site(&self, imei: &str) -> Result<Option<ModemUsbSite>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT imei, usb_device, vendor_id, product_id, seen_at
               FROM modem_usb_sites
              WHERE imei = ?1",
        )?;
        let mut rows = statement.query_map(params![imei], read_usb_site)?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Every recorded bus position, newest observation first.
    pub fn modem_usb_sites(&self) -> Result<Vec<ModemUsbSite>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT imei, usb_device, vendor_id, product_id, seen_at
               FROM modem_usb_sites
              ORDER BY seen_at DESC, imei",
        )?;
        let rows = statement
            .query_map([], read_usb_site)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// The modules this agent manages, with their latest observation.
    ///
    /// 🔴 This is what a list of modems means now, and it is a join rather
    /// than a filter for a reason: `local_modems` accumulates every module
    /// ever seen and never forgets one, so reading it directly shows hardware
    /// that was unplugged weeks ago beside hardware somebody chose. The
    /// registry decides membership; the observation only fills in the detail.
    ///
    /// A registered module with no observation yet is absent here rather than
    /// half-populated -- the caller that wants "adopted but never seen" should
    /// read the registry, which is the table that knows.
    pub fn list_managed_modems(&self) -> Result<Vec<LocalModem>, StoreError> {
        let all = self.list_local_modems()?;
        let managed: std::collections::BTreeSet<String> = self
            .registered_modems()?
            .into_iter()
            .map(|row| row.imei)
            .collect();
        Ok(all
            .into_iter()
            .filter(|modem| managed.contains(&modem.imei))
            .collect())
    }

    pub fn list_local_modems(&self) -> Result<Vec<LocalModem>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT imei, family, firmware, msisdn, msisdn_iccid, apn_contexts,
                    iccid, state, last_seen, mcc, mnc, home_mcc, home_mnc, imsi,
                    discovery, manageable, control_port
               FROM local_modems
              ORDER BY imei",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok(LocalModem {
                    imei: row.get(0)?,
                    family: row.get(1)?,
                    firmware: row.get(2)?,
                    msisdn: row.get(3)?,
                    msisdn_iccid: row.get(4)?,
                    apn_contexts: row.get(5)?,
                    iccid: row.get(6)?,
                    state: row.get(7)?,
                    last_seen: row.get(8)?,
                    mcc: row.get(9)?,
                    mnc: row.get(10)?,
                    home_mcc: row.get(11)?,
                    home_mnc: row.get(12)?,
                    imsi: row.get(13)?,
                    discovery: row.get(14)?,
                    manageable: row.get::<_, i64>(15)? != 0,
                    control_port: row.get(16)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn list_local_modem_discoveries(&self) -> Result<Vec<LocalModemDiscovery>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT candidate_key, usb_device, transport, control_port, vendor_id, product_id,
                    state, imei, detail, last_seen, family, home_mcc, home_mnc
               FROM local_modem_discoveries
              ORDER BY last_seen DESC, candidate_key",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok(LocalModemDiscovery {
                    candidate_key: row.get(0)?,
                    usb_device: row.get(1)?,
                    transport: row.get(2)?,
                    control_port: row.get(3)?,
                    vendor_id: row.get(4)?,
                    product_id: row.get(5)?,
                    state: row.get(6)?,
                    imei: row.get(7)?,
                    detail: row.get(8)?,
                    last_seen: row.get(9)?,
                    family: row.get(10)?,
                    home_mcc: row.get(11)?,
                    home_mnc: row.get(12)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Forget candidates nothing has seen for a while.
    ///
    /// A candidate row is evidence that an endpoint was there. USB topology is
    /// what the key is derived from, so a module that re-enumerates onto a
    /// different bus path becomes a *new* key rather than an update to the old
    /// one -- and the old one stays, describing an endpoint that no longer
    /// exists. After a few re-plugs the list is mostly history: on this bench,
    /// 2026-08-31, sixteen rows for four modules, with one port name appearing
    /// against three different IMEIs.
    ///
    /// Approved candidates are pruned too, and deliberately. An approval is
    /// stored separately in `manual_modem_profiles` and is matched back by
    /// endpoint, so dropping the observation does not withdraw the approval --
    /// it drops the sighting, which is the thing that has expired.
    pub fn forget_stale_discoveries(&self, before: i64) -> Result<usize, StoreError> {
        let removed = self.conn.execute(
            "DELETE FROM local_modem_discoveries WHERE last_seen < ?1",
            [before],
        )?;
        Ok(removed)
    }

    /// Save an operator's approval of an automatically discovered candidate.
    ///
    /// `candidate_key` is intentionally the identity here: a profile cannot
    /// manufacture a modem from an arbitrary port, and live discovery must
    /// still match the approved candidate before it can be used.
    pub fn upsert_manual_modem_profile(
        &self,
        profile: &ManualModemProfile,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO manual_modem_profiles
                (candidate_key, usb_device, vendor_id, product_id, control_port, approved_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(candidate_key) DO UPDATE SET
                usb_device = excluded.usb_device,
                vendor_id = excluded.vendor_id,
                product_id = excluded.product_id,
                control_port = excluded.control_port,
                approved_at = excluded.approved_at",
            params![
                profile.candidate_key,
                profile.usb_device,
                profile.vendor_id,
                profile.product_id,
                profile.control_port,
                profile.approved_at,
            ],
        )?;
        Ok(())
    }

    /// Return operator-approved candidates, with the latest approval first.
    pub fn list_manual_modem_profiles(&self) -> Result<Vec<ManualModemProfile>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT candidate_key, usb_device, vendor_id, product_id, control_port, approved_at
               FROM manual_modem_profiles
              ORDER BY approved_at DESC, candidate_key",
        )?;
        let rows = statement
            .query_map([], read_manual_modem_profile)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Withdraw an operator approval. Returns whether a saved profile existed.
    pub fn remove_manual_modem_profile(&self, candidate_key: &str) -> Result<bool, StoreError> {
        let removed = self.conn.execute(
            "DELETE FROM manual_modem_profiles WHERE candidate_key = ?1",
            params![candidate_key],
        )?;
        Ok(removed != 0)
    }

    /// Store the capability matrix the cloud just pushed.
    ///
    /// Called after the agent has accepted and parsed it, so a document that
    /// reaches here is one that already governs behaviour. Storing it before
    /// the parse would leave a restart loading something the running agent had
    /// rejected.
    pub fn save_capability_matrix(
        &self,
        version: &str,
        sha256: &str,
        document: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO capability_matrix (id, version, sha256, document, installed_at)
             VALUES (1, ?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET
                version = excluded.version,
                sha256 = excluded.sha256,
                document = excluded.document,
                installed_at = excluded.installed_at",
            params![version, sha256, document, now],
        )?;
        Ok(())
    }

    /// The matrix to start from, or `None` to fall back to the built-in one.
    pub fn capability_matrix(&self) -> Result<Option<(String, String, String)>, StoreError> {
        let row = self
            .conn
            .query_row(
                "SELECT version, sha256, document FROM capability_matrix WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        Ok(row)
    }

    /// Record the number read off one module, and the card it came from.
    ///
    /// A direct write rather than part of the modem upsert, because `None`
    /// here is a real answer: it records that this card was asked and had
    /// nothing to say, which is what stops the question being asked again on
    /// every poll. The upsert's COALESCE would discard exactly that.
    pub fn set_modem_msisdn(
        &self,
        imei: &str,
        msisdn: Option<&str>,
        iccid: Option<&str>,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE local_modems SET msisdn = ?2, msisdn_iccid = ?3 WHERE imei = ?1",
            params![imei, msisdn, iccid],
        )?;
        Ok(())
    }

    /// Replace a module's cached context table.
    ///
    /// `fill_apn_contexts` re-reads the module only when the card changes, so
    /// after a write the cache is the stale copy an operator would be shown --
    /// they would edit an APN, get an `OK`, and watch the console go on
    /// reporting the old one until the stick was moved to another card. This
    /// is how the write puts its own result back.
    pub fn set_apn_contexts(&self, imei: &str, contexts: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE local_modems SET apn_contexts = ?2 WHERE imei = ?1",
            params![imei, contexts],
        )?;
        Ok(())
    }

    /// Replace the whole card policy set with what the cloud just pushed.
    ///
    /// A replacement rather than an upsert, in one transaction. The cloud sends
    /// the complete set every time, so a card it has stopped listing has had
    /// its policy withdrawn -- and an upsert would leave that card's old rules
    /// in force here for as long as the stick stayed in the machine. Doing it
    /// in a transaction is what keeps a failure halfway through from leaving
    /// the device with neither the old set nor the new one.
    ///
    /// Returns how many rows the set now holds.
    pub fn replace_card_policies(
        &mut self,
        policies: &[CardPolicy],
        policy_version: &str,
        now: i64,
    ) -> Result<usize, StoreError> {
        let transaction = self.conn.transaction()?;
        transaction.execute("DELETE FROM card_policies", [])?;
        for policy in policies {
            transaction.execute(
                "INSERT INTO card_policies
                    (iccid, cellular_enabled, vertical, apn, policy_version, updated_at,
                     sms_send, sms_receive, data, voice)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    policy.iccid,
                    policy.cellular_enabled as i64,
                    policy.vertical,
                    policy.apn,
                    policy_version,
                    now,
                    policy.sms_send.map(|value| value as i64),
                    policy.sms_receive.map(|value| value as i64),
                    policy.data.map(|value| value as i64),
                    policy.voice.map(|value| value as i64),
                ],
            )?;
        }
        transaction.commit()?;
        Ok(policies.len())
    }

    /// The card policy for one ICCID, if the cloud has pushed one.
    pub fn card_policy(&self, iccid: &str) -> Result<Option<CardPolicy>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT iccid, cellular_enabled, vertical, apn,
                    sms_send, sms_receive, data, voice
               FROM card_policies
              WHERE iccid = ?1",
        )?;
        let mut rows = statement.query_map(params![iccid], read_card_policy)?;
        Ok(rows.next().transpose()?)
    }

    /// Every card policy currently in force, for the panel and for diagnosis.
    pub fn list_card_policies(&self) -> Result<Vec<CardPolicy>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT iccid, cellular_enabled, vertical, apn,
                    sms_send, sms_receive, data, voice
               FROM card_policies
              ORDER BY iccid",
        )?;
        let rows = statement
            .query_map([], read_card_policy)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// The version string the current set was pushed under, if there is a set.
    pub fn card_policy_version(&self) -> Result<Option<String>, StoreError> {
        let mut statement = self
            .conn
            .prepare("SELECT policy_version FROM card_policies LIMIT 1")?;
        let mut rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        Ok(rows.next().transpose()?)
    }
}

/// One card's policy, as the cloud last pushed it.
///
/// Deliberately the same four fields the contract carries and no more. The
/// edge stores what it was told rather than an interpretation of it: deciding
/// what `vertical` means is the job of whatever consumes the policy, and a
/// value this agent does not recognise still has to survive being written down
/// so that a newer build can act on it without a re-push.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CardPolicy {
    pub iccid: String,
    pub cellular_enabled: bool,
    pub vertical: String,
    pub apn: Option<String>,
    /// What the operator says this plan is sold as doing. `None` is
    /// undeclared; `Some(false)` withholds. See the 0012 migration.
    pub sms_send: Option<bool>,
    pub sms_receive: Option<bool>,
    pub data: Option<bool>,
    pub voice: Option<bool>,
}

fn read_card_policy(row: &rusqlite::Row<'_>) -> rusqlite::Result<CardPolicy> {
    // Three states, so each reads through Option rather than defaulting: a
    // column nobody has filled in is not the same record as one filled in
    // with "no".
    let flag = |index: usize| -> rusqlite::Result<Option<bool>> {
        Ok(row.get::<_, Option<i64>>(index)?.map(|value| value != 0))
    };
    Ok(CardPolicy {
        iccid: row.get(0)?,
        cellular_enabled: row.get::<_, i64>(1)? != 0,
        vertical: row.get(2)?,
        apn: row.get(3)?,
        sms_send: flag(4)?,
        sms_receive: flag(5)?,
        data: flag(6)?,
        voice: flag(7)?,
    })
}

/// One locally cached SMS row for the offline panel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalMessage {
    pub seq: u64,
    pub peer: String,
    pub body: String,
    pub bearer: String,
    pub direction: String,
    pub received_at: i64,
    pub modem_imei: Option<String>,
}

/// One locally observed modem for the offline panel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalModem {
    pub imei: String,
    pub family: String,
    /// Firmware revision, carried between polls rather than re-read: it
    /// changes only when the module is flashed.
    pub firmware: Option<String>,
    /// The card's own number, and the card it was read from. The second is
    /// what stops a number outliving its card on an eUICC profile switch.
    pub msisdn: Option<String>,
    pub msisdn_iccid: Option<String>,
    /// Packet data profiles, as the JSON the agent last read. `None` means
    /// they have not been read; an empty array means the module held none.
    pub apn_contexts: Option<String>,
    pub iccid: Option<String>,
    pub state: String,
    pub last_seen: Option<i64>,
    /// Serving network, when the modem is registered somewhere. Absent while
    /// it is searching, which is itself worth showing.
    pub mcc: Option<u16>,
    pub mnc: Option<u16>,
    /// Home network from the card's IMSI. On a roaming card this differs from
    /// the serving network, and it is the one that says which SIM this is.
    pub home_mcc: Option<u16>,
    pub home_mnc: Option<u16>,
    pub imsi: Option<String>,
    /// The transport that identified the modem: `qmi` is command-capable;
    /// `at` is a visible fallback only.
    pub discovery: String,
    /// Whether structured agent actions can safely target this modem.
    pub manageable: bool,
    /// The endpoint observed on the latest successful poll.
    pub control_port: Option<String>,
}

/// One observed QMI or serial endpoint, including endpoints that did not
/// yield an IMEI and therefore cannot be inventory records yet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalModemDiscovery {
    pub candidate_key: String,
    pub usb_device: Option<String>,
    pub transport: String,
    pub control_port: String,
    pub vendor_id: Option<String>,
    pub product_id: Option<String>,
    pub state: String,
    pub imei: Option<String>,
    pub detail: String,
    pub last_seen: i64,
    /// 这一根是什么型号 —— 纳管闸 2 的第一个输入。
    ///
    /// 在候选行上而不是只在 `local_modems` 上：inventory 只装已纳管的模组，
    /// 从那里取闸的输入就成了「先被纳管才能被纳管」（见 0017 迁移）。
    pub family: Option<String>,
    /// 卡归属的 MCC/MNC —— 闸 2 的第二个输入，运营商画像从这里推。
    ///
    /// 读不到就是 `None`，**不回落到「国际卡」**。那个兜底在报告和路由里
    /// 说得通，在一道闸上是失败即放行：一张还没读出 IMSI 的卡会被当成国际卡
    /// 去过闸。
    pub home_mcc: Option<u16>,
    pub home_mnc: Option<u16>,
}

/// An operator-approved configuration for a discovered modem candidate.
///
/// The optional USB identifiers are evidence captured when the candidate was
/// approved. They are not used as a replacement for active discovery: USB
/// topology and Linux endpoint names can change when a device re-enumerates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManualModemProfile {
    pub candidate_key: String,
    pub usb_device: Option<String>,
    pub vendor_id: Option<String>,
    pub product_id: Option<String>,
    pub control_port: String,
    /// Unix milliseconds when the operator approved or last updated it.
    pub approved_at: i64,
}

fn read_retirement(row: &rusqlite::Row<'_>) -> rusqlite::Result<Retirement> {
    Ok(Retirement {
        imei: row.get(0)?,
        registered_at: row.get(1)?,
        registered_by: row.get(2)?,
        family: row.get(3)?,
        usb_device: row.get(4)?,
        retired_at: row.get(5)?,
        reason: row.get(6)?,
        detail: row.get(7)?,
        matrix_version: row.get(8)?,
    })
}

fn read_manual_modem_profile(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<ManualModemProfile> {
    Ok(ManualModemProfile {
        candidate_key: row.get(0)?,
        usb_device: row.get(1)?,
        vendor_id: row.get(2)?,
        product_id: row.get(3)?,
        control_port: row.get(4)?,
        approved_at: row.get(5)?,
    })
}

/// Where one module was last proven to sit on the USB bus.
///
/// The bus position (`4-3`) is the field that matters. A `cdc-wdm` number is
/// reassigned every time the driver rebinds — the bench watched `cdc-wdm2`
/// come back on a stick it had not been on — whereas the position only moves
/// when the stick itself is re-attached. `vendor_id`/`product_id` are carried
/// so a recorded position can be checked against what is at that position
/// now, instead of being believed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModemUsbSite {
    pub imei: String,
    pub usb_device: String,
    pub vendor_id: String,
    pub product_id: String,
    /// Unix milliseconds of the observation, so an aim can say how old the
    /// evidence it used was.
    pub seen_at: i64,
}

fn read_usb_site(row: &rusqlite::Row<'_>) -> rusqlite::Result<ModemUsbSite> {
    Ok(ModemUsbSite {
        imei: row.get(0)?,
        usb_device: row.get(1)?,
        vendor_id: row.get(2)?,
        product_id: row.get(3)?,
        seen_at: row.get(4)?,
    })
}

/// One persisted outbox row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxRow {
    pub seq: u64,
    pub envelope_id: String,
    pub kind: String,
    pub payload: Vec<u8>,
    pub protected: bool,
}

/// Persistence errors.
#[derive(Debug)]
pub enum StoreError {
    Sqlite(rusqlite::Error),
    InvalidTarget { current: i64, target: i64 },
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(error) => write!(formatter, "sqlite: {error}"),
            Self::InvalidTarget { current, target } => {
                write!(formatter, "cannot roll schema from {current} to {target}")
            }
        }
    }
}

impl Error for StoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

#[cfg(test)]
mod usb_site_tests {
    use super::*;

    fn site(imei: &str, device: &str, seen_at: i64) -> ModemUsbSite {
        ModemUsbSite {
            imei: imei.into(),
            usb_device: device.into(),
            vendor_id: "2c7c".into(),
            product_id: "0125".into(),
            seen_at,
        }
    }

    /// The whole reason this table exists: the index the agent aimed by lived
    /// in memory, so a restart left the one recovery for a desynced module
    /// with nothing to aim at.
    #[test]
    fn a_recorded_position_outlives_the_process() {
        let store = Store::open_in_memory().expect("open");
        store
            .remember_modem_usb_site(&site("867018069509705", "4-3", 100))
            .expect("remember");
        let found = store
            .modem_usb_site("867018069509705")
            .expect("read")
            .expect("recorded");
        assert_eq!(found.usb_device, "4-3");
        assert_eq!(found.vendor_id, "2c7c");
        assert_eq!(found.seen_at, 100);
    }

    #[test]
    fn a_module_that_was_never_seen_has_no_position() {
        let store = Store::open_in_memory().expect("open");
        assert_eq!(store.modem_usb_site("862547055142811").expect("read"), None);
    }

    /// A stick that re-enumerates onto another position must not leave its old
    /// claim behind. Two rows pointing at one bus position is precisely the
    /// state in which a reset aimed at one IMEI lands on another module.
    #[test]
    fn the_newest_observation_evicts_the_older_claim() {
        let store = Store::open_in_memory().expect("open");
        store
            .remember_modem_usb_site(&site("862547055142811", "4-2", 100))
            .expect("first");
        store
            .remember_modem_usb_site(&site("867018069514820", "4-2", 200))
            .expect("second");

        assert_eq!(store.modem_usb_site("862547055142811").expect("read"), None);
        assert_eq!(
            store
                .modem_usb_site("867018069514820")
                .expect("read")
                .expect("recorded")
                .usb_device,
            "4-2"
        );
        let all = store.modem_usb_sites().expect("list");
        assert_eq!(all.len(), 1, "one position, one claimant: {all:?}");
    }

    #[test]
    fn a_module_that_moved_keeps_one_row() {
        let store = Store::open_in_memory().expect("open");
        store
            .remember_modem_usb_site(&site("867018069509705", "4-3", 100))
            .expect("first");
        store
            .remember_modem_usb_site(&site("867018069509705", "4-1", 200))
            .expect("moved");
        let all = store.modem_usb_sites().expect("list");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].usb_device, "4-1");
        assert_eq!(all[0].seen_at, 200);
    }

    #[test]
    fn positions_survive_a_rollback_and_replay() {
        let mut store = Store::open_in_memory().expect("open");
        store.rollback_to(0).expect("rollback");
        store.migrate().expect("re-upgrade");
        store
            .remember_modem_usb_site(&site("867018069509705", "4-3", 100))
            .expect("remember after rebuild");
        assert!(store.modem_usb_site("867018069509705").expect("read").is_some());
    }
}

#[cfg(test)]
mod ingested_sms_tests {
    use super::*;

    const IMEI: &str = "867018069509705";

    #[test]
    fn a_fragment_nobody_stored_is_not_on_the_books() {
        let store = Store::open_in_memory().expect("open");
        assert_eq!(store.ingested_sms_copies(IMEI, "v1|10086|1|0000|1|1|a").expect("read"), 0);
    }

    /// The point of the table: what we stored is remembered across restarts,
    /// so a message the modem now calls "read" is still recognised as ours
    /// rather than as something new.
    #[test]
    fn a_recorded_fragment_outlives_the_process() {
        let store = Store::open_in_memory().expect("open");
        let fingerprint = "v1|10086|1756058516000|00c3|4|1|deadbeefdeadbeef".to_string();
        store
            .record_ingested_sms(IMEI, std::slice::from_ref(&fingerprint), 100)
            .expect("record");
        assert_eq!(store.ingested_sms_copies(IMEI, &fingerprint).expect("read"), 1);
    }

    /// Two deliveries of one message are two messages, and the count is what
    /// keeps the second one from being mistaken for an echo of the first.
    #[test]
    fn a_second_copy_is_counted_not_collapsed() {
        let store = Store::open_in_memory().expect("open");
        let fingerprint = "v1|10086|1756058516000|00c3|4|1|deadbeefdeadbeef".to_string();
        store.record_ingested_sms(IMEI, &[fingerprint.clone()], 100).expect("first");
        store.record_ingested_sms(IMEI, &[fingerprint.clone()], 200).expect("second");
        assert_eq!(store.ingested_sms_copies(IMEI, &fingerprint).expect("read"), 2);
    }

    /// Books are per module. The same 10086 text arriving on two cards is two
    /// messages, and one card's ledger must not silence the other's.
    #[test]
    fn one_modules_books_do_not_answer_for_another() {
        let store = Store::open_in_memory().expect("open");
        let fingerprint = "v1|10086|1756058516000|0000|1|1|deadbeefdeadbeef".to_string();
        store.record_ingested_sms(IMEI, &[fingerprint.clone()], 100).expect("record");
        assert_eq!(
            store.ingested_sms_copies("867018069514820", &fingerprint).expect("read"),
            0
        );
    }

    #[test]
    fn pruning_keeps_the_newest_and_leaves_other_modules_alone() {
        let store = Store::open_in_memory().expect("open");
        for index in 0..10 {
            store
                .record_ingested_sms(IMEI, &[format!("v1|10086|{index}|0000|1|1|00")], index)
                .expect("record");
        }
        store
            .record_ingested_sms("867018069514820", &["v1|10086|0|0000|1|1|00".into()], 0)
            .expect("other module");

        assert_eq!(store.prune_ingested_sms(IMEI, 4).expect("prune"), 6);
        assert_eq!(store.ingested_sms_len(IMEI).expect("count"), 4);
        assert_eq!(
            store.ingested_sms_copies(IMEI, "v1|10086|9|0000|1|1|00").expect("newest"),
            1,
            "the newest entry is the one that must survive"
        );
        assert_eq!(
            store.ingested_sms_copies(IMEI, "v1|10086|0|0000|1|1|00").expect("oldest"),
            0
        );
        assert_eq!(store.ingested_sms_len("867018069514820").expect("count"), 1);
    }

    #[test]
    fn the_books_survive_a_rollback_and_replay() {
        let mut store = Store::open_in_memory().expect("open");
        store.rollback_to(0).expect("rollback");
        store.migrate().expect("re-upgrade");
        let fingerprint = "v1|10086|1|0000|1|1|00".to_string();
        store
            .record_ingested_sms(IMEI, &[fingerprint.clone()], 1)
            .expect("record after rebuild");
        assert_eq!(store.ingested_sms_copies(IMEI, &fingerprint).expect("read"), 1);
    }
}

/// One module an operator chose to manage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredModem {
    pub imei: String,
    pub registered_at: i64,
    /// `panel`, `cloud`, or `migration`.
    pub registered_by: String,
    /// What it looked like when adopted. Evidence, never a lookup key.
    pub usb_device: Option<String>,
    pub family: Option<String>,
    pub note: Option<String>,
}

/// 一根已纳管模组当前的「闸不再满足」标记。
///
/// 🔴 标记不是删除。带着它的模组**仍然被管理**、仍然被轮询、仍然出现在
/// `managed_imeis` 里。这是自动化「先说、后做」里的那个「说」。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GateFailure {
    /// 第一次判为「该解绑」的时刻。**不会被后续的趟数推后**，
    /// 否则倒计时永远走不完。
    pub since: i64,
    pub reason: String,
    pub passes: u32,
}

/// 一条被追溯执行摘掉的纳管履历。
///
/// 0015 说 `registered_by` 存在的理由是「why is this being managed 是别人对
/// 一个没人记得添加过的模组问的第一个问题」。自动解绑会把那个答案从库里彻底
/// 抹掉，这张表就是答案的去处 —— 它回答那个问题的镜像：为什么这根不再被管了。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Retirement {
    pub imei: String,
    pub registered_at: i64,
    pub registered_by: String,
    pub family: Option<String>,
    pub usb_device: Option<String>,
    pub retired_at: i64,
    /// `no_strategy` 或 `never_measured`。
    pub reason: String,
    pub detail: Option<String>,
    pub matrix_version: Option<String>,
}

impl Store {
    /// Adopt a module, or refresh the evidence on one already adopted.
    ///
    /// Idempotent on IMEI: adopting twice is not an error, because the two
    /// paths that can do it -- the panel and a cloud command -- can race, and
    /// the second one arriving is not a fault worth reporting to anybody.
    pub fn register_modem(&self, modem: &RegisteredModem) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO registered_modems
                 (imei, registered_at, registered_by, usb_device, family, note)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(imei) DO UPDATE SET
                 usb_device = excluded.usb_device,
                 family = COALESCE(excluded.family, registered_modems.family),
                 -- 纳管是一次**新的决定**，倒计时归零。
                 --
                 -- 场景：运维看到「闸不再满足，还需 8 分钟」的告警，查过之后
                 -- 认定那是一次矩阵手误，于是把这一根重新纳管一次以示确认。
                 -- 留着旧的 gate_failed_since，下一趟真判定会带着那个旧起点
                 -- 立刻到期 —— 运维那个动作不但没有重置倒计时，反而什么都
                 -- 没改变，而他以为自己救回来了。
                 --
                 -- ⚠️ 只清这三列。registered_at / registered_by / note 依旧
                 -- 不动（0015 的保证，tests/registered_modems.rs 钉着）：
                 -- 「重复纳管」不是「重新纳管」，首次纳管的履历不该被改写。
                 gate_failed_since = NULL,
                 gate_failed_reason = NULL,
                 gate_failed_passes = 0",
            params![
                modem.imei,
                modem.registered_at,
                modem.registered_by,
                modem.usb_device,
                modem.family,
                modem.note,
            ],
        )?;
        Ok(())
    }

    /// Stop managing a module.
    ///
    /// 🔴 History is deliberately untouched. Messages it carried, commands it
    /// ran and the rows it wrote stay exactly where they are -- unmanaging a
    /// stick is a statement about the future, not a retraction of what it did.
    /// Returns whether a row was actually removed, so a caller can tell
    /// "unregistered it" from "it was never registered".
    pub fn unregister_modem(&self, imei: &str) -> Result<bool, StoreError> {
        let removed = self
            .conn
            .execute("DELETE FROM registered_modems WHERE imei = ?1", params![imei])?;
        Ok(removed > 0)
    }

    pub fn is_registered(&self, imei: &str) -> Result<bool, StoreError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM registered_modems WHERE imei = ?1",
            params![imei],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Everything this agent is managing, oldest adoption first.
    /// 记下「这一趟依然判为该解绑」，并推进倒计时。
    ///
    /// 🔴 `COALESCE(gate_failed_since, ?2)`：起点只在**第一趟**写入。
    /// 每趟都刷新起点的话，倒计时永远走不到 30 分钟，隔离期就成了
    /// 一个永远不到期的摆设 —— 那和关掉这个特性没有区别，但看起来像开着。
    pub fn mark_gate_failure(&self, imei: &str, reason: &str, now: i64) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE registered_modems
                SET gate_failed_since = COALESCE(gate_failed_since, ?2),
                    gate_failed_reason = ?3,
                    gate_failed_passes = gate_failed_passes + 1
              WHERE imei = ?1",
            params![imei, now, reason],
        )?;
        Ok(())
    }

    /// 闸又过了：把标记和倒计时一起清掉。
    ///
    /// 这是自愈发生的地方。云端手误推了一份规则更少的矩阵、十分钟内补回来，
    /// 这个场景里一根都不会被删，也不需要任何人做任何事。
    pub fn clear_gate_failure(&self, imei: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE registered_modems
                SET gate_failed_since = NULL,
                    gate_failed_reason = NULL,
                    gate_failed_passes = 0
              WHERE imei = ?1",
            params![imei],
        )?;
        Ok(())
    }

    /// 一根模组当前的闸标记。
    pub fn gate_failure(&self, imei: &str) -> Result<Option<GateFailure>, StoreError> {
        let row = self.conn.query_row(
            "SELECT gate_failed_since, gate_failed_reason, gate_failed_passes
               FROM registered_modems WHERE imei = ?1",
            params![imei],
            |row| {
                let since: Option<i64> = row.get(0)?;
                let reason: Option<String> = row.get(1)?;
                let passes: i64 = row.get(2)?;
                Ok(since.map(|since| GateFailure {
                    since,
                    reason: reason.unwrap_or_default(),
                    passes: passes.max(0) as u32,
                }))
            },
        );
        match row {
            Ok(value) => Ok(value),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// 摘掉一根：履历搬进退休表，纳管行删掉。**一个事务。**
    ///
    /// 🔴 两步必须同生共死。先删后写，中间掉电就永久丢掉了「为什么不再管它」；
    /// 先写后删，中间掉电就留下一条说着「已退休」而实际还在被管的记录，
    /// 而下一趟判定会看到它仍然纳管、再写一次退休行。
    pub fn retire_modem(&mut self, retirement: &Retirement) -> Result<bool, StoreError> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO registration_retirements
                 (imei, registered_at, registered_by, family, usb_device,
                  retired_at, reason, detail, matrix_version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(imei) DO UPDATE SET
                 retired_at = excluded.retired_at,
                 reason = excluded.reason,
                 detail = excluded.detail,
                 matrix_version = excluded.matrix_version",
            params![
                retirement.imei,
                retirement.registered_at,
                retirement.registered_by,
                retirement.family,
                retirement.usb_device,
                retirement.retired_at,
                retirement.reason,
                retirement.detail,
                retirement.matrix_version,
            ],
        )?;
        let removed = tx.execute(
            "DELETE FROM registered_modems WHERE imei = ?1",
            params![retirement.imei],
        )?;
        tx.commit()?;
        Ok(removed > 0)
    }

    /// 这根之前有没有被追溯执行摘掉过。
    ///
    /// 重新纳管时读它来复原履历：一次十分钟就修好的云端手误，不该让六条
    /// 纳管履历被永久改写成今天。
    pub fn retired_registration(&self, imei: &str) -> Result<Option<Retirement>, StoreError> {
        let row = self.conn.query_row(
            "SELECT imei, registered_at, registered_by, family, usb_device,
                    retired_at, reason, detail, matrix_version
               FROM registration_retirements WHERE imei = ?1",
            params![imei],
            read_retirement,
        );
        match row {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub fn list_retirements(&self) -> Result<Vec<Retirement>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT imei, registered_at, registered_by, family, usb_device,
                    retired_at, reason, detail, matrix_version
               FROM registration_retirements ORDER BY retired_at DESC, imei",
        )?;
        let rows = statement
            .query_map([], read_retirement)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// 履历已经复原到纳管行里了，退休记录可以走了。
    pub fn forget_retirement(&self, imei: &str) -> Result<bool, StoreError> {
        let removed = self.conn.execute(
            "DELETE FROM registration_retirements WHERE imei = ?1",
            params![imei],
        )?;
        Ok(removed > 0)
    }

    pub fn registered_modems(&self) -> Result<Vec<RegisteredModem>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT imei, registered_at, registered_by, usb_device, family, note
               FROM registered_modems
              ORDER BY registered_at, imei",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(RegisteredModem {
                imei: row.get(0)?,
                registered_at: row.get(1)?,
                registered_by: row.get(2)?,
                usb_device: row.get(3)?,
                family: row.get(4)?,
                note: row.get(5)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }
}
