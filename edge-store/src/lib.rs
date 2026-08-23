//! SQLite persistence for the edge agent.
//!
//! Schema migrations are versioned integers. Upgrade and rollback are both
//! tested so a failed edge update can return to the previous database.

use std::{error::Error, fmt, path::Path};

mod outbox;

use rusqlite::{params, Connection, OptionalExtension};

pub use outbox::{CapacityAlert, DurableOutbox, QueueError, DEFAULT_MAX_RECORDS};

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

const MIGRATIONS: &[&str] = &[
    include_str!("../migrations/0001_init.sql"),
    include_str!("../migrations/0002_cursor.sql"),
    include_str!("../migrations/0003_local_inbox.sql"),
    include_str!("../migrations/0004_modem_network.sql"),
    include_str!("../migrations/0005_modem_home.sql"),
    MODEM_USB_SITES,
    INGESTED_SMS,
];

/// An opened edge database with migrations applied.
pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let _ = conn.pragma_update(None, "journal_mode", "WAL");
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
            self.conn.execute_batch("DROP TABLE IF EXISTS ingested_sms;")?;
            self.conn.execute_batch("DROP TABLE IF EXISTS modem_usb_sites;")?;
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
        self.conn.execute(
            "INSERT INTO local_modems (imei, family, iccid, state, last_seen, mcc, mnc, home_mcc, home_mnc, imsi)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(imei) DO UPDATE SET
                family = excluded.family,
                iccid = excluded.iccid,
                state = excluded.state,
                last_seen = excluded.last_seen,
                -- A poll taken while the modem is searching reports no network.
                -- Keeping the last known one stops the card's identity from
                -- blinking out every time it re-registers.
                mcc = COALESCE(excluded.mcc, local_modems.mcc),
                mnc = COALESCE(excluded.mnc, local_modems.mnc),
                -- A read that failed leaves the card's identity alone rather
                -- than blanking it; one bad poll must not lose what is known.
                home_mcc = COALESCE(excluded.home_mcc, local_modems.home_mcc),
                home_mnc = COALESCE(excluded.home_mnc, local_modems.home_mnc),
                imsi = COALESCE(excluded.imsi, local_modems.imsi)",
            params![
                modem.imei,
                modem.family,
                modem.iccid,
                modem.state,
                modem.last_seen,
                modem.mcc,
                modem.mnc,
                modem.home_mcc,
                modem.home_mnc,
                modem.imsi,
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

    pub fn list_local_modems(&self) -> Result<Vec<LocalModem>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT imei, family, iccid, state, last_seen, mcc, mnc, home_mcc, home_mnc, imsi
               FROM local_modems
              ORDER BY imei",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok(LocalModem {
                    imei: row.get(0)?,
                    family: row.get(1)?,
                    iccid: row.get(2)?,
                    state: row.get(3)?,
                    last_seen: row.get(4)?,
                    mcc: row.get(5)?,
                    mnc: row.get(6)?,
                    home_mcc: row.get(7)?,
                    home_mnc: row.get(8)?,
                    imsi: row.get(9)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }
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
