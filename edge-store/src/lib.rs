//! SQLite persistence for the edge agent.
//!
//! Schema migrations are versioned integers. Upgrade and rollback are both
//! tested so a failed edge update can return to the previous database.

use std::{error::Error, fmt, path::Path};

mod outbox;

use rusqlite::{params, Connection};

pub use outbox::{CapacityAlert, DurableOutbox, QueueError, DEFAULT_MAX_RECORDS};

const MIGRATIONS: &[&str] = &[
    include_str!("../migrations/0001_init.sql"),
    include_str!("../migrations/0002_cursor.sql"),
    include_str!("../migrations/0003_local_inbox.sql"),
    include_str!("../migrations/0004_modem_network.sql"),
    include_str!("../migrations/0005_modem_home.sql"),
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
