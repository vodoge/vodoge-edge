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
];

/// An opened edge database with migrations applied.
pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
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
