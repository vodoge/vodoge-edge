//! SQLite persistence for the edge agent.
//!
//! Schema migrations are versioned integers. Upgrade and rollback are both
//! tested so a failed edge update can return to the previous database.

use std::{error::Error, fmt, path::Path};

use rusqlite::{params, Connection};

const MIGRATIONS: &[&str] = &[include_str!("../migrations/0001_init.sql")];

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
