CREATE TABLE IF NOT EXISTS uplink_outbox (
    seq INTEGER PRIMARY KEY,
    envelope_id TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    payload BLOB NOT NULL,
    protected INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS uplink_gaps (
    gap_id TEXT PRIMARY KEY,
    ranges TEXT NOT NULL,
    reason TEXT NOT NULL,
    accepted INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
