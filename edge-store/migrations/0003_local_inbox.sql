CREATE TABLE IF NOT EXISTS local_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    seq INTEGER NOT NULL UNIQUE,
    peer TEXT NOT NULL,
    body TEXT NOT NULL,
    bearer TEXT NOT NULL,
    direction TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    modem_imei TEXT
);

CREATE TABLE IF NOT EXISTS local_modems (
    imei TEXT PRIMARY KEY,
    family TEXT NOT NULL,
    iccid TEXT,
    state TEXT NOT NULL,
    last_seen INTEGER
);
