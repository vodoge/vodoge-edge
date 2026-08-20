CREATE TABLE IF NOT EXISTS uplink_cursor (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    committed_through INTEGER NOT NULL,
    last_allocated INTEGER NOT NULL
);

INSERT OR IGNORE INTO uplink_cursor (id, committed_through, last_allocated)
VALUES (1, 0, 0);
