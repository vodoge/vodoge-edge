-- The capability matrix the cloud last pushed.
--
-- Without this the push does not survive a restart: `live_matrix` is seeded
-- unconditionally from the built-in TOML at startup and the pushed document
-- lived only in memory, so every agent restart silently reverted the fleet to
-- the compiled-in rules. The cloud does not re-send -- that command is already
-- `succeeded` -- so nothing put it back.
--
-- It was not a theoretical gap. The support ledger published on 2026-08-29 was
-- in force, verified on the bench, and then lost to the next deploy; the China
-- Telecom pairing it had authorised went back to being refused as untested,
-- with nothing anywhere saying why.
--
-- The document is stored verbatim rather than re-serialised from the parsed
-- matrix. A round trip through the parser would have to reproduce the fallback
-- and the rule ordering exactly, and the digest the cloud computed is over the
-- bytes it sent -- so the bytes are what is kept.
--
-- One row, enforced by the primary key: there is one live matrix, and a table
-- that could hold two would need a rule for which one wins.
CREATE TABLE IF NOT EXISTS capability_matrix (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    version      TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    document     TEXT NOT NULL,
    installed_at INTEGER NOT NULL
);
