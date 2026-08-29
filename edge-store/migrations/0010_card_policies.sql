-- Per-card policy as the cloud last pushed it.
--
-- Keyed by ICCID rather than by modem, matching the cloud: a policy belongs to
-- the subscription, not to the stick it is in today. On an eUICC the ICCID is
-- what changes when a profile is switched, which is exactly when a different
-- policy should take effect.
--
-- The whole set is replaced on every push, so a card dropped upstream stops
-- having a policy here too. `policy_version` is stored on each row rather than
-- in a table of its own: there is only ever one version present, and keeping it
-- beside the rows means a partially applied push cannot leave a version claiming
-- to describe rows that were never written.
CREATE TABLE IF NOT EXISTS card_policies (
    iccid            TEXT PRIMARY KEY,
    cellular_enabled INTEGER NOT NULL,
    vertical         TEXT NOT NULL,
    apn              TEXT,
    policy_version   TEXT NOT NULL,
    updated_at       INTEGER NOT NULL
);
