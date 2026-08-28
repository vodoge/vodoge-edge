-- The local panel has to distinguish a fully manageable QMI modem from a
-- module that is merely visible over AT. Keeping that fact beside the local
-- inventory prevents the latter from disappearing after a page refresh.
ALTER TABLE local_modems ADD COLUMN discovery TEXT NOT NULL DEFAULT 'qmi';
ALTER TABLE local_modems ADD COLUMN manageable INTEGER NOT NULL DEFAULT 1;
ALTER TABLE local_modems ADD COLUMN control_port TEXT;

-- A physical endpoint may be present even when it cannot provide an IMEI.
-- It therefore cannot live in local_modems, whose primary key is the IMEI.
-- Candidate keys are transport-qualified so a failed QMI endpoint and its AT
-- fallback can both be diagnosed without one result overwriting the other.
CREATE TABLE IF NOT EXISTS local_modem_discoveries (
    candidate_key TEXT PRIMARY KEY,
    usb_device    TEXT,
    transport     TEXT NOT NULL,
    control_port  TEXT NOT NULL,
    vendor_id     TEXT,
    product_id    TEXT,
    state         TEXT NOT NULL,
    imei          TEXT,
    detail        TEXT NOT NULL,
    last_seen     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS local_modem_discoveries_seen
    ON local_modem_discoveries (last_seen DESC);
