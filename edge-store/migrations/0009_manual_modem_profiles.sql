-- A manual profile is an operator's approval of an already discovered
-- physical candidate. It deliberately does not contain an IMEI: a candidate
-- may be claimable before any transport can read one, and the current USB
-- observations remain the authority for whether the hardware is present.
CREATE TABLE IF NOT EXISTS manual_modem_profiles (
    candidate_key TEXT PRIMARY KEY,
    usb_device    TEXT,
    vendor_id     TEXT,
    product_id    TEXT,
    control_port  TEXT NOT NULL,
    approved_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS manual_modem_profiles_approved
    ON manual_modem_profiles (approved_at DESC, candidate_key);
