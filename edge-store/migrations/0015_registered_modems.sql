-- Which modules this agent has been told to manage.
--
-- Separate from `local_modems` on purpose. That table answers "what did I
-- see", and it was also being used to answer "what do I manage" -- one table
-- holding two different facts, which is why the panel filled with rows nobody
-- could act on: a stick seen once and unplugged stayed in the list for ever,
-- indistinguishable from one an operator had deliberately adopted.
--
-- Here the two are apart:
--
--   local_modems       what the last probe found. Transient.
--   registered_modems  what somebody chose to manage. Persistent.
--
-- A registered module that is not currently found is **offline** -- still
-- listed, still polled for, and worth an alert. An unregistered module that is
-- found is a **candidate** -- shown, never written to, and gone when unplugged.
--
-- Keyed on IMEI because that is the only identifier that survives what
-- actually happens to this hardware: USB paths change on every re-enumeration,
-- `/dev` names change when a hub is repopulated, and the ICCID belongs to the
-- card rather than the module. A stick moved to another port is the same
-- device; a different stick in the same port is not.
CREATE TABLE IF NOT EXISTS registered_modems (
    imei TEXT PRIMARY KEY,
    registered_at INTEGER NOT NULL,
    -- Who adopted it: 'panel', 'cloud', or 'migration' for the one-time
    -- adoption below. Kept because "why is this being managed" is the first
    -- question asked about a module nobody remembers adding.
    registered_by TEXT NOT NULL,
    -- Evidence captured at registration, never used for lookup. USB topology
    -- and family are what the module looked like when it was adopted; both
    -- can change without the registration meaning anything different.
    usb_device TEXT,
    family TEXT,
    note TEXT
);

-- One-time adoption of whatever this agent is already managing.
--
-- Without it, the first start after this migration manages nothing: every
-- module drops to "candidate", the bench stops, and an operator has to
-- re-adopt hardware that was already working. `INSERT OR IGNORE` so a re-run
-- is a no-op, and `registered_by = 'migration'` so these are distinguishable
-- from anything a person chose.
INSERT OR IGNORE INTO registered_modems (imei, registered_at, registered_by, usb_device, family)
SELECT imei,
       CAST(strftime('%s', 'now') AS INTEGER) * 1000,
       'migration',
       control_port,
       family
  FROM local_modems;
