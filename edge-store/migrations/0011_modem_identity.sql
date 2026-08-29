-- Identity that belongs to the hardware and the card rather than to one poll.
--
-- Both kept beside the modem row rather than re-read every pass: the firmware
-- revision changes only when the module is flashed, and the card's own number
-- only when a different card -- or, on an eUICC, a different profile -- is in
-- the slot. Carrying them lets the panel and the cloud show them without an
-- operator having to ask for a diagnostic report first.
--
-- `msisdn_iccid` records which card the number was read from. Without it a
-- number would outlive its card and be shown against the next one, which is
-- worse than showing nothing: it is a plausible wrong answer.
ALTER TABLE local_modems ADD COLUMN firmware TEXT;
ALTER TABLE local_modems ADD COLUMN msisdn TEXT;
ALTER TABLE local_modems ADD COLUMN msisdn_iccid TEXT;
