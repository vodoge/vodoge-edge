-- Which network a modem is on, so the panel can answer "whose card is this"
-- without a diagnostic run per stick.
--
-- The serving system already reports MCC and MNC on every poll; keeping them
-- costs nothing more than the read that was already happening.
ALTER TABLE local_modems ADD COLUMN mcc INTEGER;
ALTER TABLE local_modems ADD COLUMN mnc INTEGER;
