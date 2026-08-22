-- The home network, taken from EF_IMSI.
--
-- 0004 stored the serving network, which on a roaming card belongs to somebody
-- else: both cards on the bench are Hong Kong subscriptions registered on China
-- Unicom, so the serving network answered "who is carrying this" rather than
-- "whose card is this". The panel needs the second question answered.
ALTER TABLE local_modems ADD COLUMN home_mcc INTEGER;
ALTER TABLE local_modems ADD COLUMN home_mnc INTEGER;
ALTER TABLE local_modems ADD COLUMN imsi TEXT;
