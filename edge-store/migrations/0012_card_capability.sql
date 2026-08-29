-- What an operator says a card's plan is sold as doing.
--
-- Three states per operation, which is why these are nullable rather than
-- boolean-with-a-default: NULL is "nobody has said", 0 is "this plan does not
-- include it", 1 is "it does". Only the middle one changes behaviour -- a
-- declaration is strictly subtractive and cannot grant a capability the
-- (modem, carrier) pair was never measured to have -- but the difference
-- between undeclared and declared-true still has to survive, because a form
-- somebody has filled in and a form nobody has touched are not the same
-- record.
--
-- This is the layer that separates two cards on one network in one module:
-- on this bench a Club profile receives and cannot send while a Webbing
-- profile does both, and nothing readable from the hardware or the network
-- tells them apart. It is a billing fact and it arrives by being typed in.
ALTER TABLE card_policies ADD COLUMN sms_send INTEGER;
ALTER TABLE card_policies ADD COLUMN sms_receive INTEGER;
ALTER TABLE card_policies ADD COLUMN data INTEGER;
ALTER TABLE card_policies ADD COLUMN voice INTEGER;
