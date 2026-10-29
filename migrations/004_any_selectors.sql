BEGIN;
SET LOCAL search_path = navis, public;
ALTER TABLE policy_selector ADD COLUMN matches_any boolean NOT NULL DEFAULT false;
ALTER TABLE policy_selector DROP CONSTRAINT policy_selector_check;
ALTER TABLE policy_selector ADD CONSTRAINT policy_selector_one_value CHECK (num_nonnulls(address_object_id,service_object_id,security_zone_id,interface_id) + matches_any::integer = 1);
ALTER TABLE nat_selector ADD COLUMN matches_any boolean NOT NULL DEFAULT false;
ALTER TABLE nat_selector DROP CONSTRAINT nat_selector_check;
ALTER TABLE nat_selector ADD CONSTRAINT nat_selector_one_value CHECK (num_nonnulls(address_object_id,service_object_id,security_zone_id,interface_id) + matches_any::integer = 1);
COMMIT;
