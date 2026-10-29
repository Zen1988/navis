BEGIN;
SET LOCAL search_path = navis, public;
ALTER TABLE api_consumer ADD COLUMN identity_source_system_id uuid REFERENCES source_system(id);
COMMIT;
