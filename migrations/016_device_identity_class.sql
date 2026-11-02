-- External identity is a source instance, object class and opaque ID tuple.
BEGIN;
SET LOCAL search_path = navis, public;
CREATE EXTENSION IF NOT EXISTS btree_gist;
ALTER TABLE device_identity_mapping ADD COLUMN object_class text NOT NULL DEFAULT 'device'
 CHECK (length(object_class) BETWEEN 1 AND 255 AND object_class = btrim(object_class) AND object_class <> '');
ALTER TABLE ingestion_submission ADD COLUMN object_class text NOT NULL DEFAULT 'device'
 CHECK (length(object_class) BETWEEN 1 AND 255 AND object_class = btrim(object_class) AND object_class <> '');
ALTER TABLE api_consumer ADD COLUMN identity_object_class text NOT NULL DEFAULT 'device'
 CHECK (length(identity_object_class) BETWEEN 1 AND 255 AND identity_object_class = btrim(identity_object_class) AND identity_object_class <> '');
DROP INDEX device_identity_active;
ALTER TABLE device_identity_mapping ADD CONSTRAINT device_identity_no_overlap
 EXCLUDE USING gist (source_system_id WITH =, object_class WITH =, external_id WITH =,
 tstzrange(valid_from, valid_until, '[)') WITH &&);
COMMIT;
