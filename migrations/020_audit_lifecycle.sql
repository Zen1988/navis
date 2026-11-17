BEGIN;
SET LOCAL search_path = navis, public;
ALTER TABLE ingestion_submission ADD COLUMN updated_at timestamptz;
UPDATE ingestion_submission i SET updated_at=COALESCE((SELECT s.received_at FROM device_snapshot s WHERE s.id=i.snapshot_id),i.received_at);
ALTER TABLE ingestion_submission ALTER COLUMN updated_at SET DEFAULT now();
ALTER TABLE ingestion_submission ALTER COLUMN updated_at SET NOT NULL;
ALTER TABLE trace_session ADD COLUMN updated_at timestamptz;
UPDATE trace_session SET updated_at=created_at;
ALTER TABLE trace_session ALTER COLUMN updated_at SET DEFAULT now();
ALTER TABLE trace_session ALTER COLUMN updated_at SET NOT NULL;
-- One generic archive format supports rows from every operational table.
-- It has no FKs to live data, so archived history is self-contained storage.
CREATE TABLE audit_record (
 id uuid PRIMARY KEY,
 source_table text NOT NULL,
 record_key jsonb NOT NULL,
 source_system_id uuid,
 consumer_id uuid,
 row_data jsonb NOT NULL,
 context jsonb NOT NULL DEFAULT '{}',
 source_updated_at timestamptz NOT NULL,
 archived_at timestamptz NOT NULL DEFAULT now(),
 purge_at timestamptz NOT NULL DEFAULT now()+interval '1 year'
);
CREATE INDEX audit_record_expiry ON audit_record(purge_at);
CREATE INDEX audit_record_lookup ON audit_record(source_table,source_system_id,consumer_id);
CREATE INDEX audit_record_key ON audit_record USING gin(record_key);
CREATE TABLE retention_policy (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 archive_after_days integer NOT NULL DEFAULT 90 CHECK(archive_after_days>0),
 audit_retention_years integer NOT NULL DEFAULT 1 CHECK(audit_retention_years>0)
);
INSERT INTO retention_policy DEFAULT VALUES;
CREATE INDEX ingestion_retention_age ON ingestion_submission(updated_at);
CREATE INDEX topology_version_retention_age ON topology_version(updated_at);
CREATE INDEX trace_session_retention_age ON trace_session(updated_at);
COMMIT;
