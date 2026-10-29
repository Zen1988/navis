BEGIN;
SET LOCAL search_path = navis, public;
ALTER TABLE ingestion_submission DROP CONSTRAINT ingestion_submission_status_check;
ALTER TABLE ingestion_submission ADD CONSTRAINT ingestion_submission_status_check
 CHECK (status IN ('pending_identity','pending_processing','processed','raw_only'));
ALTER TABLE ingestion_submission ADD COLUMN snapshot_id uuid REFERENCES device_snapshot(id);
COMMIT;
