-- Store submissions before device identity has been resolved.
BEGIN;
SET LOCAL search_path = navis, public;
CREATE TABLE ingestion_submission (
 id uuid PRIMARY KEY,
 source_system_id uuid NOT NULL REFERENCES source_system(id),
 external_device_id text NOT NULL,
 claimed_device_id uuid REFERENCES device(id),
 adapter_name text NOT NULL,
 input_format text NOT NULL,
 format_version text NOT NULL,
 data_type text NOT NULL,
 collected_at timestamptz NOT NULL,
 received_at timestamptz NOT NULL DEFAULT now(),
 completeness text NOT NULL CHECK (completeness IN ('complete','partial','unknown')),
 payload jsonb NOT NULL,
 submitted_by text NOT NULL,
 status text NOT NULL CHECK (status IN ('pending_identity','pending_processing'))
);
CREATE INDEX ingestion_submission_source_idx ON ingestion_submission(source_system_id, external_device_id);
COMMIT;
