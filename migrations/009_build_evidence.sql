BEGIN;
SET LOCAL search_path = navis, public;
ALTER TABLE graph_build ADD COLUMN evidence_manifest jsonb;
COMMIT;
