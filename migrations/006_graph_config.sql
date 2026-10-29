BEGIN;
SET LOCAL search_path = navis, public;
ALTER TABLE graph_build ADD COLUMN graph_name text UNIQUE;
CREATE TABLE graph_config (
 dataset_id uuid PRIMARY KEY REFERENCES graph_dataset(id),
 include_manual_links boolean NOT NULL DEFAULT true,
 include_discovered_links boolean NOT NULL DEFAULT true,
 updated_at timestamptz NOT NULL DEFAULT now()
);
COMMIT;
