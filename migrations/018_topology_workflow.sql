BEGIN;
SET LOCAL search_path = navis, public;
CREATE TABLE topology_build (
 build_id uuid PRIMARY KEY REFERENCES graph_build(id),
 source_system_id uuid NOT NULL REFERENCES source_system(id),
 consumer_id uuid REFERENCES api_consumer(id),
 name text,
 ips jsonb NOT NULL DEFAULT '[]',
 projection jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX topology_build_source ON topology_build(source_system_id, created_at DESC);
COMMIT;
