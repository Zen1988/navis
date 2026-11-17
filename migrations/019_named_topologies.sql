BEGIN;
SET LOCAL search_path = navis, public;
CREATE TABLE topology_definition (
 id uuid PRIMARY KEY,
 source_system_id uuid NOT NULL REFERENCES source_system(id),
 consumer_id uuid REFERENCES api_consumer(id),
 name text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 255),
 members jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(members)='array'),
 latest_build_id uuid NOT NULL REFERENCES graph_build(id),
 updated_at timestamptz NOT NULL DEFAULT now(),
 CHECK ((consumer_id IS NULL AND name='default' AND members='[]'::jsonb)
     OR (consumer_id IS NOT NULL AND name<>'default'))
);
CREATE UNIQUE INDEX topology_default_name ON topology_definition(source_system_id) WHERE consumer_id IS NULL;
CREATE UNIQUE INDEX topology_application_name ON topology_definition(source_system_id,consumer_id,name) WHERE consumer_id IS NOT NULL;
ALTER TABLE topology_build ADD COLUMN members jsonb NOT NULL DEFAULT '[]';
UPDATE topology_build SET members=ips;
-- Catalog the latest completed versions without rewriting historical builds.
INSERT INTO topology_definition(id,source_system_id,consumer_id,name,members,latest_build_id,updated_at)
 SELECT build_id,source_system_id,NULL,'default','[]'::jsonb,build_id,created_at FROM (
   SELECT DISTINCT ON (t.source_system_id) t.* FROM topology_build t
   JOIN graph_build b ON b.id=t.build_id WHERE t.consumer_id IS NULL AND b.status='completed'
   ORDER BY t.source_system_id,t.created_at DESC,t.build_id DESC
 ) latest;
INSERT INTO topology_definition(id,source_system_id,consumer_id,name,members,latest_build_id,updated_at)
 SELECT build_id,source_system_id,consumer_id,name,members,build_id,created_at FROM (
   SELECT DISTINCT ON (t.source_system_id,t.consumer_id,t.name) t.* FROM topology_build t
   JOIN graph_build b ON b.id=t.build_id
   WHERE t.consumer_id IS NOT NULL AND t.name IS NOT NULL AND t.name<>'default' AND b.status='completed'
   ORDER BY t.source_system_id,t.consumer_id,t.name,t.created_at DESC,t.build_id DESC
 ) latest;
CREATE TABLE topology_version (
 id uuid PRIMARY KEY,
 topology_id uuid NOT NULL REFERENCES topology_definition(id),
 build_id uuid NOT NULL REFERENCES graph_build(id),
 members jsonb NOT NULL,
 content_hash text,
 content jsonb NOT NULL DEFAULT '{}',
 built_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 check_count integer NOT NULL DEFAULT 1,
 latest_evidence jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX topology_version_history ON topology_version(topology_id,built_at DESC,id);
ALTER TABLE topology_definition ADD COLUMN latest_version_id uuid REFERENCES topology_version(id);
INSERT INTO topology_version(id,topology_id,build_id,members,built_at,updated_at)
 SELECT t.build_id,d.id,t.build_id,t.members,COALESCE(b.completed_at,t.created_at),COALESCE(b.completed_at,t.created_at)
 FROM topology_build t JOIN graph_build b ON b.id=t.build_id
 JOIN topology_definition d ON d.source_system_id=t.source_system_id
 AND ((d.consumer_id IS NULL AND t.consumer_id IS NULL)
   OR (d.consumer_id=t.consumer_id AND d.name=t.name))
 WHERE b.status='completed';
UPDATE topology_definition d SET latest_version_id=v.id FROM topology_version v
 WHERE v.topology_id=d.id AND v.build_id=d.latest_build_id;
COMMIT;
