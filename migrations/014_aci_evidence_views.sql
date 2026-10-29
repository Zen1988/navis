BEGIN;
SET LOCAL search_path = navis, public;

-- These views expose unverified collector evidence only. They are deliberately
-- not joined into route, policy or AGE graph tables.
CREATE VIEW aci_fabric_evidence AS
SELECT r.id AS raw_payload_id, r.snapshot_id, s.device_id, s.import_batch_id,
       s.collected_at, r.payload->'inventory'->>'fabric_id' AS fabric_id,
       r.payload->'inventory' AS inventory, r.payload->'semantics' AS semantics
FROM raw_payload r
JOIN device_snapshot s ON s.id = r.snapshot_id
WHERE r.data_type = 'topology' AND r.format = 'normalized-json'
  AND r.format_version = '1' AND r.payload->>'kind' = 'aci_fabric_evidence'
  AND r.payload->>'version' = '1'
  AND jsonb_typeof(r.payload->'inventory') = 'object'
  AND jsonb_typeof(r.payload->'semantics') = 'object';

CREATE VIEW aci_evidence_object AS
SELECT e.raw_payload_id, e.snapshot_id, e.device_id, e.fabric_id,
       obj->>'dn' AS native_dn, obj->>'class' AS native_class,
       obj->>'kind' AS object_kind, obj->'attributes' AS attributes
FROM aci_fabric_evidence e
CROSS JOIN LATERAL jsonb_array_elements(
  CASE WHEN jsonb_typeof(e.inventory->'objects') = 'array'
       THEN e.inventory->'objects' ELSE '[]'::jsonb END) AS obj;

CREATE VIEW aci_evidence_relationship AS
SELECT e.raw_payload_id, e.snapshot_id, e.device_id, e.fabric_id,
       rel->>'kind' AS relationship_kind, rel->>'source' AS source_dn,
       rel->>'target' AS target_dn, rel->'resolved' AS resolved
FROM aci_fabric_evidence e
CROSS JOIN LATERAL jsonb_array_elements(
  CASE WHEN jsonb_typeof(e.inventory->'relationships') = 'array'
       THEN e.inventory->'relationships' ELSE '[]'::jsonb END) AS rel;

CREATE VIEW aci_evidence_finding AS
SELECT e.raw_payload_id, e.snapshot_id, e.device_id, e.fabric_id,
       finding AS details
FROM aci_fabric_evidence e
CROSS JOIN LATERAL jsonb_array_elements(
  CASE WHEN jsonb_typeof(e.semantics->'findings') = 'array'
       THEN e.semantics->'findings' ELSE '[]'::jsonb END) AS finding;

COMMIT;
