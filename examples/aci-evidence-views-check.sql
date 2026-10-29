-- Run after migration 014 against an isolated test database. This exercise
-- creates temporary fixture rows using an existing device snapshot, then rolls
-- everything back. It never labels the evidence as confirmed forwarding.
BEGIN;
DO $$
DECLARE test_snapshot uuid; test_raw uuid := 'edeb2000-0000-4000-8000-000000000001';
BEGIN
  SELECT id INTO test_snapshot FROM navis.device_snapshot LIMIT 1;
  IF test_snapshot IS NULL THEN RAISE EXCEPTION 'An existing device snapshot is required'; END IF;
  INSERT INTO navis.raw_payload(id,snapshot_id,data_type,format,format_version,payload)
  VALUES (test_raw,test_snapshot,'topology','normalized-json','1',
    '{"kind":"aci_fabric_evidence","version":1,"inventory":{"fabric_id":"test-fabric","objects":[{"dn":"uni/tn-a","class":"fvTenant","kind":"tenant","attributes":{"name":"a"}}],"relationships":[{"kind":"fvRsBd","source":"uni/tn-a/a","target":"uni/tn-a/b","resolved":false}]},"semantics":{"findings":[{"reason":"unresolved"}]}}'::jsonb);
  IF (SELECT count(*) FROM navis.aci_evidence_object WHERE raw_payload_id=test_raw AND native_class='fvTenant') <> 1 THEN
    RAISE EXCEPTION 'ACI object view check failed';
  END IF;
  IF (SELECT count(*) FROM navis.aci_evidence_relationship WHERE raw_payload_id=test_raw AND resolved='false'::jsonb) <> 1 THEN
    RAISE EXCEPTION 'ACI relationship view check failed';
  END IF;
  IF (SELECT count(*) FROM navis.aci_evidence_finding WHERE raw_payload_id=test_raw) <> 1 THEN
    RAISE EXCEPTION 'ACI finding view check failed';
  END IF;
END $$;
ROLLBACK;
