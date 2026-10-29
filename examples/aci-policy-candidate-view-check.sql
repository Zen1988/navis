BEGIN;
DO $$
DECLARE test_snapshot uuid; test_raw uuid := 'edeb2000-0000-4000-8000-000000000002';
BEGIN
  SELECT id INTO test_snapshot FROM navis.device_snapshot LIMIT 1;
  IF test_snapshot IS NULL THEN RAISE EXCEPTION 'An existing device snapshot is required'; END IF;
  INSERT INTO navis.raw_payload(id,snapshot_id,data_type,format,format_version,payload)
  VALUES (test_raw,test_snapshot,'topology','normalized-json','1',
    '{"kind":"aci_fabric_evidence","version":1,"inventory":{"fabric_id":"test"},"semantics":{"policy_candidates":[{"contract":"uni/tn-a/brc-web","consumer_epg":"epg-client","provider_epg":"epg-server","candidate_action":"allow","status":"unverified"}]}}'::jsonb);
  IF (SELECT count(*) FROM navis.aci_policy_candidate WHERE raw_payload_id=test_raw
       AND consumer_epg_dn='epg-client' AND provider_epg_dn='epg-server'
       AND candidate_action='allow' AND status='unverified') <> 1 THEN
    RAISE EXCEPTION 'ACI candidate view check failed';
  END IF;
END $$;
ROLLBACK;
