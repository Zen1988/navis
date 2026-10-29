-- Add only the expired fixture when the original session fixture was already loaded.
INSERT INTO navis.nat_session_evidence(id,snapshot_id,nat_rule_id,original_packet,translated_packet,observed_at,expires_at,source_system_id)
VALUES ('50000000-0000-4000-8000-000000000002','10000000-0000-4000-8000-000000000022','20000000-0000-4000-8000-000000000002',
 '{"source":"192.0.2.1","destination":"198.51.100.10","protocol":"tcp","destination_port":443,"source_port":50002}'::jsonb,
 '{"source":"192.0.2.1","destination":"10.10.1.10","protocol":"tcp","destination_port":443,"source_port":50002}'::jsonb,
 now()-interval '2 hours',now()-interval '1 hour','10000000-0000-4000-8000-000000000001');
