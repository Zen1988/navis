-- Explicit assumptions for the isolated three-device test fixture only.
BEGIN;
INSERT INTO navis.snapshot_coverage(id,snapshot_id,data_type,coverage,details) VALUES
 ('40000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000021','route','complete','{"table_kind":"installed"}'::jsonb),
 ('40000000-0000-4000-8000-000000000002','10000000-0000-4000-8000-000000000022','route','complete','{"table_kind":"installed"}'::jsonb),
 ('40000000-0000-4000-8000-000000000003','10000000-0000-4000-8000-000000000021','nat','complete',NULL),
 ('40000000-0000-4000-8000-000000000004','10000000-0000-4000-8000-000000000023','nat','complete',NULL);
UPDATE navis.policy_rule_set SET statefulness='stateful', session_semantics='{"supported_protocols":["tcp"]}'::jsonb
 WHERE id='10000000-0000-4000-8000-000000000094';
COMMIT;
