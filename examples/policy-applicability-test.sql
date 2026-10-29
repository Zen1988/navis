-- Apply once to the isolated three-device fixture.
BEGIN;
INSERT INTO navis.snapshot_coverage(id,snapshot_id,data_type,coverage) VALUES
 ('30000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000021','policy','complete'),
 ('30000000-0000-4000-8000-000000000002','10000000-0000-4000-8000-000000000023','policy','complete');
INSERT INTO navis.policy_applicability(id,snapshot_id,direction,mechanism,state,evidence) VALUES
 ('30000000-0000-4000-8000-000000000011','10000000-0000-4000-8000-000000000021','device','normalized','not_applicable','{"fixture":true}'::jsonb),
 ('30000000-0000-4000-8000-000000000012','10000000-0000-4000-8000-000000000022','device','normalized','enforced','{"fixture":true}'::jsonb),
 ('30000000-0000-4000-8000-000000000013','10000000-0000-4000-8000-000000000023','device','normalized','not_applicable','{"fixture":true}'::jsonb);
COMMIT;
