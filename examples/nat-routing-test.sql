-- Apply once to the existing three-device AGE test database.
BEGIN;
INSERT INTO navis.nat_rule_set(id,enforcement_point_id,native_id,processing_stage,evaluation_order)
VALUES ('20000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000093','test-dnat','before_route_after_policy','first_match');
INSERT INTO navis.nat_rule(id,nat_rule_set_id,native_rule_id,position,enabled,details)
VALUES ('20000000-0000-4000-8000-000000000002','20000000-0000-4000-8000-000000000001','dnat-web',1,true,'{"selectors_complete":true}'::jsonb);
INSERT INTO navis.nat_translation(id,nat_rule_id,kind,specification)
VALUES ('20000000-0000-4000-8000-000000000003','20000000-0000-4000-8000-000000000002','destination','{"address":"10.10.1.10"}'::jsonb);
INSERT INTO navis.address_object(id,snapshot_id,kind,prefix) VALUES
 ('20000000-0000-4000-8000-000000000004','10000000-0000-4000-8000-000000000022','prefix','198.51.100.10/32');
INSERT INTO navis.service_object(id,snapshot_id,protocol,destination_port_start,destination_port_end)
VALUES ('20000000-0000-4000-8000-000000000005','10000000-0000-4000-8000-000000000022','tcp',443,443);
INSERT INTO navis.nat_selector(id,nat_rule_id,role,address_object_id,service_object_id,matches_any) VALUES
 ('20000000-0000-4000-8000-000000000006','20000000-0000-4000-8000-000000000002','source',NULL,NULL,true),
 ('20000000-0000-4000-8000-000000000007','20000000-0000-4000-8000-000000000002','destination','20000000-0000-4000-8000-000000000004',NULL,false),
 ('20000000-0000-4000-8000-000000000008','20000000-0000-4000-8000-000000000002','service',NULL,'20000000-0000-4000-8000-000000000005',false);
INSERT INTO navis.snapshot_coverage(id,snapshot_id,data_type,coverage)
VALUES ('20000000-0000-4000-8000-000000000009','10000000-0000-4000-8000-000000000022','nat','complete');
INSERT INTO navis.route(id,snapshot_id,routing_context_id,destination,route_type)
VALUES ('20000000-0000-4000-8000-000000000010','10000000-0000-4000-8000-000000000022','10000000-0000-4000-8000-000000000032','10.10.1.0/24','forward');
INSERT INTO navis.route_next_hop(id,snapshot_id,route_id,interface_id)
VALUES ('20000000-0000-4000-8000-000000000011','10000000-0000-4000-8000-000000000022','20000000-0000-4000-8000-000000000010','10000000-0000-4000-8000-000000000043');
COMMIT;
