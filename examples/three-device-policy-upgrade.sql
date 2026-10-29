-- Apply once after the original three-device graph fixture.
BEGIN;
UPDATE navis.interface SET routing_context_id='10000000-0000-4000-8000-000000000031' WHERE id='10000000-0000-4000-8000-000000000041';
INSERT INTO navis.interface_address(id,interface_id,address) VALUES
 ('10000000-0000-4000-8000-000000000091','10000000-0000-4000-8000-000000000041','192.0.2.1/24'),
 ('10000000-0000-4000-8000-000000000092','10000000-0000-4000-8000-000000000044','198.51.100.10/24');
INSERT INTO navis.enforcement_point(id,snapshot_id,native_id,kind) VALUES ('10000000-0000-4000-8000-000000000093','10000000-0000-4000-8000-000000000022','firewall','firewall');
INSERT INTO navis.policy_rule_set(id,enforcement_point_id,native_id,evaluation_order,default_action) VALUES ('10000000-0000-4000-8000-000000000094','10000000-0000-4000-8000-000000000093','security','first_match','deny');
INSERT INTO navis.policy_rule(id,rule_set_id,native_rule_id,position,action,enabled,details) VALUES ('10000000-0000-4000-8000-000000000095','10000000-0000-4000-8000-000000000094','allow-web',1,'allow',true,'{"selectors_complete":false}'::jsonb);
INSERT INTO navis.address_object(id,snapshot_id,kind,prefix) VALUES
 ('10000000-0000-4000-8000-000000000096','10000000-0000-4000-8000-000000000022','prefix','192.0.2.1/32'),
 ('10000000-0000-4000-8000-000000000097','10000000-0000-4000-8000-000000000022','prefix','198.51.100.10/32');
INSERT INTO navis.service_object(id,snapshot_id,protocol,destination_port_start,destination_port_end) VALUES ('10000000-0000-4000-8000-000000000098','10000000-0000-4000-8000-000000000022','tcp',443,443);
INSERT INTO navis.policy_selector(id,policy_rule_id,role,address_object_id,service_object_id) VALUES
 ('10000000-0000-4000-8000-0000000000a1','10000000-0000-4000-8000-000000000095','source','10000000-0000-4000-8000-000000000096',NULL),
 ('10000000-0000-4000-8000-0000000000a2','10000000-0000-4000-8000-000000000095','destination','10000000-0000-4000-8000-000000000097',NULL),
 ('10000000-0000-4000-8000-0000000000a3','10000000-0000-4000-8000-000000000095','service',NULL,'10000000-0000-4000-8000-000000000098');
INSERT INTO navis.graph_dataset_snapshot(dataset_id,device_id,data_type,snapshot_id) VALUES ('10000000-0000-4000-8000-000000000080','10000000-0000-4000-8000-000000000012','policy','10000000-0000-4000-8000-000000000022');
COMMIT;
