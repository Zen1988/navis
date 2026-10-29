-- Test fixture update: attach the firewall ingress VRF and translated endpoint.
BEGIN;
UPDATE navis.interface SET routing_context_id='10000000-0000-4000-8000-000000000032'
 WHERE id='10000000-0000-4000-8000-000000000042';
INSERT INTO navis.interface_address(id,interface_id,address)
VALUES ('20000000-0000-4000-8000-000000000012','10000000-0000-4000-8000-000000000044','10.10.1.10/24');
COMMIT;
