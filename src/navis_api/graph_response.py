"""Caller-scoped graph response with external device identities."""
from uuid import UUID


def get_graph(connection_factory, build_id, principal):
    """Read only completed builds whose complete dataset is in caller scope."""
    if not principal.issuer:
        raise PermissionError("issuer required")
    build_id = UUID(str(build_id))
    with connection_factory() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT c.id,c.identity_source_system_id FROM navis.api_consumer c WHERE c.issuer=%s AND c.subject_or_client_id=%s AND c.status='active'", (principal.issuer, principal.subject))
            consumer = cur.fetchone()
            if consumer is None:
                raise PermissionError("consumer not authorized")
            consumer_id, identity_source = consumer
            cur.execute("SELECT b.dataset_id,b.status FROM navis.graph_build b WHERE b.id=%s", (build_id,))
            build = cur.fetchone()
            if build is None:
                raise LookupError("graph build not found")
            dataset, status = build
            if status != "completed":
                raise ValueError("graph build is not completed")
            # Refuse the whole graph if any selected snapshot's source is outside scope.
            cur.execute("""SELECT 1 FROM navis.graph_build_snapshot bs
                JOIN navis.device_snapshot s ON s.id=bs.snapshot_id
                JOIN navis.import_batch b ON b.id=s.import_batch_id
                WHERE bs.graph_build_id=%s AND NOT EXISTS (
                  SELECT 1 FROM navis.consumer_data_scope ds
                  WHERE ds.api_consumer_id=%s AND ds.source_system_id=b.source_system_id
                  AND ds.permissions @> '["graph:read"]'::jsonb) LIMIT 1""", (build_id, consumer_id))
            if cur.fetchone():
                raise PermissionError("graph outside caller scope")
            cur.execute("""SELECT DISTINCT s.device_id FROM navis.graph_build_snapshot bs
                JOIN navis.device_snapshot s ON s.id=bs.snapshot_id WHERE bs.graph_build_id=%s""", (build_id,))
            devices = [r[0] for r in cur.fetchall()]
            nodes = []
            for device in devices:
                # Require a mapping valid for every selected snapshot of this device.
                cur.execute("""SELECT m.external_id, src.namespace FROM navis.device_identity_mapping m
                    JOIN navis.source_system src ON src.id=m.source_system_id
                    WHERE m.device_id=%s AND m.source_system_id=%s AND NOT EXISTS (
                      SELECT 1 FROM navis.graph_build_snapshot bs JOIN navis.device_snapshot s ON s.id=bs.snapshot_id
                      WHERE bs.graph_build_id=%s AND s.device_id=%s
                      AND NOT (m.valid_from <= s.collected_at AND (m.valid_until IS NULL OR m.valid_until > s.collected_at)))""", (device, identity_source, build_id, device))
                mappings = cur.fetchall()
                identity = {"status": "missing"}
                if len(mappings) == 1:
                    identity = {"status": "mapped", "namespace": mappings[0][1], "id": mappings[0][0]}
                elif len(mappings) > 1:
                    identity = {"status": "ambiguous"}
                nodes.append({"id": str(device), "type": "device", "external_identity": identity})
            return {"build_id": str(build_id), "dataset_id": str(dataset), "status": status, "nodes": nodes, "connections": [], "projection_status": "device_identity_only"}
