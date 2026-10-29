"""Destination-first database trace foundation; does not infer reachability."""
from ipaddress import ip_address


class PostgresTraceProcessor:
    def __init__(self, connection_factory):
        self.connection_factory = connection_factory

    def trace(self, request, flows, principal):
        if not principal.issuer:
            raise PermissionError("issuer required")
        with self.connection_factory() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT c.id FROM navis.api_consumer c WHERE c.issuer=%s AND c.subject_or_client_id=%s AND c.status='active'", (principal.issuer, principal.subject))
                consumer = cur.fetchone()
                if consumer is None:
                    raise PermissionError("unknown consumer")
                cur.execute("SELECT dataset_id,status FROM navis.graph_build WHERE id=%s", (request.graph_build_id,))
                build = cur.fetchone()
                if build is None or build[1] != "completed":
                    raise ValueError("completed graph build required")
                dataset = build[0]
                cur.execute("""SELECT 1 FROM navis.graph_build_snapshot bs
                    JOIN navis.device_snapshot s ON s.id=bs.snapshot_id
                    JOIN navis.import_batch b ON b.id=s.import_batch_id
                    WHERE bs.graph_build_id=%s AND NOT EXISTS
                    (SELECT 1 FROM navis.consumer_data_scope ds WHERE ds.api_consumer_id=%s
                    AND ds.source_system_id=b.source_system_id AND ds.permissions @> '["analysis:run"]'::jsonb) LIMIT 1""", (request.graph_build_id, consumer[0]))
                if cur.fetchone():
                    raise PermissionError("dataset outside scope")
                results = []
                for flow in flows:
                    destination = self._endpoints(cur, dataset, request.graph_build_id, flow.destination)
                    source = self._endpoints(cur, dataset, request.graph_build_id, flow.source)
                    routes = []
                    if len(source) == 1 and source[0]["vrf"] is not None:
                        routes = self._routes(cur, dataset, request.graph_build_id, source[0], flow.destination)
                    reasons = ["Path traversal, NAT and policy evaluation are not implemented"]
                    if not destination:
                        reasons.append("Destination interface not found; NAT and incomplete inventory may affect resolution")
                    if len(destination) > 1:
                        reasons.append("Destination matches multiple interfaces")
                    if len(source) != 1:
                        reasons.append("Source resolution is missing or ambiguous")
                    elif source[0]["vrf"] is None:
                        reasons.append("Source routing context is unknown")
                    results.append({"source": flow.source, "destination": flow.destination,
                        "protocol": flow.protocol, "destination_port": flow.destination_port,
                        "status": "unknown", "destination_candidates": destination,
                        "source_candidates": source, "route_candidates": routes, "reasons": reasons})
                return {"graph_build_id": str(request.graph_build_id), "results": results}

    @staticmethod
    def _endpoints(cur, dataset, build_id, address):
        ip_address(address)
        cur.execute("""SELECT DISTINCT s.device_id, i.id, i.native_id, rc.native_id
            FROM navis.graph_dataset_snapshot ds
            JOIN navis.graph_build_snapshot bs ON bs.snapshot_id=ds.snapshot_id AND bs.graph_build_id=%s
            JOIN navis.device_snapshot s ON s.id=ds.snapshot_id AND s.device_id=ds.device_id
            JOIN navis.interface i ON i.snapshot_id=s.id
            JOIN navis.interface_address a ON a.interface_id=i.id
            LEFT JOIN navis.routing_context rc ON rc.id=i.routing_context_id
            WHERE ds.dataset_id=%s AND ds.data_type='interface' AND host(a.address)=host(%s::inet)
            ORDER BY s.device_id,i.id""", (build_id, dataset, address))
        return [{"device_id": str(device), "interface_id": str(interface), "interface": name, "vrf": vrf}
                for device, interface, name, vrf in cur.fetchall()]

    @staticmethod
    def _routes(cur, dataset, build_id, source, destination):
        cur.execute("""SELECT r.id, r.destination::text, r.route_type, r.protocol, r.preference, r.metric,
                n.next_hop_address::text, i.native_id
            FROM navis.graph_dataset_snapshot ds
            JOIN navis.graph_build_snapshot bs ON bs.snapshot_id=ds.snapshot_id AND bs.graph_build_id=%s
            JOIN navis.route r ON r.snapshot_id=ds.snapshot_id
            JOIN navis.routing_context rc ON rc.id=r.routing_context_id
            LEFT JOIN navis.route_next_hop n ON n.route_id=r.id
            LEFT JOIN navis.interface i ON i.id=n.interface_id
            WHERE ds.dataset_id=%s AND ds.device_id=%s AND ds.data_type='route'
              AND rc.native_id=%s AND r.destination >>= %s::inet
            ORDER BY masklen(r.destination) DESC, r.id, n.id""", (build_id, dataset, source["device_id"], source["vrf"], destination))
        return [{"route_id": str(r), "prefix": prefix, "route_type": kind, "protocol": protocol,
                 "preference": preference, "metric": metric, "next_hop": hop, "interface": interface}
                for r, prefix, kind, protocol, preference, metric, hop, interface in cur.fetchall()]
