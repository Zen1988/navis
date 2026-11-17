"""Build an immutable Apache AGE projection of a selected dataset."""
from uuid import UUID, uuid4
from .build_evidence import evidence_manifest


def _uuid(value):
    return str(UUID(str(value)))


def _cypher(cur, graph, query):
    # Graph name and all interpolated values are generated or validated UUIDs;
    # never insert names, configuration, or other external text into Cypher.
    cur.execute(f"SELECT * FROM ag_catalog.cypher('{graph}', $$ {query} $$) AS (v ag_catalog.agtype)")


def build_graph(connection_factory, dataset_id, *, after_build=None):
    dataset_id = UUID(str(dataset_id))
    build_id = uuid4()
    graph = "navis_" + build_id.hex
    with connection_factory() as conn:
        with conn.cursor() as cur:
            cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            cur.execute("LOAD 'age'")
            cur.execute("SET LOCAL search_path = ag_catalog, navis, public")
            cur.execute("SELECT id FROM navis.graph_dataset WHERE id=%s FOR UPDATE", (dataset_id,))
            if cur.fetchone() is None:
                raise LookupError("dataset not found")
            cur.execute("SELECT device_id, data_type, snapshot_id FROM navis.graph_dataset_snapshot WHERE dataset_id=%s", (dataset_id,))
            snapshots = cur.fetchall()
            if not snapshots:
                raise ValueError("dataset has no snapshots")
            cur.execute("INSERT INTO navis.graph_build(id,dataset_id,graph_name,started_at,status,builder_version) VALUES (%s,%s,%s,now(),'building','1')", (build_id, dataset_id, graph))
            for _, _, snapshot in snapshots:
                cur.execute("INSERT INTO navis.graph_build_snapshot(graph_build_id,snapshot_id) VALUES (%s,%s) ON CONFLICT DO NOTHING", (build_id, snapshot))
            cur.execute("SELECT ag_catalog.create_graph(%s)", (graph,))
            device_ids = {_uuid(device) for device, _, _ in snapshots}
            for device in sorted(device_ids):
                _cypher(cur, graph, f"CREATE (:Device {{id: '{device}'}})")
            # Vertices are snapshot-specific and preserve relational provenance.
            cur.execute("SELECT i.id, s.device_id, i.snapshot_id, i.native_id FROM navis.interface i JOIN navis.device_snapshot s ON s.id=i.snapshot_id JOIN navis.graph_dataset_snapshot d ON d.snapshot_id=i.snapshot_id AND d.device_id=s.device_id WHERE d.dataset_id=%s ORDER BY s.device_id, i.native_id, (d.data_type='interface') DESC, i.id", (dataset_id,))
            interface_rows = cur.fetchall()
            interface_ids = {}
            canonical = {}
            for iface, device, snap, native_id in interface_rows:
                iface, device, snap = _uuid(iface), _uuid(device), _uuid(snap)
                if iface in interface_ids:
                    continue
                key = (device, native_id)
                if key not in canonical:
                    canonical[key] = iface
                    _cypher(cur, graph, f"CREATE (:Interface {{id: '{iface}', snapshot_id: '{snap}'}})")
                    _cypher(cur, graph, f"MATCH (d:Device {{id: '{device}'}}), (i:Interface {{id: '{iface}'}}) CREATE (d)-[:HAS_INTERFACE]->(i)")
                interface_ids[iface] = canonical[key]
            cur.execute("SELECT r.id, r.snapshot_id, s.device_id FROM navis.route r JOIN navis.device_snapshot s ON s.id=r.snapshot_id JOIN navis.graph_dataset_snapshot d ON d.snapshot_id=r.snapshot_id AND d.device_id=s.device_id WHERE d.dataset_id=%s AND d.data_type='route'", (dataset_id,))
            for route, snap, device in cur.fetchall():
                route, snap, device = _uuid(route), _uuid(snap), _uuid(device)
                _cypher(cur, graph, f"CREATE (:Route {{id: '{route}', snapshot_id: '{snap}'}})")
                _cypher(cur, graph, f"MATCH (d:Device {{id: '{device}'}}), (r:Route {{id: '{route}'}}) CREATE (d)-[:HAS_ROUTE]->(r)")
            cur.execute("SELECT n.route_id, n.interface_id, n.id FROM navis.route_next_hop n JOIN navis.graph_dataset_snapshot d ON d.snapshot_id=n.snapshot_id WHERE d.dataset_id=%s AND d.data_type='route' AND n.interface_id IS NOT NULL", (dataset_id,))
            for route, iface, hop in cur.fetchall():
                route, iface, hop = _uuid(route), _uuid(iface), _uuid(hop)
                if iface in interface_ids:
                    iface = interface_ids[iface]
                    _cypher(cur, graph, f"MATCH (r:Route {{id: '{route}'}}), (i:Interface {{id: '{iface}'}}) CREATE (r)-[:OUTGOING_INTERFACE {{source_id: '{hop}'}}]->(i)")
            cur.execute("SELECT l.id, l.origin, sa.device_id, ia.native_id, sb.device_id, ib.native_id FROM navis.topology_link l JOIN navis.topology_link_endpoint a ON a.link_id=l.id AND a.endpoint_number=1 JOIN navis.topology_link_endpoint b ON b.link_id=l.id AND b.endpoint_number=2 JOIN navis.interface ia ON ia.id=a.interface_id JOIN navis.device_snapshot sa ON sa.id=ia.snapshot_id JOIN navis.interface ib ON ib.id=b.interface_id JOIN navis.device_snapshot sb ON sb.id=ib.snapshot_id LEFT JOIN navis.graph_config c ON c.dataset_id=%s WHERE a.interface_id IS NOT NULL AND b.interface_id IS NOT NULL AND (l.valid_until IS NULL OR l.valid_until > now()) AND (l.valid_from IS NULL OR l.valid_from <= now()) AND ((l.origin='manual' AND COALESCE(c.include_manual_links,true)) OR (l.origin<>'manual' AND COALESCE(c.include_discovered_links,true)))", (dataset_id,))
            for link, origin, left_device, left_native, right_device, right_native in cur.fetchall():
                link = _uuid(link)
                left = canonical.get((_uuid(left_device), left_native))
                right = canonical.get((_uuid(right_device), right_native))
                if left and right:
                    relationship = "MANUAL_LINK" if origin == "manual" else "DISCOVERED_LINK"
                    _cypher(cur, graph, f"MATCH (a:Interface {{id: '{left}'}}), (b:Interface {{id: '{right}'}}) CREATE (a)-[:{relationship} {{source_id: '{link}'}}]->(b)")
            # A next-hop IP is route-specific evidence, not a physical link.
            # Only match selected interface snapshots in the same source; do not
            # choose among reused addresses or bridge routing-context boundaries.
            cur.execute("""SELECT r.id,n.id,peer.id,ps.device_id,local.native_id,remote.native_id,
                    b.source_system_id,pb.source_system_id
                FROM navis.graph_dataset_snapshot ds
                JOIN navis.device_snapshot s ON s.id=ds.snapshot_id
                JOIN navis.import_batch b ON b.id=s.import_batch_id
                JOIN navis.route r ON r.snapshot_id=s.id
                JOIN navis.routing_context local ON local.id=r.routing_context_id
                JOIN navis.route_next_hop n ON n.route_id=r.id
                JOIN navis.interface_address a ON host(a.address)=host(n.next_hop_address)
                JOIN navis.interface peer ON peer.id=a.interface_id
                JOIN navis.routing_context remote ON remote.id=peer.routing_context_id
                JOIN navis.device_snapshot ps ON ps.id=peer.snapshot_id
                JOIN navis.import_batch pb ON pb.id=ps.import_batch_id
                JOIN navis.graph_dataset_snapshot pds ON pds.snapshot_id=ps.id
                    AND pds.dataset_id=ds.dataset_id AND pds.data_type='interface'
                WHERE ds.dataset_id=%s AND ds.data_type='route' AND ps.device_id<>s.device_id
                AND n.next_hop_context_id IS NULL""", (dataset_id,))
            candidates = {}
            for route, hop, peer, device, local, remote, source, peer_source in cur.fetchall():
                if local == remote and source == peer_source:
                    candidates.setdefault((route, hop), set()).add((_uuid(peer), _uuid(device)))
            for (route, hop), peers in candidates.items():
                if len(peers) != 1:
                    continue
                peer, _ = next(iter(peers))
                if peer in interface_ids:
                    canonical_peer = interface_ids[peer]
                    _cypher(cur, graph, f"MATCH (r:Route {{id: '{_uuid(route)}'}}), (i:Interface {{id: '{canonical_peer}'}}) CREATE (r)-[:NEXT_HOP_CANDIDATE {{source_id: '{_uuid(hop)}'}}]->(i)")
            from psycopg.types.json import Jsonb
            manifest = evidence_manifest(cur, dataset_id)
            cur.execute("UPDATE navis.graph_build SET status='completed',completed_at=now(),evidence_manifest=%s WHERE id=%s", (Jsonb(manifest), build_id))
            publication = after_build(cur, build_id) if after_build is not None else None
    return {"build_id": str(build_id), "graph_name": graph, "publication": publication}
