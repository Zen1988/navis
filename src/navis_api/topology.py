"""Namespace-scoped incremental topology orchestration and frozen evidence views."""
import logging
from collections import deque
from ipaddress import ip_address
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .graph_builder import build_graph
from .worker import process_submission

log = logging.getLogger(__name__)


class TopologyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    namespace: str | None = Field(default=None, min_length=1, max_length=255)
    name: str | None = Field(default=None, min_length=1, max_length=255)
    ips: list[str] = Field(default_factory=list, max_length=1000)

    @field_validator("ips")
    @classmethod
    def addresses(cls, values):
        return sorted({str(ip_address(value)) for value in values})


def application_view(projection, ips):
    """Select transit devices along candidate paths; retain unresolved endpoints."""
    if not ips:
        return projection
    owners = {ip: {node["id"] for node in projection["nodes"] if ip in node["addresses"]} for ip in ips}
    terminals = set().union(*owners.values())
    adjacency = {}
    for edge in projection["connections"]:
        adjacency.setdefault(edge["source"], set()).add(edge["target"])
        adjacency.setdefault(edge["target"], set()).add(edge["source"])
    selected = set(terminals)
    for start in sorted(terminals):
        parents, queue = {start: None}, deque([start])
        while queue:
            node = queue.popleft()
            for peer in sorted(adjacency.get(node, ())):
                if peer not in parents:
                    parents[peer] = node
                    queue.append(peer)
        for end in terminals & parents.keys():
            while end is not None:
                selected.add(end)
                end = parents[end]
    return {**projection,
            "nodes": [n for n in projection["nodes"] if n["id"] in selected],
            "connections": [e for e in projection["connections"] if e["source"] in selected and e["target"] in selected],
            "endpoint_candidates": {ip: sorted(nodes) for ip, nodes in owners.items()},
            "view_status": "candidate_paths_not_a_reachability_verdict"}


class TopologyService:
    def __init__(self, connection_factory):
        self.connection_factory = connection_factory

    @staticmethod
    def consumer(cur, principal):
        cur.execute("SELECT id FROM navis.api_consumer WHERE issuer=%s AND subject_or_client_id=%s AND status='active'", (principal.issuer, principal.subject))
        row = cur.fetchone()
        if row is None:
            raise PermissionError("active consumer required")
        return row[0]

    def source(self, cur, principal, namespace, permission):
        consumer = self.consumer(cur, principal)
        cur.execute("""SELECT DISTINCT s.id,s.namespace FROM navis.source_system s
            JOIN navis.consumer_data_scope ds ON ds.source_system_id=s.id
            WHERE ds.api_consumer_id=%s AND ds.permissions @> %s::jsonb
            AND (%s::text IS NULL OR s.namespace=%s) ORDER BY s.namespace""",
                    (consumer, '["' + permission + '"]', namespace, namespace))
        rows = cur.fetchall()
        if not rows:
            raise PermissionError("namespace outside caller scope")
        if len(rows) != 1:
            raise ValueError("namespace is required when multiple sources are authorized")
        return consumer, rows[0][0], rows[0][1]

    def refresh(self, principal, namespace=None, *, permission="analysis:run", name=None, ips=None):
        """Freeze latest processed evidence; serialize ingestion/builds per source."""
        from psycopg.types.json import Jsonb
        with self.connection_factory() as conn, conn.cursor() as cur:
            consumer, source, namespace = self.source(cur, principal, namespace, permission)
            cur.execute("SELECT pg_advisory_lock(hashtextextended(%s,0))", (str(source),))
            try:
                # Separate transactions are intentional: normalization failures keep
                # submissions staged for operator repair and later refresh retries.
                cur.execute("""SELECT id FROM navis.ingestion_submission
                    WHERE source_system_id=%s AND status='pending_identity' ORDER BY collected_at,id""", (source,))
                pending = [row[0] for row in cur.fetchall()]
                failures = []
                for submission_id in pending:
                    try:
                        process_submission(self.connection_factory, submission_id)
                    except (ValueError, PermissionError, LookupError) as exc:
                        failures.append({"ingestion_id": str(submission_id), "reason": str(exc)})
                cur.execute("""SELECT DISTINCT ON (s.device_id,c.data_type)
                    s.device_id,c.data_type,s.id,s.collected_at,c.coverage
                    FROM navis.device_snapshot s JOIN navis.import_batch b ON b.id=s.import_batch_id
                    JOIN navis.snapshot_coverage c ON c.snapshot_id=s.id
                    WHERE b.source_system_id=%s
                    ORDER BY s.device_id,c.data_type,s.collected_at DESC,s.received_at DESC,s.id DESC""", (source,))
                snapshots = cur.fetchall()
                if not snapshots:
                    raise ValueError("no processed snapshots; check device mappings and approved adapters")
                dataset = uuid4()
                cur.execute("INSERT INTO navis.graph_dataset(id,name) VALUES (%s,%s)", (dataset, name or "default:" + namespace))
                for device, kind, snapshot, _, _ in snapshots:
                    cur.execute("INSERT INTO navis.graph_dataset_snapshot(dataset_id,device_id,data_type,snapshot_id) VALUES (%s,%s,%s,%s)", (dataset, device, kind, snapshot))
                conn.commit()
                built = build_graph(self.connection_factory, dataset)
                projection = self.projection(cur, dataset)
                projection.update(namespace=namespace, snapshots=[{"device_id": str(d), "data_type": k, "snapshot_id": str(s), "collected_at": t.isoformat(), "coverage": c} for d,k,s,t,c in snapshots], pending_submissions=failures)
                cur.execute("INSERT INTO navis.topology_build(build_id,source_system_id,consumer_id,name,ips,projection) VALUES (%s,%s,%s,%s,%s,%s)",
                            (UUID(built["build_id"]), source, consumer if name else None, name, Jsonb(ips or []), Jsonb(projection)))
                conn.commit()
                return {"graph_build_id": built["build_id"], "dataset_id": str(dataset), "name": name, **application_view(projection, ips or [])}
            finally:
                # An error may leave the transaction aborted; release session lock.
                conn.rollback()
                cur.execute("SELECT pg_advisory_unlock(hashtextextended(%s,0))", (str(source),))

    def after_ingestion(self, principal, namespace):
        try:
            self.refresh(principal, namespace, permission="inventory:write")
        except Exception:
            log.exception("Automatic topology refresh failed for namespace %s; retry via topology API", namespace)

    @staticmethod
    def projection(cur, dataset):
        cur.execute("""SELECT DISTINCT s.device_id,d.display_name,host(a.address)
            FROM navis.graph_dataset_snapshot ds JOIN navis.device_snapshot s ON s.id=ds.snapshot_id
            JOIN navis.device d ON d.id=s.device_id
            LEFT JOIN navis.interface i ON i.snapshot_id=s.id AND ds.data_type='interface'
            LEFT JOIN navis.interface_address a ON a.interface_id=i.id WHERE ds.dataset_id=%s""", (dataset,))
        nodes = {}
        for device, name, address in cur.fetchall():
            node = nodes.setdefault(str(device), {"id": str(device), "name": name, "type": "device", "addresses": []})
            if address and address not in node["addresses"]:
                node["addresses"].append(address)
        cur.execute("""SELECT r.id,s.device_id,host(n.next_hop_address),n.id
            FROM navis.graph_dataset_snapshot ds JOIN navis.device_snapshot s ON s.id=ds.snapshot_id
            JOIN navis.route r ON r.snapshot_id=s.id JOIN navis.route_next_hop n ON n.route_id=r.id
            WHERE ds.dataset_id=%s AND ds.data_type='route' AND n.next_hop_address IS NOT NULL""", (dataset,))
        edges = []
        for route, device, address, hop in cur.fetchall():
            peers = [n["id"] for n in nodes.values() if address in n["addresses"] and n["id"] != str(device)]
            for peer in peers:
                edges.append({"source": str(device), "target": peer, "kind": "next_hop_candidate", "status": "unverified" if len(peers) == 1 else "ambiguous", "route_id": str(route), "next_hop_id": str(hop), "next_hop_address": address})
        cur.execute("""SELECT DISTINCT l.id,l.origin,da.device_id,db.device_id
            FROM navis.topology_link l
            JOIN navis.topology_link_endpoint a ON a.link_id=l.id AND a.endpoint_number=1
            JOIN navis.topology_link_endpoint b ON b.link_id=l.id AND b.endpoint_number=2
            JOIN navis.interface ia ON ia.id=a.interface_id JOIN navis.interface ib ON ib.id=b.interface_id
            JOIN navis.graph_dataset_snapshot da ON da.snapshot_id=ia.snapshot_id
            JOIN navis.graph_dataset_snapshot db ON db.snapshot_id=ib.snapshot_id AND db.dataset_id=da.dataset_id
            WHERE da.dataset_id=%s AND (l.valid_from IS NULL OR l.valid_from<=now())
            AND (l.valid_until IS NULL OR l.valid_until>now())""", (dataset,))
        for link, origin, left, right in cur.fetchall():
            edges.append({"source": str(left), "target": str(right), "kind": origin + "_link", "status": "declared", "link_id": str(link)})
        return {"nodes": list(nodes.values()), "connections": edges, "projection_status": "network_evidence_candidates"}

    def list_builds(self, principal, namespace=None, limit=50):
        with self.connection_factory() as conn, conn.cursor() as cur:
            consumer = self.consumer(cur, principal)
            cur.execute("""SELECT b.id,b.status,b.started_at,b.completed_at,t.name,s.namespace,b.dataset_id
                FROM navis.graph_build b LEFT JOIN navis.topology_build t ON t.build_id=b.id
                LEFT JOIN navis.source_system s ON s.id=t.source_system_id
                WHERE (t.consumer_id IS NULL OR t.consumer_id=%s)
                AND (%s::text IS NULL OR EXISTS (
                    SELECT 1 FROM navis.graph_build_snapshot bs JOIN navis.device_snapshot snap ON snap.id=bs.snapshot_id
                    JOIN navis.import_batch ib ON ib.id=snap.import_batch_id
                    JOIN navis.source_system src ON src.id=ib.source_system_id
                    WHERE bs.graph_build_id=b.id AND src.namespace=%s))
                AND EXISTS (SELECT 1 FROM navis.graph_build_snapshot bs WHERE bs.graph_build_id=b.id)
                AND NOT EXISTS (SELECT 1 FROM navis.graph_build_snapshot bs
                    JOIN navis.device_snapshot snap ON snap.id=bs.snapshot_id
                    JOIN navis.import_batch ib ON ib.id=snap.import_batch_id
                    WHERE bs.graph_build_id=b.id AND NOT EXISTS (
                        SELECT 1 FROM navis.consumer_data_scope ds WHERE ds.api_consumer_id=%s
                        AND ds.source_system_id=ib.source_system_id AND ds.permissions @> '["graph:read"]'::jsonb))
                ORDER BY b.started_at DESC,b.id LIMIT %s""", (consumer, namespace, namespace, consumer, limit))
            return {"builds": [{"graph_build_id": str(b), "status": status, "started_at": start, "completed_at": end, "name": name, "namespace": ns, "dataset_id": str(ds)} for b,status,start,end,name,ns,ds in cur.fetchall()]}

    def read(self, principal, build_id, permission="graph:read"):
        with self.connection_factory() as conn, conn.cursor() as cur:
            consumer = self.consumer(cur, principal)
            cur.execute("""SELECT t.name,t.ips,t.projection,t.consumer_id,t.source_system_id,b.dataset_id
                FROM navis.topology_build t JOIN navis.graph_build b ON b.id=t.build_id
                WHERE t.build_id=%s AND b.status='completed'""", (build_id,))
            row = cur.fetchone()
            if row is None:
                raise LookupError("topology build not found")
            name, ips, projection, owner, source, dataset = row
            if owner is not None and owner != consumer:
                raise PermissionError("topology belongs to another consumer")
            cur.execute("SELECT 1 FROM navis.consumer_data_scope WHERE api_consumer_id=%s AND source_system_id=%s AND permissions @> %s::jsonb", (consumer, source, '["' + permission + '"]'))
            if cur.fetchone() is None:
                raise PermissionError("topology outside source scope")
            return {"graph_build_id": str(build_id), "build_id": str(build_id), "dataset_id": str(dataset),
                    "status": "completed", "name": name, **application_view(projection, ips)}

    def ingestion_status(self, principal, submission_id):
        with self.connection_factory() as conn, conn.cursor() as cur:
            consumer = self.consumer(cur, principal)
            cur.execute("""SELECT i.status,s.namespace,i.data_type,i.collected_at FROM navis.ingestion_submission i
                JOIN navis.source_system s ON s.id=i.source_system_id WHERE i.id=%s AND EXISTS (
                    SELECT 1 FROM navis.consumer_data_scope ds WHERE ds.api_consumer_id=%s
                    AND ds.source_system_id=s.id AND ds.permissions @> '["inventory:write"]'::jsonb)""", (submission_id, consumer))
            row = cur.fetchone()
            if row is None:
                raise LookupError("ingestion not found or inaccessible")
            return {"ingestion_id": str(submission_id), "status": row[0], "namespace": row[1], "data_type": row[2], "collected_at": row[3]}
