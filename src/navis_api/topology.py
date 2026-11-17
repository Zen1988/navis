"""Namespace-scoped incremental topology orchestration and frozen evidence views."""
import logging
from contextlib import contextmanager
from collections import deque
from ipaddress import ip_address
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .graph_builder import build_graph
from .worker import process_submission
from .build_evidence import evidence_manifest
from .topology_content import content_state, selected_content, digest, compare_content
from navis_common.path_visibility import inventory_evidence, unmanaged_node

log = logging.getLogger(__name__)


class TopologyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    namespace: str | None = Field(default=None, min_length=1, max_length=255)
    name: str | None = Field(default=None, min_length=1, max_length=255)
    ips: list[str] = Field(default_factory=list, max_length=1000)
    members: list[str] | None = Field(default=None, max_length=1000)

    @field_validator("name", "namespace")
    @classmethod
    def nonblank(cls, value, info):
        if value is not None:
            value = value.strip()
            if not value:
                raise ValueError("name and namespace must not be blank")
            if info.field_name == "name" and ('/' in value or any(ord(char) < 32 for char in value)):
                raise ValueError("topology names cannot contain slashes or control characters")
        return value

    @field_validator("members")
    @classmethod
    def member_names(cls, values):
        if values is None:
            return None
        cleaned = []
        for value in values:
            value = value.strip()
            if not value or len(value) > 255:
                raise ValueError("members must be nonblank names or IPs of at most 255 characters")
            try:
                value = str(ip_address(value))
            except ValueError:
                pass
            if value not in cleaned:
                cleaned.append(value)
        return cleaned

    @field_validator("ips")
    @classmethod
    def addresses(cls, values):
        return sorted({str(ip_address(value)) for value in values})


def application_view(projection, ips):
    """Select members by inventory name, external ID or IP and retain transit."""
    if not ips:
        return projection
    owners = {ref: {node["id"] for node in projection["nodes"] if not node.get("placeholder") and
                   (ref in node["addresses"] or ref == node.get("name") or ref in node.get("aliases", []))} for ref in ips}
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
    # Keep visibility boundaries adjacent to the selected managed network.
    placeholders = {n["id"] for n in projection["nodes"] if n.get("placeholder")}
    selected.update(peer for node in list(selected) for peer in adjacency.get(node, ()) if peer in placeholders)
    view_nodes = [n for n in projection["nodes"] if n["id"] in selected]
    for ip, candidates in owners.items():
        if not candidates:
            try:
                addresses = [str(ip_address(ip))]
            except ValueError:
                addresses = []
            node = unmanaged_node(["application_endpoint", ip], reason="endpoint_inventory_missing", addresses=addresses, role="endpoint")
            node["requested_member"] = ip
            view_nodes.append(node)
    return {**projection,
            "nodes": view_nodes,
            "connections": [e for e in projection["connections"] if e["source"] in selected and e["target"] in selected],
            "endpoint_candidates": {ip: sorted(nodes) for ip, nodes in owners.items()},
            "member_resolution": {ref: {"status": "resolved" if len(ids) == 1 else "ambiguous" if ids else "missing", "device_ids": sorted(ids)} for ref, ids in owners.items()},
            "view_status": "candidate_paths_not_a_reachability_verdict"}


class TopologyService:
    def __init__(self, connection_factory):
        self.connection_factory = connection_factory

    @contextmanager
    def trace_lease(self, build_id):
        """Keep a graph live until analysis and session persistence finish."""
        with self.connection_factory() as conn, conn.cursor() as cur:
            key = "graph:" + str(build_id)
            cur.execute("SELECT pg_advisory_lock_shared(hashtextextended(%s,2))", (key,))
            try:
                yield
            finally:
                conn.rollback()
                cur.execute("SELECT pg_advisory_unlock_shared(hashtextextended(%s,2))", (key,))

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

    def refresh(self, principal, namespace=None, *, permission="analysis:run", name=None, ips=None, members=None):
        """Freeze latest processed evidence; serialize ingestion/builds per source."""
        from psycopg.types.json import Jsonb
        with self.connection_factory() as conn, conn.cursor() as cur:
            consumer, source, namespace = self.source(cur, principal, namespace, permission)
            cur.execute("SELECT pg_advisory_lock(hashtextextended(%s,0))", (str(source),))
            try:
                name = name or "default"
                selectors = list(dict.fromkeys((members or []) + (ips or [])))
                if len(selectors) > 1000:
                    raise ValueError("a topology supports at most 1000 members")
                if name == "default" and selectors:
                    raise ValueError("default includes all inventory; provide a name for a member-selected topology")
                if name != "default" and not selectors:
                    if members is not None:
                        raise ValueError("a named topology requires at least one member")
                    cur.execute("""SELECT members FROM navis.topology_definition
                        WHERE source_system_id=%s AND consumer_id=%s AND name=%s""", (source, consumer, name))
                    definition = cur.fetchone()
                    if definition is None:
                        raise LookupError("named topology not found; create it with members first")
                    selectors = definition[0]
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
                cur.execute("INSERT INTO navis.graph_dataset(id,name) VALUES (%s,%s)", (dataset, name + ":" + namespace))
                for device, kind, snapshot, _, _ in snapshots:
                    cur.execute("INSERT INTO navis.graph_dataset_snapshot(dataset_id,device_id,data_type,snapshot_id) VALUES (%s,%s,%s,%s)", (dataset, device, kind, snapshot))
                projection = self.projection(cur, dataset)
                state = content_state(cur, dataset)
                selected = selected_content(state, projection, selectors)
                evidence = {"snapshots": [{"device_id": str(d), "data_type": k, "snapshot_id": str(s), "collected_at": t.isoformat(), "coverage": c} for d,k,s,t,c in snapshots], "pending_submissions": failures}
                owner = consumer if name != "default" else None
                head = self.head(cur, source, owner, name)
                reusable = self.reusable(cur, head, selected)
                build_head = head if reusable else None
                if not reusable and owner is not None:
                    base = self.head(cur, source, None, "default")
                    if self.reusable(cur, base, selected_content(state, projection, [])):
                        build_head = base
                if build_head:
                    # The provisional selection is not a new graph or saved dataset.
                    cur.execute("DELETE FROM navis.graph_dataset_snapshot WHERE dataset_id=%s", (dataset,))
                    cur.execute("DELETE FROM navis.graph_dataset WHERE id=%s", (dataset,))
                    build_id = build_head["graph_build_id"]
                    dataset = build_head["dataset_id"]
                    version = self.publish(cur, source, owner, name, selectors, build_id, selected, evidence, head, reusable)
                    if owner is None:
                        self.refresh_named_views(cur, source, build_id, state, projection, evidence)
                else:
                    conn.commit()
                    projection.update(namespace=namespace, **evidence)
                    def publish_build(build_cur, new_build):
                        build_cur.execute("INSERT INTO navis.topology_build(build_id,source_system_id,consumer_id,name,ips,members,projection) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                                          (new_build, source, owner, name, Jsonb(ips or []), Jsonb(selectors), Jsonb(projection)))
                        saved = self.publish(build_cur, source, owner, name, selectors, new_build, selected, evidence, head, False)
                        if owner is None:
                            self.refresh_named_views(build_cur, source, new_build, state, projection, evidence)
                        return saved
                    built = build_graph(self.connection_factory, dataset, after_build=publish_build)
                    build_id = UUID(built["build_id"])
                    version = built["publication"]
                conn.commit()
                if build_head:
                    # Keep original IDs/provenance in the frozen graph; fresh
                    # collection receipts are exposed separately as latest_evidence.
                    projection = self.read(principal, build_id, permission=permission, full=True)
                return {**application_view(projection, selectors), "graph_build_id": str(build_id),
                        "dataset_id": str(dataset), "name": name, "members": selectors,
                        **version, "latest_evidence": evidence, "pending_submissions": failures}
            finally:
                conn.rollback()
                cur.execute("SELECT pg_advisory_unlock(hashtextextended(%s,0))", (str(source),))

    @staticmethod
    def head(cur, source, owner, name):
        cur.execute("""SELECT d.id,v.id,v.build_id,v.content_hash,v.content,v.members,v.built_at,
                v.updated_at,v.check_count,b.dataset_id,b.evidence_manifest,v.latest_evidence
            FROM navis.topology_definition d LEFT JOIN navis.topology_version v ON v.id=d.latest_version_id
            LEFT JOIN navis.graph_build b ON b.id=v.build_id
            WHERE d.source_system_id=%s AND d.consumer_id IS NOT DISTINCT FROM %s::uuid AND d.name=%s""", (source, owner, name))
        row = cur.fetchone()
        if row is None:
            return None
        return dict(zip(("topology_id", "version_id", "graph_build_id", "content_hash", "content", "members", "built_at", "updated_at", "check_count", "dataset_id", "evidence_manifest", "latest_evidence"), row))

    @staticmethod
    def reusable(cur, head, state):
        if not head or head["content_hash"] != digest(state) or head["evidence_manifest"] is None:
            return False
        current = evidence_manifest(cur, head["dataset_id"])
        if current != head["evidence_manifest"]:
            # Metadata freshness may change while network content does not.
            # Rebaseline only if the original graph's semantic evidence still
            # matches its stored content fingerprint; otherwise rebuild it.
            cur.execute("SELECT projection FROM navis.topology_build WHERE build_id=%s", (head["graph_build_id"],))
            row = cur.fetchone()
            if row is None:
                return False
            original = selected_content(content_state(cur, head["dataset_id"]), row[0], head["members"])
            if digest(original) != head["content_hash"]:
                return False
            from psycopg.types.json import Jsonb
            cur.execute("UPDATE navis.graph_build SET evidence_manifest=%s WHERE id=%s", (Jsonb(current), head["graph_build_id"]))
        return True

    @staticmethod
    def publish(cur, source, owner, name, members, build_id, state, evidence, head, reusable):
        """Only save a new version when content changes; otherwise recheck it."""
        from psycopg.types.json import Jsonb
        if owner is not None:
            relevant = {device for row in state.get("records", []) for device in row.get("devices", [])}
            evidence = {**evidence, "snapshots": [s for s in evidence.get("snapshots", []) if s["device_id"] in relevant]}
        if owner is None:
            cur.execute("""INSERT INTO navis.topology_definition(id,source_system_id,consumer_id,name,members,latest_build_id)
                VALUES (%s,%s,NULL,'default','[]',%s)
                ON CONFLICT (source_system_id) WHERE consumer_id IS NULL
                DO UPDATE SET name=EXCLUDED.name RETURNING id""", (uuid4(), source, build_id))
        else:
            cur.execute("""INSERT INTO navis.topology_definition(id,source_system_id,consumer_id,name,members,latest_build_id)
                VALUES (%s,%s,%s,%s,%s,%s)
                ON CONFLICT (source_system_id,consumer_id,name) WHERE consumer_id IS NOT NULL
                DO UPDATE SET members=EXCLUDED.members RETURNING id""", (uuid4(), source, owner, name, Jsonb(members), build_id))
        topology_id = cur.fetchone()[0]
        if reusable:
            version_id, build_id = head["version_id"], head["graph_build_id"]
            cur.execute("""UPDATE navis.topology_version SET updated_at=clock_timestamp(),check_count=check_count+1,
                latest_evidence=%s WHERE id=%s RETURNING built_at,updated_at,check_count""", (Jsonb(evidence), version_id))
        else:
            version_id = uuid4()
            cur.execute("""INSERT INTO navis.topology_version(id,topology_id,build_id,members,content_hash,content,latest_evidence)
                VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING built_at,updated_at,check_count""",
                        (version_id, topology_id, build_id, Jsonb(members), digest(state), Jsonb(state), Jsonb(evidence)))
        built_at, updated_at, count = cur.fetchone()
        cur.execute("""UPDATE navis.topology_definition SET latest_build_id=%s,latest_version_id=%s,updated_at=%s WHERE id=%s""", (build_id, version_id, updated_at, topology_id))
        return {"version_id": str(version_id), "built_at": built_at, "updated_at": updated_at,
                "check_count": count, "changed": not reusable}

    def refresh_named_views(self, cur, source, build_id, state, projection, evidence):
        cur.execute("SELECT consumer_id,name,members FROM navis.topology_definition WHERE source_system_id=%s AND consumer_id IS NOT NULL", (source,))
        for owner, name, members in cur.fetchall():
            selected = selected_content(state, projection, members)
            head = self.head(cur, source, owner, name)
            same = self.reusable(cur, head, selected)
            self.publish(cur, source, owner, name, members, build_id, selected, evidence, head, same)

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
            node = nodes.setdefault(str(device), {"id": str(device), "name": name, "type": "device", "addresses": [], **inventory_evidence()})
            if address and address not in node["addresses"]:
                node["addresses"].append(address)
        cur.execute("""SELECT DISTINCT m.device_id,m.external_id FROM navis.device_identity_mapping m
            JOIN navis.graph_dataset_snapshot ds ON ds.device_id=m.device_id
            JOIN navis.device_snapshot s ON s.id=ds.snapshot_id
            JOIN navis.import_batch b ON b.id=s.import_batch_id AND b.source_system_id=m.source_system_id
            WHERE ds.dataset_id=%s AND NOT EXISTS (
                SELECT 1 FROM navis.graph_dataset_snapshot other
                JOIN navis.device_snapshot os ON os.id=other.snapshot_id
                WHERE other.dataset_id=ds.dataset_id AND other.device_id=m.device_id
                AND NOT (m.valid_from<=os.collected_at AND (m.valid_until IS NULL OR m.valid_until>os.collected_at)))""", (dataset,))
        for device, external_id in cur.fetchall():
            if str(device) in nodes:
                nodes[str(device)].setdefault("aliases", []).append(external_id)
        cur.execute("""SELECT r.id,s.device_id,host(n.next_hop_address),n.id
            FROM navis.graph_dataset_snapshot ds JOIN navis.device_snapshot s ON s.id=ds.snapshot_id
            JOIN navis.route r ON r.snapshot_id=s.id JOIN navis.route_next_hop n ON n.route_id=r.id
            WHERE ds.dataset_id=%s AND ds.data_type='route' AND n.next_hop_address IS NOT NULL""", (dataset,))
        edges = []
        # Match against actual inventory only; placeholders cannot resolve a peer.
        inventory = list(nodes.values())
        for route, device, address, hop in cur.fetchall():
            peers = [n["id"] for n in inventory if address in n["addresses"] and n["id"] != str(device)]
            if not peers:
                missing = unmanaged_node(["next_hop", str(device), str(route), address],
                                         reason="next_hop_inventory_missing", addresses=[address])
                nodes[missing["id"]] = missing
                edges.append({"source": str(device), "target": missing["id"], "kind": "visibility_gap", "status": "unknown", "route_id": str(route), "next_hop_id": str(hop), "next_hop_address": address})
            for peer in peers:
                edges.append({"source": str(device), "target": peer, "kind": "next_hop_candidate", "status": "unverified" if len(peers) == 1 else "ambiguous", "route_id": str(route), "next_hop_id": str(hop), "next_hop_address": address})
        cur.execute("""SELECT DISTINCT l.id,l.origin,da.device_id,db.device_id
            FROM navis.topology_link l
            JOIN navis.topology_link_endpoint a ON a.link_id=l.id AND a.endpoint_number=1
            JOIN navis.topology_link_endpoint b ON b.link_id=l.id AND b.endpoint_number=2
            JOIN navis.interface ia ON ia.id=a.interface_id JOIN navis.interface ib ON ib.id=b.interface_id
            JOIN navis.device_snapshot sa ON sa.id=ia.snapshot_id
            JOIN navis.device_snapshot sb ON sb.id=ib.snapshot_id
            JOIN navis.graph_dataset_snapshot da ON da.device_id=sa.device_id
            JOIN navis.interface ca ON ca.snapshot_id=da.snapshot_id AND ca.native_id=ia.native_id
            JOIN navis.graph_dataset_snapshot db ON db.device_id=sb.device_id AND db.dataset_id=da.dataset_id
            JOIN navis.interface cb ON cb.snapshot_id=db.snapshot_id AND cb.native_id=ib.native_id
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

    def list_topologies(self, principal, namespace=None, limit=50):
        with self.connection_factory() as conn, conn.cursor() as cur:
            consumer = self.consumer(cur, principal)
            cur.execute("""SELECT t.name,s.namespace,t.members,t.latest_build_id,v.id,v.built_at,v.updated_at,v.check_count
                FROM navis.topology_definition t JOIN navis.source_system s ON s.id=t.source_system_id
                JOIN navis.topology_version v ON v.id=t.latest_version_id
                WHERE (t.consumer_id IS NULL OR t.consumer_id=%s)
                AND (%s::text IS NULL OR s.namespace=%s)
                AND EXISTS (SELECT 1 FROM navis.consumer_data_scope ds WHERE ds.api_consumer_id=%s
                    AND ds.source_system_id=s.id AND ds.permissions @> '["graph:read"]'::jsonb)
                ORDER BY s.namespace,t.name LIMIT %s""", (consumer, namespace, namespace, consumer, limit))
            from navis_common.lifecycle import lifecycle
            return {"topologies": [{"name": name, "namespace": ns, "members": members,
                "graph_build_id": str(build), "version_id": str(version), "built_at": built,
                "updated_at": updated, "check_count": count, "lifecycle": lifecycle(updated, active=True)}
                for name, ns, members, build, version, built, updated, count in cur.fetchall()]}

    def named_definition(self, cur, principal, name, namespace, permission):
        consumer, source, namespace = self.source(cur, principal, namespace, permission)
        cur.execute("""SELECT id,latest_version_id FROM navis.topology_definition
            WHERE source_system_id=%s AND name=%s AND
            ((%s='default' AND consumer_id IS NULL) OR consumer_id=%s)""", (source, name, name, consumer))
        row = cur.fetchone()
        if row is None:
            raise LookupError("topology name not found")
        return row[0], row[1], namespace

    def read_named(self, principal, name, namespace=None, permission="graph:read", version_id=None):
        with self.connection_factory() as conn, conn.cursor() as cur:
            definition, latest, namespace = self.named_definition(cur, principal, name, namespace, permission)
            selected = version_id or latest
            cur.execute("""SELECT v.id,v.build_id,v.members,v.built_at,v.updated_at,v.check_count,v.latest_evidence,
                EXISTS (SELECT 1 FROM navis.trace_session s WHERE s.graph_build_id=v.build_id AND s.expires_at>now())
                FROM navis.topology_version v WHERE v.topology_id=%s AND v.id=%s""", (definition, selected))
            row = cur.fetchone()
            archived_at = None
            pinned = False
            if row is None:
                if version_id is None:
                    raise LookupError("topology version not found")
                archived, context, archived_at = self.archived_version(cur, definition, selected)
                version, build_id, members = archived["id"], archived["build_id"], archived["members"]
                built, updated, count, evidence = archived["built_at"], archived["updated_at"], archived["check_count"], archived["latest_evidence"]
                graph = {**context["projection"], "graph_build_id": str(build_id)}
            else:
                version, build_id, members, built, updated, count, evidence, pinned = row
                graph = None
        if graph is None:
            graph = self.read(principal, build_id, permission=permission, full=True)
        from navis_common.lifecycle import lifecycle
        return {**application_view(graph, members), "name": name, "members": members,
                "namespace": namespace, "version_id": str(version), "built_at": built,
                "updated_at": updated, "check_count": count, "is_latest": str(version) == str(latest),
                "latest_evidence": evidence, "lifecycle": lifecycle(updated, active=str(version) == str(latest) or pinned, protected=pinned, archived_at=archived_at)}

    def versions(self, principal, name, namespace=None, limit=50, include_audit=False):
        with self.connection_factory() as conn, conn.cursor() as cur:
            definition, latest, namespace = self.named_definition(cur, principal, name, namespace, "graph:read")
            cur.execute("""SELECT v.id,v.build_id,v.built_at,v.updated_at,v.check_count,v.members,
                EXISTS (SELECT 1 FROM navis.trace_session s WHERE s.graph_build_id=v.build_id AND s.expires_at>now())
                FROM navis.topology_version v WHERE v.topology_id=%s ORDER BY v.built_at DESC,v.id LIMIT %s""", (definition, limit))
            from navis_common.lifecycle import lifecycle
            versions = [{"version_id": str(v), "graph_build_id": str(b), "built_at": built,
                "updated_at": updated, "check_count": count, "members": members, "is_latest": v == latest,
                "lifecycle": lifecycle(updated, active=v == latest or pinned, protected=pinned)} for v,b,built,updated,count,members,pinned in cur.fetchall()]
            if include_audit:
                cur.execute("""SELECT row_data,archived_at FROM navis.audit_record WHERE source_table='topology_version'
                    AND row_data->>'topology_id'=%s ORDER BY source_updated_at DESC LIMIT %s""", (str(definition), limit))
                for row, archived_at in cur.fetchall():
                    versions.append({"version_id": row["id"], "graph_build_id": row["build_id"], "built_at": row["built_at"],
                        "updated_at": row["updated_at"], "check_count": row["check_count"], "members": row["members"], "is_latest": False,
                        "lifecycle": lifecycle(row["updated_at"], active=False, archived_at=archived_at)})
            from navis_common.lifecycle import as_datetime
            versions.sort(key=lambda v: (as_datetime(v["built_at"]), v["version_id"]), reverse=True)
            return {"name": name, "namespace": namespace, "versions": versions[:limit]}

    def compare(self, principal, name, from_version, to_version=None, namespace=None):
        with self.connection_factory() as conn, conn.cursor() as cur:
            definition, latest, namespace = self.named_definition(cur, principal, name, namespace, "graph:read")
            states = []
            for version in (from_version, to_version or latest):
                cur.execute("SELECT content FROM navis.topology_version WHERE topology_id=%s AND id=%s", (definition, version))
                row = cur.fetchone()
                if row is None:
                    archived, _, _ = self.archived_version(cur, definition, version)
                    states.append(archived["content"])
                else:
                    states.append(row[0])
            if not all("records" in state for state in states):
                raise ValueError("legacy version lacks a content baseline; refresh this topology first")
            return {"name": name, "namespace": namespace, "from_version": str(from_version),
                    "to_version": str(to_version or latest), **compare_content(*states)}

    @staticmethod
    def archived_version(cur, definition, version):
        cur.execute("""SELECT row_data,context,archived_at FROM navis.audit_record
            WHERE source_table='topology_version' AND record_key->>'id'=%s
            AND row_data->>'topology_id'=%s ORDER BY archived_at DESC LIMIT 1""", (str(version), str(definition)))
        row = cur.fetchone()
        if row is None:
            raise LookupError("topology version not found")
        return row

    def read(self, principal, build_id, permission="graph:read", *, full=False):
        with self.connection_factory() as conn, conn.cursor() as cur:
            consumer = self.consumer(cur, principal)
            cur.execute("""SELECT t.name,t.members,t.projection,t.consumer_id,t.source_system_id,b.dataset_id
                FROM navis.topology_build t JOIN navis.graph_build b ON b.id=t.build_id
                WHERE t.build_id=%s AND b.status='completed'""", (build_id,))
            row = cur.fetchone()
            if row is None:
                raise LookupError("topology build not found")
            name, members, projection, owner, source, dataset = row
            if owner is not None and owner != consumer:
                raise PermissionError("topology belongs to another consumer")
            cur.execute("SELECT 1 FROM navis.consumer_data_scope WHERE api_consumer_id=%s AND source_system_id=%s AND permissions @> %s::jsonb", (consumer, source, '["' + permission + '"]'))
            if cur.fetchone() is None:
                raise PermissionError("topology outside source scope")
            return {"graph_build_id": str(build_id), "build_id": str(build_id), "dataset_id": str(dataset),
                    "status": "completed", "name": name or "default", "members": members,
                    **(projection if full else application_view(projection, members))}

    def ingestion_status(self, principal, submission_id):
        with self.connection_factory() as conn, conn.cursor() as cur:
            consumer = self.consumer(cur, principal)
            cur.execute("""SELECT i.status,s.namespace,i.data_type,i.collected_at,i.updated_at,i.snapshot_id,
                (i.status IN ('pending_identity','pending_processing')
                 OR EXISTS (SELECT 1 FROM navis.topology_definition d JOIN navis.graph_build_snapshot bs ON bs.graph_build_id=d.latest_build_id
                    WHERE d.source_system_id=i.source_system_id AND bs.snapshot_id=i.snapshot_id)
                 OR (ss.id IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM navis.device_snapshot ns JOIN navis.import_batch nb ON nb.id=ns.import_batch_id
                    JOIN navis.snapshot_coverage nc ON nc.snapshot_id=ns.id AND nc.data_type=i.data_type
                    WHERE ns.device_id=ss.device_id AND nb.source_system_id=i.source_system_id
                    AND (ns.collected_at,ns.received_at,ns.id)>(ss.collected_at,ss.received_at,ss.id)))),
                (EXISTS (SELECT 1 FROM navis.graph_build_snapshot bs WHERE bs.snapshot_id=i.snapshot_id)
                 OR EXISTS (SELECT 1 FROM navis.graph_dataset_snapshot ds WHERE ds.snapshot_id=i.snapshot_id))
                ,i.external_device_id,i.completeness,i.input_items,i.processed_items,i.processing_error,
                i.processing_attempts,i.last_attempt_at,ss.device_id,i.collection_run_id,i.adapter_name,i.input_format,i.format_version
                FROM navis.ingestion_submission i
                LEFT JOIN navis.device_snapshot ss ON ss.id=i.snapshot_id
                JOIN navis.source_system s ON s.id=i.source_system_id WHERE i.id=%s AND EXISTS (
                    SELECT 1 FROM navis.consumer_data_scope ds WHERE ds.api_consumer_id=%s
                    AND ds.source_system_id=s.id AND ds.permissions @> '["inventory:write"]'::jsonb)""", (submission_id, consumer))
            row = cur.fetchone()
            if row is None:
                raise LookupError("ingestion not found or inaccessible")
            from navis_common.lifecycle import lifecycle
            from .ingestion_progress import details
            result = {"ingestion_id": str(submission_id), "status": row[0], "namespace": row[1], "data_type": row[2],
                    "collected_at": row[3], "updated_at": row[4], "snapshot_id": str(row[5]) if row[5] else None,
                    "lifecycle": lifecycle(row[4], active=row[6], protected=row[7])}
            result.update(dict(zip(('external_device_id','completeness','input_items','processed_items','processing_error',
                                    'processing_attempts','last_attempt_at','device_id','collection_run_id','adapter_name','input_format','format_version'), row[8:])))
            return details(result)

    def collection_progress(self, principal, run_id, namespace=None, limit=50, offset=0):
        from .ingestion_progress import collection
        with self.connection_factory() as conn, conn.cursor() as cur:
            cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            consumer = self.consumer(cur, principal)
            return collection(cur, consumer, run_id, namespace, limit, offset)
