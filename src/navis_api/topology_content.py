"""Compare network content independently of generated import IDs and timestamps."""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from .build_evidence import evidence_records


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_records(records, reference_aliases=None):
    """Resolve relational FKs to content; preserve order inside policy payloads.

    Unknown/cyclic references retain their IDs, conservatively causing a rebuild
    rather than guessing that different evidence is equivalent.
    """
    rows = [(table, json.loads(raw) if isinstance(raw, str) else raw) for table, _, raw in records]
    indexed = {row["id"]: (table, row) for table, row in rows if isinstance(row, dict) and row.get("id") and table != "device"}
    for old, current in (reference_aliases or {}).items():
        if current in indexed:
            indexed[old] = indexed[current]
    group_members = {}
    for table, row in rows:
        if table in ('address_group_member', 'service_group_member'):
            group_members.setdefault(row['group_id'], []).append(row['member_id'])
    cache = {}

    def reference(value, visiting):
        if value in visiting:
            return {"unresolved_reference": value}
        if value not in cache:
            ref_table, ref_row = indexed[value]
            cache[value] = {"table": ref_table, "record": canonical(ref_table, ref_row, visiting | {value})}
        return cache[value]

    def canonical(table, row, visiting=frozenset()):
        if row is None:
            return None
        if row.get('id'):
            visiting = visiting | {row['id']}
        output = {}
        for key, value in row.items():
            if key in {"normalization_run_id", "collected_at", "received_at", "created_at", "started_at", "completed_at"}:
                continue
            if table == "device" and key in {"first_seen_at", "last_seen_at"}:
                continue
            if key == "id" and table != "device" or table == "graph_config" and key == "dataset_id":
                continue
            if key.endswith("_id") and key != "native_id" and isinstance(value, str) and value in indexed:
                output[key] = reference(value, visiting)
            else:
                output[key] = value
        if table in ('address_object', 'service_object') and row.get('id') in group_members:
            output['members'] = sorted([reference(member, visiting) if member in indexed else
                {"unresolved_reference": member} for member in group_members[row['id']]], key=encoded)
        return output

    def devices(value):
        if isinstance(value, dict):
            result = {value["device_id"]} if isinstance(value.get("device_id"), str) else set()
            for item in value.values():
                result.update(devices(item))
            return result
        if isinstance(value, list):
            return set().union(*(devices(item) for item in value)) if value else set()
        return set()

    # Links outside the selected inventory, and inactive links, do not affect
    # this namespace's graph. Use the same current-validity rule as the builder.
    link_owners = {}
    endpoints = {}
    for table, row in rows:
        if table == "topology_link_endpoint" and row.get("interface_id") in indexed:
            value = canonical(table, row)
            endpoints.setdefault(row["link_id"], []).append(devices(value))
    for table, row in rows:
        if table == "topology_link" and len(endpoints.get(row["id"], [])) == 2:
            now = datetime.now(timezone.utc)
            start, end = row.get("valid_from"), row.get("valid_until")
            if start and datetime.fromisoformat(start) > now or end and datetime.fromisoformat(end) <= now:
                continue
            link_owners[row["id"]] = set().union(*endpoints[row["id"]])
    result = []
    for table, row in rows:
        if table == "topology_link" and row["id"] not in link_owners:
            continue
        if table == "topology_link_endpoint" and row["link_id"] not in link_owners:
            continue
        value = canonical(table, row)
        owners = devices(value)
        if table == "device":
            owners.add(row["id"])
        elif table == "topology_link":
            owners = link_owners[row["id"]]
        # Persist compact fingerprints, not another full copy of configurations.
        result.append({"table": table, "devices": sorted(owners),
                       "record_hash": hashlib.sha256(encoded(value).encode()).hexdigest()})
    return sorted(result, key=encoded)


def content_state(cur, dataset):
    selections, records = evidence_records(cur, dataset)
    data_types = {}
    for _, kind, snapshot in selections:
        data_types.setdefault(str(snapshot), set()).add(kind)
    # Raw vendor/normalized payloads and active identity aliases are significant
    # even when their data is not yet projected into AGE vertices.
    cur.execute("""SELECT r.id::text,row_to_json(r)::text FROM navis.raw_payload r
        WHERE r.snapshot_id IN (SELECT snapshot_id FROM navis.graph_dataset_snapshot WHERE dataset_id=%s)""", (dataset,))
    records.extend(("raw_payload", *row) for row in cur.fetchall())
    cur.execute("""SELECT e.id::text,row_to_json(e)::text FROM navis.nat_session_evidence e
        WHERE e.snapshot_id IN (SELECT snapshot_id FROM navis.graph_dataset_snapshot WHERE dataset_id=%s)""", (dataset,))
    records.extend(("nat_session_evidence", *row) for row in cur.fetchall())
    cur.execute("""SELECT DISTINCT m.id::text,row_to_json(m)::text FROM navis.device_identity_mapping m
        JOIN navis.graph_dataset_snapshot ds ON ds.device_id=m.device_id
        JOIN navis.device_snapshot s ON s.id=ds.snapshot_id
        JOIN navis.import_batch b ON b.id=s.import_batch_id AND b.source_system_id=m.source_system_id
        WHERE ds.dataset_id=%s AND m.valid_from<=s.collected_at
        AND (m.valid_until IS NULL OR m.valid_until>s.collected_at)""", (dataset,))
    records.extend(("device_identity_mapping", *row) for row in cur.fetchall())
    # Import batch IDs are delivery metadata, not network content.
    cleaned = []
    for table, key, raw in records:
        row = json.loads(raw) if isinstance(raw, str) else raw
        if table == "device_snapshot" and row:
            row.pop("import_batch_id", None)
            row.pop("source_snapshot_id", None)
            row["selected_data_types"] = sorted(data_types.get(str(row['id']), ()))
        cleaned.append((table, key, row))
    cur.execute("""SELECT DISTINCT ON (old.id) old.id::text,selected_iface.id::text
        FROM navis.topology_link_endpoint e JOIN navis.interface old ON old.id=e.interface_id
        JOIN navis.device_snapshot os ON os.id=old.snapshot_id
        JOIN navis.graph_dataset_snapshot ds ON ds.device_id=os.device_id
        JOIN navis.interface selected_iface ON selected_iface.snapshot_id=ds.snapshot_id AND selected_iface.native_id=old.native_id
        WHERE ds.dataset_id=%s ORDER BY old.id,(ds.data_type='interface') DESC,selected_iface.id""", (dataset,))
    aliases = dict(cur.fetchall())
    return {"records": canonical_records(cleaned, aliases),
            "builder": hashlib.sha256(Path(__file__).with_name("graph_builder.py").read_text(encoding="utf-8").encode()).hexdigest()}


def selected_content(state, projection, members):
    """A named graph includes its connected context, including alternate paths."""
    if not members:
        return {**state, "members": []}
    from .topology import application_view
    view = application_view(projection, members)
    relevant = {node["id"] for node in view["nodes"] if not node.get("placeholder")}
    adjacency = {}
    for edge in projection["connections"]:
        adjacency.setdefault(edge["source"], set()).add(edge["target"])
        adjacency.setdefault(edge["target"], set()).add(edge["source"])
    queue = list(relevant)
    while queue:
        for peer in adjacency.get(queue.pop(), ()):
            if peer not in relevant:
                relevant.add(peer)
                queue.append(peer)
    return {**state, "members": sorted(members), "member_resolution": view["member_resolution"],
            "records": [r for r in state["records"] if not r["devices"] or relevant.intersection(r["devices"])]}


def digest(state):
    return hashlib.sha256(encoded(state).encode()).hexdigest()


def compare_content(left, right):
    a = Counter((r["table"], encoded(r)) for r in left.get("records", []))
    b = Counter((r["table"], encoded(r)) for r in right.get("records", []))
    changes = {}
    for (table, _), count in (b-a).items():
        changes.setdefault(table, {"added": 0, "removed": 0})["added"] += count
    for (table, _), count in (a-b).items():
        changes.setdefault(table, {"added": 0, "removed": 0})["removed"] += count
    return {"changed": digest(left) != digest(right), "tables": changes,
            "members_added": sorted(set(right.get("members", []))-set(left.get("members", []))),
            "members_removed": sorted(set(left.get("members", []))-set(right.get("members", []))),
            "builder_changed": left.get("builder") != right.get("builder")}
