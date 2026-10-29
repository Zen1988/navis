"""Detect changes to the relational evidence included in a graph build."""
import hashlib
import json


def evidence_manifest(cur, dataset_id):
    # Canonical whole-row JSON preserves changes to values as well as membership.
    # A digest detects modification; it does not prove collection completeness.
    cur.execute("""SELECT ds.device_id::text, ds.data_type, ds.snapshot_id::text
        FROM navis.graph_dataset_snapshot ds WHERE ds.dataset_id=%s
        ORDER BY ds.device_id,ds.data_type,ds.snapshot_id""", (dataset_id,))
    selections = cur.fetchall()
    cur.execute("""SELECT s.id::text, row_to_json(s)::text FROM navis.device_snapshot s
        WHERE s.id IN (SELECT snapshot_id FROM navis.graph_dataset_snapshot WHERE dataset_id=%s)
        ORDER BY s.id""", (dataset_id,))
    records = [("device_snapshot", *row) for row in cur.fetchall()]
    # Only fixed identifiers are interpolated, never collector-provided text.
    for table in ("snapshot_coverage", "interface", "routing_context", "route", "route_next_hop", "neighbor_entry", "mac_entry", "enforcement_point", "address_object", "service_object", "policy_applicability"):
        cur.execute(f"SELECT t.id::text,row_to_json(t)::text FROM navis.{table} t WHERE t.snapshot_id IN (SELECT snapshot_id FROM navis.graph_dataset_snapshot WHERE dataset_id=%s) ORDER BY t.id", (dataset_id,))
        records.extend((table, *row) for row in cur.fetchall())
    for table, parent, foreign in (("interface_address", "interface", "interface_id"),
                                    ("policy_rule_set", "enforcement_point", "enforcement_point_id"),
                                    ("security_zone", "enforcement_point", "enforcement_point_id"),
                                    ("nat_rule_set", "enforcement_point", "enforcement_point_id")):
        cur.execute(f"SELECT t.id::text,row_to_json(t)::text FROM navis.{table} t JOIN navis.{parent} p ON p.id=t.{foreign} WHERE p.snapshot_id IN (SELECT snapshot_id FROM navis.graph_dataset_snapshot WHERE dataset_id=%s) ORDER BY t.id", (dataset_id,))
        records.extend((table, *row) for row in cur.fetchall())
    # Higher-level and membership rows are captured separately below.
    queries = {
        "device": "SELECT d.id::text,row_to_json(d)::text FROM navis.device d WHERE d.id IN (SELECT device_id FROM navis.graph_dataset_snapshot WHERE dataset_id=%s) ORDER BY d.id",
        "interface_segment": "SELECT t.id::text,row_to_json(t)::text FROM navis.interface_segment t JOIN navis.interface i ON i.id=t.interface_id WHERE i.snapshot_id IN (SELECT snapshot_id FROM navis.graph_dataset_snapshot WHERE dataset_id=%s) ORDER BY t.id",
        "policy_schedule": "SELECT t.id::text,row_to_json(t)::text FROM navis.policy_schedule t JOIN navis.policy_rule r ON r.id=t.policy_rule_id JOIN navis.policy_rule_set rs ON rs.id=r.rule_set_id JOIN navis.enforcement_point ep ON ep.id=rs.enforcement_point_id WHERE ep.snapshot_id IN (SELECT snapshot_id FROM navis.graph_dataset_snapshot WHERE dataset_id=%s) ORDER BY t.id",
        "address_group_member": "SELECT (t.group_id::text || ':' || t.member_id::text),row_to_json(t)::text FROM navis.address_group_member t JOIN navis.address_object a ON a.id=t.group_id WHERE a.snapshot_id IN (SELECT snapshot_id FROM navis.graph_dataset_snapshot WHERE dataset_id=%s) ORDER BY 1",
        "service_group_member": "SELECT (t.group_id::text || ':' || t.member_id::text),row_to_json(t)::text FROM navis.service_group_member t JOIN navis.service_object a ON a.id=t.group_id WHERE a.snapshot_id IN (SELECT snapshot_id FROM navis.graph_dataset_snapshot WHERE dataset_id=%s) ORDER BY 1",
        "route_protocol_attributes": "SELECT t.route_id::text,row_to_json(t)::text FROM navis.route_protocol_attributes t JOIN navis.route r ON r.id=t.route_id WHERE r.snapshot_id IN (SELECT snapshot_id FROM navis.graph_dataset_snapshot WHERE dataset_id=%s) ORDER BY t.route_id",
        "policy_rule": "SELECT t.id::text,row_to_json(t)::text FROM navis.policy_rule t JOIN navis.policy_rule_set rs ON rs.id=t.rule_set_id JOIN navis.enforcement_point ep ON ep.id=rs.enforcement_point_id WHERE ep.snapshot_id IN (SELECT snapshot_id FROM navis.graph_dataset_snapshot WHERE dataset_id=%s) ORDER BY t.id",
        "policy_selector": "SELECT t.id::text,row_to_json(t)::text FROM navis.policy_selector t JOIN navis.policy_rule r ON r.id=t.policy_rule_id JOIN navis.policy_rule_set rs ON rs.id=r.rule_set_id JOIN navis.enforcement_point ep ON ep.id=rs.enforcement_point_id WHERE ep.snapshot_id IN (SELECT snapshot_id FROM navis.graph_dataset_snapshot WHERE dataset_id=%s) ORDER BY t.id",
        "nat_rule": "SELECT t.id::text,row_to_json(t)::text FROM navis.nat_rule t JOIN navis.nat_rule_set rs ON rs.id=t.nat_rule_set_id JOIN navis.enforcement_point ep ON ep.id=rs.enforcement_point_id WHERE ep.snapshot_id IN (SELECT snapshot_id FROM navis.graph_dataset_snapshot WHERE dataset_id=%s) ORDER BY t.id",
        "nat_selector": "SELECT t.id::text,row_to_json(t)::text FROM navis.nat_selector t JOIN navis.nat_rule r ON r.id=t.nat_rule_id JOIN navis.nat_rule_set rs ON rs.id=r.nat_rule_set_id JOIN navis.enforcement_point ep ON ep.id=rs.enforcement_point_id WHERE ep.snapshot_id IN (SELECT snapshot_id FROM navis.graph_dataset_snapshot WHERE dataset_id=%s) ORDER BY t.id",
        "nat_translation": "SELECT t.id::text,row_to_json(t)::text FROM navis.nat_translation t JOIN navis.nat_rule r ON r.id=t.nat_rule_id JOIN navis.nat_rule_set rs ON rs.id=r.nat_rule_set_id JOIN navis.enforcement_point ep ON ep.id=rs.enforcement_point_id WHERE ep.snapshot_id IN (SELECT snapshot_id FROM navis.graph_dataset_snapshot WHERE dataset_id=%s) ORDER BY t.id",
        "zone_member": "SELECT (t.security_zone_id::text || ':' || t.interface_id::text),row_to_json(t)::text FROM navis.security_zone_member t JOIN navis.security_zone z ON z.id=t.security_zone_id JOIN navis.enforcement_point ep ON ep.id=z.enforcement_point_id WHERE ep.snapshot_id IN (SELECT snapshot_id FROM navis.graph_dataset_snapshot WHERE dataset_id=%s) ORDER BY 1",
    }
    for table, query in queries.items():
        cur.execute(query, (dataset_id,))
        records.extend((table, *row) for row in cur.fetchall())
    cur.execute("SELECT COALESCE(row_to_json(c)::text, 'null') FROM navis.graph_dataset d LEFT JOIN navis.graph_config c ON c.dataset_id=d.id WHERE d.id=%s", (dataset_id,))
    records.extend(("graph_config", str(i), row[0]) for i, row in enumerate(cur.fetchall()))
    # Include all declared link records: the builder considers them globally.
    for table, key in (("topology_link", "id::text"), ("topology_link_endpoint", "link_id::text || ':' || endpoint_number::text")):
        cur.execute(f"SELECT {key},row_to_json(t)::text FROM navis.{table} t ORDER BY 1")
        records.extend((table, *row) for row in cur.fetchall())
    payload = json.dumps({"selections": selections, "records": records}, separators=(",", ":"), ensure_ascii=True)
    return {"algorithm": "sha256", "digest": hashlib.sha256(payload.encode()).hexdigest(), "version": 1}
