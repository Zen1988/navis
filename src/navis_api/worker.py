"""Transactional processor for the built-in normalized adapter."""
import hashlib
from pathlib import Path
from uuid import uuid4

from . import normalized_adapter


def _write_selectors(cur, snapshot, point_id, rule_id, selectors, policy):
    """Persist selectors in typed rows; unsupported kinds fail during validation."""
    from ipaddress import ip_network
    from psycopg.types.json import Jsonb
    table = "policy_selector" if policy else "nat_selector"
    rule_column = "policy_rule_id" if policy else "nat_rule_id"
    for selector in selectors:
        kind, value = selector["kind"], selector["value"]
        address_id = service_id = zone_id = interface_id = None
        if kind == "address":
            address_id = uuid4()
            cur.execute("INSERT INTO navis.address_object(id,snapshot_id,kind,prefix,details) VALUES (%s,%s,'prefix',%s,%s)", (address_id, snapshot, str(ip_network(value, strict=False)), Jsonb({"original": value})))
        elif kind == "service":
            service_id = uuid4()
            cur.execute("INSERT INTO navis.service_object(id,snapshot_id,protocol,destination_port_start,destination_port_end,source_port_start,source_port_end,details) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)", (service_id, snapshot, value["protocol"], value["destination_port_start"], value["destination_port_end"], value.get("source_port_start"), value.get("source_port_end"), Jsonb({key: value[key] for key in ("tcp_flags_all", "tcp_flags_any") if key in value})))
        elif kind == "zone":
            cur.execute("SELECT id FROM navis.security_zone WHERE enforcement_point_id=%s AND native_id=%s", (point_id, value))
            found = cur.fetchone()
            zone_id = found[0] if found else uuid4()
            if not found:
                cur.execute("INSERT INTO navis.security_zone(id,enforcement_point_id,native_id,name) VALUES (%s,%s,%s,%s)", (zone_id, point_id, value, value))
        elif kind == "interface":
            cur.execute("SELECT id FROM navis.interface WHERE snapshot_id=%s AND native_id=%s", (snapshot, value))
            found = cur.fetchone()
            interface_id = found[0] if found else uuid4()
            if not found:
                cur.execute("INSERT INTO navis.interface(id,snapshot_id,native_id,name,kind) VALUES (%s,%s,%s,%s,'unknown')", (interface_id, snapshot, value, value))
        cur.execute(f"INSERT INTO navis.{table}(id,{rule_column},role,address_object_id,service_object_id,security_zone_id,interface_id,negated,matches_any) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)", (uuid4(), rule_id, selector["role"], address_id, service_id, zone_id, interface_id, selector["negated"], kind == "any"))


def process_submission(connection_factory, submission_id):
    """Process one staged submission; failures roll back all database writes.

    Invoke only from a trusted worker with restricted database permissions.
    Identity mappings must be unique and valid at collection time.
    """
    from psycopg.types.json import Jsonb
    with connection_factory() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT source_system_id, external_device_id, claimed_device_id, adapter_name, input_format, format_version, data_type, collected_at, completeness, payload, status FROM navis.ingestion_submission WHERE id=%s FOR UPDATE", (submission_id,))
            row = cur.fetchone()
            if row is None:
                raise LookupError("submission not found")
            source, external, claimed, adapter, fmt, version, kind, collected, completeness, payload, status = row
            if status in ("processed", "raw_only"):
                raise ValueError("submission already processed")
            if (adapter, fmt, version) != ("navis", "normalized-json", "1"):
                raise ValueError("unsupported adapter")
            digest = hashlib.sha256(Path(normalized_adapter.__file__).read_bytes()).digest()
            cur.execute("SELECT 1 FROM navis.adapter_artifact WHERE product=%s AND version=%s AND artifact_name=%s AND digest_algorithm='sha256' AND digest=%s AND status='approved'", ("navis", "1", "normalized_adapter.py", digest))
            if cur.fetchone() is None:
                raise PermissionError("adapter artifact is not approved")
            cur.execute("SELECT DISTINCT device_id FROM navis.device_identity_mapping WHERE source_system_id=%s AND external_id=%s AND valid_from<=%s AND (valid_until IS NULL OR valid_until>%s)", (source, external, collected, collected))
            devices = [r[0] for r in cur.fetchall()]
            if len(devices) != 1 or (claimed is not None and claimed != devices[0]):
                raise ValueError("device identity requires confirmation")
            supported = kind in ("mac", "route", "policy", "interface", "neighbor", "nat", "security_zone")
            entries = normalized_adapter.normalize(kind, payload) if supported else []
            batch, snapshot, run = uuid4(), uuid4(), uuid4()
            cur.execute("INSERT INTO navis.import_batch(id,source_system_id,status) VALUES (%s,%s,'processed')", (batch, source))
            cur.execute("INSERT INTO navis.device_snapshot(id,device_id,import_batch_id,collected_at) VALUES (%s,%s,%s,%s)", (snapshot, devices[0], batch, collected))
            cur.execute("INSERT INTO navis.snapshot_coverage(id,snapshot_id,data_type,coverage) VALUES (%s,%s,%s,%s)", (uuid4(), snapshot, kind, completeness))
            cur.execute("INSERT INTO navis.raw_payload(id,snapshot_id,data_type,format,format_version,payload) VALUES (%s,%s,%s,%s,%s,%s)", (uuid4(), snapshot, kind, fmt, version, Jsonb(payload)))
            if supported:
                cur.execute("INSERT INTO navis.normalization_run(id,snapshot_id,adapter_name,adapter_version,started_at,status) VALUES (%s,%s,%s,%s,now(),'completed')", (run, snapshot, adapter, version))
            interfaces, contexts, points, rulesets = {}, {}, {}, {}
            if kind == "interface":
                for entry in entries:
                    native_id = entry.get("native_id") or entry["name"]
                    if native_id in interfaces:
                        raise ValueError("duplicate interface native ID")
                    interfaces[native_id] = uuid4()
                for entry in entries:
                    native_id = entry.get("native_id") or entry["name"]
                    vrf = entry.get("vrf")
                    if vrf and vrf not in contexts:
                        contexts[vrf] = uuid4()
                        cur.execute("INSERT INTO navis.routing_context(id,snapshot_id,normalization_run_id,native_id,name) VALUES (%s,%s,%s,%s,%s)", (contexts[vrf], snapshot, run, vrf, vrf))
                    cur.execute("INSERT INTO navis.interface(id,snapshot_id,normalization_run_id,native_id,name,kind,routing_context_id,operational_state,details) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)", (interfaces[native_id], snapshot, run, native_id, entry["name"], entry["kind"], contexts.get(vrf), entry.get("operational_state"), Jsonb({"config": entry.get("config", {}), "vlans": entry.get("vlans", [])})))
                for entry in entries:
                    native_id = entry.get("native_id") or entry["name"]
                    parent = entry.get("parent")
                    if parent:
                        if parent not in interfaces or parent == native_id:
                            raise ValueError("invalid parent interface")
                        cur.execute("UPDATE navis.interface SET parent_interface_id=%s WHERE id=%s", (interfaces[parent], interfaces[native_id]))
                    for address in entry["addresses"]:
                        cur.execute("INSERT INTO navis.interface_address(id,interface_id,address) VALUES (%s,%s,%s)", (uuid4(), interfaces[native_id], address))
            for entry in entries:
                if kind == "security_zone":
                    point = entry["enforcement_point"]
                    if point not in points:
                        points[point] = uuid4()
                        cur.execute("INSERT INTO navis.enforcement_point(id,snapshot_id,native_id,kind) VALUES (%s,%s,%s,'unknown')", (points[point], snapshot, point))
                    zone = uuid4()
                    cur.execute("INSERT INTO navis.security_zone(id,enforcement_point_id,native_id,name) VALUES (%s,%s,%s,%s)", (zone, points[point], entry["zone"], entry["zone"]))
                    for name in entry["interfaces"]:
                        if name not in interfaces:
                            interfaces[name] = uuid4()
                            cur.execute("INSERT INTO navis.interface(id,snapshot_id,normalization_run_id,native_id,name,kind) VALUES (%s,%s,%s,%s,%s,'unknown')", (interfaces[name], snapshot, run, name, name))
                        cur.execute("INSERT INTO navis.security_zone_member(security_zone_id,interface_id) VALUES (%s,%s)", (zone, interfaces[name]))
                    continue
                if kind == "interface":
                    continue
                if kind in ("mac", "route", "neighbor"):
                    name = entry["interface"]
                    if name is not None and name not in interfaces:
                        interfaces[name] = uuid4()
                        cur.execute("INSERT INTO navis.interface(id,snapshot_id,normalization_run_id,native_id,name,kind) VALUES (%s,%s,%s,%s,%s,'unknown')", (interfaces[name], snapshot, run, name, name))
                if kind == "mac":
                    cur.execute("INSERT INTO navis.mac_entry(id,snapshot_id,interface_id,mac_address,vlan_id,observed_at) VALUES (%s,%s,%s,%s,%s,%s)", (uuid4(), snapshot, interfaces[name], entry["mac"], entry["vlan"], collected))
                elif kind in ("route", "neighbor"):
                    vrf = entry["vrf"]
                    if vrf not in contexts:
                        contexts[vrf] = uuid4()
                        cur.execute("INSERT INTO navis.routing_context(id,snapshot_id,normalization_run_id,native_id,name) VALUES (%s,%s,%s,%s,%s)", (contexts[vrf], snapshot, run, vrf, vrf))
                    if kind == "route":
                        route = uuid4()
                        cur.execute("INSERT INTO navis.route(id,snapshot_id,normalization_run_id,routing_context_id,destination,route_type,details) VALUES (%s,%s,%s,%s,%s,%s,%s)", (route, snapshot, run, contexts[vrf], entry["destination"], entry.get("route_type", "forward"), Jsonb(entry.get("details", {}))))
                        if entry["next_hop"] is not None or name is not None:
                            cur.execute("INSERT INTO navis.route_next_hop(id,snapshot_id,route_id,next_hop_address,interface_id) VALUES (%s,%s,%s,%s,%s)", (uuid4(), snapshot, route, entry["next_hop"], interfaces.get(name)))
                    else:
                        cur.execute("INSERT INTO navis.neighbor_entry(id,snapshot_id,routing_context_id,interface_id,ip_address,mac_address,state,observed_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)", (uuid4(), snapshot, contexts[vrf], interfaces[name], entry["ip"], entry["mac"], entry["state"], collected))
                else:
                    point, rule_set = entry["enforcement_point"], entry["rule_set"]
                    if point not in points:
                        points[point] = uuid4()
                        cur.execute("INSERT INTO navis.enforcement_point(id,snapshot_id,native_id,kind) VALUES (%s,%s,%s,'unknown')", (points[point], snapshot, point))
                    key = (point, rule_set)
                    if kind == "nat":
                        if key not in rulesets:
                            rulesets[key] = (uuid4(), entry["processing_stage"])
                            cur.execute("INSERT INTO navis.nat_rule_set(id,enforcement_point_id,native_id,processing_stage,evaluation_order) VALUES (%s,%s,%s,%s,'first_match')", (rulesets[key][0], points[point], rule_set, entry["processing_stage"]))
                        if rulesets[key][1] != entry["processing_stage"]:
                            raise ValueError("conflicting NAT processing stages")
                        nat_id = uuid4()
                        cur.execute("INSERT INTO navis.nat_rule(id,nat_rule_set_id,native_rule_id,position,enabled,details) VALUES (%s,%s,%s,%s,%s,%s)", (nat_id, rulesets[key][0], entry["rule_id"], entry["position"], entry["enabled"], Jsonb({**entry.get("details", {}), "selectors_complete": False})))
                        cur.execute("INSERT INTO navis.nat_translation(id,nat_rule_id,kind,specification) VALUES (%s,%s,%s,%s)", (uuid4(), nat_id, entry["translation_kind"], Jsonb(entry["translation"])))
                        _write_selectors(cur, snapshot, points[point], nat_id, entry["selectors"], False)
                        continue
                    statefulness = entry.get("details", {}).get("statefulness", "unknown")
                    if statefulness not in ("stateless", "stateful", "unknown"):
                        raise ValueError("invalid policy statefulness")
                    if key not in rulesets:
                        rulesets[key] = (uuid4(), entry["default_action"], statefulness)
                        cur.execute("INSERT INTO navis.policy_rule_set(id,enforcement_point_id,native_id,evaluation_order,default_action,statefulness) VALUES (%s,%s,%s,'first_match',%s,%s)", (rulesets[key][0], points[point], rule_set, entry["default_action"], statefulness))
                    if rulesets[key][1] != entry["default_action"]:
                        raise ValueError("conflicting rule set defaults")
                    if rulesets[key][2] != statefulness:
                        raise ValueError("conflicting rule set statefulness")
                    policy_id = uuid4()
                    details = {**entry.get("details", {}), "selectors_complete": False}
                    cur.execute("INSERT INTO navis.policy_rule(id,rule_set_id,native_rule_id,position,action,enabled,details) VALUES (%s,%s,%s,%s,%s,%s,%s)", (policy_id, rulesets[key][0], entry["rule_id"], entry["position"], entry["action"], entry["enabled"], Jsonb(details)))
                    _write_selectors(cur, snapshot, points[point], policy_id, entry["selectors"], True)
            cur.execute("UPDATE navis.ingestion_submission SET status=%s, snapshot_id=%s WHERE id=%s", ("processed" if supported else "raw_only", snapshot, submission_id))
    return snapshot
