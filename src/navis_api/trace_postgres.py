"""Destination-first database trace foundation; does not infer reachability."""
from ipaddress import ip_address
from .graph_trace import next_hops, peer_interfaces
from navis_common.policy_selectors import evaluate_policy
from navis_common.nat import Packet, evaluate_nat, reverse_session_packet
from dataclasses import asdict
from navis_common.zones import rule_recommendation, resolve_zone
from navis_common.verdict import derive_verdict, connection_verdict
from .build_evidence import evidence_manifest
from navis_common.coverage import policy_coverage, applicability_coverage, forwarding_coverage, overall_coverage
from navis_common.policy_normalization import normalize_enforcement
from navis_common.routing import select_routes, resolve_recursive, resolve_recursive_alternatives
from navis_common.path_search import ForwardingState, explore_paths, alternative_verdict
from navis_common.connection_state import evaluate_return
from navis_common.findings import trace_findings
from navis_common.reverse_path import ReverseTransition, apply_reverse_mapping, trace_reverse_path, assess_reverse_paths
from navis_common.aci_trace_evidence import candidate_evidence
from navis_common.policy_pipeline import ORIGINAL_ADDRESS_STAGE
from navis_common.load_balancer import candidate_evidence as load_balancer_evidence


class PostgresTraceProcessor:
    def __init__(self, connection_factory):
        self.connection_factory = connection_factory

    def trace(self, request, flows, principal, *, include_reverse=True):
        if not principal.issuer:
            raise PermissionError("issuer required")
        with self.connection_factory() as conn:
            with conn.cursor() as cur:
                cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                cur.execute("SELECT c.id FROM navis.api_consumer c WHERE c.issuer=%s AND c.subject_or_client_id=%s AND c.status='active'", (principal.issuer, principal.subject))
                consumer = cur.fetchone()
                if consumer is None:
                    raise PermissionError("unknown consumer")
                cur.execute("SELECT dataset_id,status,graph_name,evidence_manifest FROM navis.graph_build WHERE id=%s", (request.graph_build_id,))
                build = cur.fetchone()
                if build is None or build[1] != "completed":
                    raise ValueError("completed graph build required")
                dataset = build[0]
                graph = build[2]
                manifest = build[3]
                cur.execute("LOAD 'age'")
                cur.execute("SET LOCAL search_path = ag_catalog, navis, public")
                cur.execute("""SELECT 1 FROM navis.graph_build_snapshot bs
                    JOIN navis.device_snapshot s ON s.id=bs.snapshot_id
                    JOIN navis.import_batch b ON b.id=s.import_batch_id
                    WHERE bs.graph_build_id=%s AND NOT EXISTS
                    (SELECT 1 FROM navis.consumer_data_scope ds WHERE ds.api_consumer_id=%s
                    AND ds.source_system_id=b.source_system_id AND ds.permissions @> '["analysis:run"]'::jsonb) LIMIT 1""", (request.graph_build_id, consumer[0]))
                if cur.fetchone():
                    raise PermissionError("dataset outside scope")
                evidence_unchanged = manifest is not None and manifest == evidence_manifest(cur, dataset)
                # Restrict vendor evidence to snapshots in this authorized build.
                cur.execute("""SELECT r.snapshot_id::text, r.payload FROM navis.raw_payload r
                    JOIN navis.graph_build_snapshot bs ON bs.snapshot_id=r.snapshot_id
                    WHERE bs.graph_build_id=%s AND r.data_type='topology'
                    AND r.payload->>'kind' IN ('aci_fabric_evidence','avi_load_balancer_evidence','f5_load_balancer_evidence')""", (request.graph_build_id,))
                vendor_payloads = cur.fetchall()
                results = []
                for flow in flows:
                    destination = self._endpoints(cur, dataset, request.graph_build_id, flow.destination)
                    source = self._endpoints(cur, dataset, request.graph_build_id, flow.source)
                    routes = []
                    if len(source) == 1 and source[0]["vrf"] is not None:
                        routes = self._routes(cur, dataset, request.graph_build_id, source[0], flow.destination)
                    hops = []
                    current = source[0]["device_id"] if len(source) == 1 else None
                    target = destination[0]["device_id"] if len(destination) == 1 else None
                    visited = set()
                    packet = Packet(flow.source, flow.destination, flow.protocol, flow.destination_port, getattr(request, "source_port", None))
                    ingress = None
                    vrf = source[0]["vrf"] if current else None
                    while current and target and current not in visited and len(hops) < 64:
                        visited.add(current)
                        cur.execute("SELECT display_name,platform FROM navis.device WHERE id=%s", (current,))
                        device = cur.fetchone()
                        hop = {"number": len(hops) + 1, "device_id": current, "name": device[0], "platform": device[1]}
                        cur.execute("""SELECT ep.native_id, pr.native_rule_id, pr.action, pr.details
                            FROM navis.graph_build_snapshot bs JOIN navis.enforcement_point ep ON ep.snapshot_id=bs.snapshot_id
                            JOIN navis.policy_rule_set rs ON rs.enforcement_point_id=ep.id
                            JOIN navis.policy_rule pr ON pr.rule_set_id=rs.id
                            JOIN navis.device_snapshot s ON s.id=bs.snapshot_id
                            WHERE bs.graph_build_id=%s AND s.device_id=%s AND pr.enabled ORDER BY pr.position""", (request.graph_build_id, current))
                        hop["policy_evidence"] = [{"enforcement_point": ep, "rule_id": rule, "action": action, "details": details} for ep, rule, action, details in cur.fetchall()]
                        policy_packet = packet
                        hop["policy_evaluations"] = self._policies(cur, request.graph_build_id, current, policy_packet, application=flow.application)
                        hop["packet_before"] = asdict(packet)
                        packet, nat_evidence = self._nat(cur, request.graph_build_id, current, packet,
                                                        dataset=dataset, vrf=vrf, ingress=ingress)
                        hop["nat_evidence"] = nat_evidence
                        hop["packet_after"] = asdict(packet)
                        hops.append(hop)
                        if any(item["status"] == "unknown" for item in nat_evidence):
                            break
                        if packet.destination != policy_packet.destination:
                            translated = self._endpoints(cur, dataset, request.graph_build_id, packet.destination)
                            hop["translated_destination_candidates"] = translated
                            target = translated[0]["device_id"] if len(translated) == 1 else None
                            if target is None:
                                hop["stop_reason"] = "translated destination is missing or ambiguous"
                                break
                        if current == target:
                            break
                        candidates = self._routes(cur, dataset, request.graph_build_id, {"device_id": current, "vrf": vrf}, packet.destination) if vrf else []
                        cur.execute("""SELECT c.coverage, c.details FROM navis.graph_dataset_snapshot ds
                            JOIN navis.graph_build_snapshot bs ON bs.snapshot_id=ds.snapshot_id AND bs.graph_build_id=%s
                            JOIN navis.snapshot_coverage c ON c.snapshot_id=ds.snapshot_id AND c.data_type='route'
                            WHERE ds.dataset_id=%s AND ds.device_id=%s AND ds.data_type='route'""", (request.graph_build_id, dataset, current))
                        route_coverage = cur.fetchall()
                        coverage_complete = len(route_coverage) == 1 and route_coverage[0][0] == "complete"
                        table_kind = (route_coverage[0][1] or {}).get("table_kind") if len(route_coverage) == 1 else None
                        hop["route_assessment"] = select_routes(packet.destination, candidates, complete=coverage_complete, table_kind=table_kind)
                        if not candidates:
                            hop["stop_reason"] = "No matching route data was found for this device and routing context"
                            break
                        from ipaddress import ip_network
                        best = ip_network(candidates[0]["prefix"]).prefixlen
                        selected = [r for r in candidates if ip_network(r["prefix"]).prefixlen == best]
                        if len(selected) != 1:
                            hop["stop_reason"] = "Multiple equally specific route candidates require resolution"
                            break
                        hop["route"] = selected[0]
                        graph_route_id = selected[0]["route_id"]
                        if not selected[0]["interface"] and selected[0]["next_hop"]:
                            def recursive_lookup(address):
                                recursive_routes = self._routes(cur, dataset, request.graph_build_id, {"device_id": current, "vrf": vrf}, address)
                                return recursive_routes, coverage_complete, table_kind
                            resolution = resolve_recursive(selected[0]["next_hop"], recursive_lookup)
                            hop["recursive_resolution"] = resolution
                            if resolution["status"] != "resolved":
                                hop["stop_reason"] = "recursive next hop unresolved"
                                break
                            graph_route_id = resolution["chain"][-1]["route_id"]
                            hop["resolved_egress_interface"] = resolution["interface"]
                        if selected[0]["route_type"] not in ("forward", "connected"):
                            hop["stop_reason"] = "route behavior requires explicit evaluation"
                            break
                        hop["ingress_interface"] = ingress
                        egress = hop.get("resolved_egress_interface", selected[0]["interface"])
                        hop["egress_interface"] = egress
                        hop["policy_evaluations"] = self._policies(cur, request.graph_build_id, current, policy_packet, ingress, egress, application=flow.application)
                        for evaluation in hop["policy_evaluations"]:
                            if evaluation["decision"] == "deny":
                                memberships = self._zone_memberships(cur, request.graph_build_id, current, evaluation["enforcement_point"])
                                hop.setdefault("recommendations", []).append(rule_recommendation(
                                    device_id=current, source=policy_packet.source, destination=policy_packet.destination,
                                    protocol=policy_packet.protocol, destination_port=policy_packet.destination_port,
                                    ingress=ingress, egress=egress, memberships=memberships,
                                    reason=evaluation["reason"]))
                        if any(evaluation["decision"] == "deny" for evaluation in hop["policy_evaluations"]):
                            hop["stop_reason"] = "policy denied traffic"
                            break
                        next_devices = next_hops(cur, graph, graph_route_id)
                        if len(next_devices) != 1:
                            hop["stop_reason"] = "Next device connection is missing or ambiguous"
                            break
                        peers = peer_interfaces(cur, graph, graph_route_id, next_devices[0])
                        ingress = None
                        if len(peers) == 1:
                            cur.execute("SELECT i.native_id,rc.native_id FROM navis.interface i LEFT JOIN navis.routing_context rc ON rc.id=i.routing_context_id WHERE i.id=%s", (peers[0],))
                            peer = cur.fetchone()
                            ingress = peer[0] if peer else None
                            vrf = peer[1] if peer else None
                        current = next_devices[0]
                    if current in visited and current != target and hops and hops[-1]["device_id"] != current:
                        reasons_loop = "Routing loop detected"
                    else:
                        reasons_loop = None
                    reasons = ["Path traversal, NAT and policy evaluation are not implemented"]
                    reasons[0] = "Candidate traversal only; route selection, NAT and policy evaluation are incomplete"
                    if reasons_loop:
                        reasons.append(reasons_loop)
                    if not destination:
                        reasons.append("Destination interface not found; NAT and incomplete inventory may affect resolution")
                    if len(destination) > 1:
                        reasons.append("Destination matches multiple interfaces")
                    if len(source) != 1:
                        reasons.append("Source resolution is missing or ambiguous")
                    elif source[0]["vrf"] is None:
                        reasons.append("Source routing context is unknown")
                    # Coverage records are necessary but not sufficient: current
                    # snapshots and selected dataset rows remain mutable, and
                    # route eligibility and policy stage ordering are incomplete.
                    coverage = self._coverage(cur, request.graph_build_id, hops)
                    reached = bool(hops and target and hops[-1]["device_id"] == target and not hops[-1].get("stop_reason"))
                    coverage_by_device = {item["device_id"]: item["data_types"] for item in coverage["devices"]}
                    for hop in hops:
                        hop["policy_coverage"] = coverage_by_device.get(hop["device_id"], {}).get("policy", "unknown")
                        cur.execute("""SELECT a.state,a.mechanism,a.direction,i.native_id FROM navis.policy_applicability a
                            JOIN navis.graph_build_snapshot bs ON bs.snapshot_id=a.snapshot_id
                            JOIN navis.device_snapshot s ON s.id=a.snapshot_id
                            LEFT JOIN navis.interface i ON i.id=a.interface_id
                            WHERE bs.graph_build_id=%s AND s.device_id=%s""", (request.graph_build_id, hop["device_id"]))
                        applicability = cur.fetchall()
                        hop["policy_applicability"] = [{"state": state, "mechanism": mechanism, "direction": direction, "interface": interface} for state, mechanism, direction, interface in applicability]
                        hop["policy_direction_applicability"] = applicability_coverage(hop["policy_applicability"], hop.get("ingress_interface"), hop.get("egress_interface"))
                        # Only explicit device-wide no-policy evidence can establish
                        # that an empty policy evaluation is inapplicable.
                        hop["policy_not_applicable"] = bool(applicability) and all(state == "not_applicable" and direction == "device" and interface is None for state, _, direction, interface in applicability)
                        if hop["policy_not_applicable"] and not hop["policy_evaluations"]:
                            normalized = normalize_enforcement(state="not_applicable", complete=hop["policy_coverage"] == "complete")
                            hop["policy_evaluations"].append({"enforcement_point": None, "decision": normalized["default_action"],
                                "rule_id": None, "reason": normalized["reason"]})
                    coverage["policy"] = policy_coverage(hops, destination_reached=reached)
                    coverage["destination_reached"] = reached
                    coverage["relational_evidence_unchanged"] = evidence_unchanged
                    coverage["forwarding"] = forwarding_coverage(hops, coverage["devices"], destination_reached=reached, evidence_unchanged=evidence_unchanged)
                    coverage["forwarding_semantics_verified"] = coverage["forwarding"]["complete"]
                    # Final coverage is assembled after reverse analysis.
                    coverage["complete"] = False
                    return_evidence = []
                    for hop in hops:
                        for evaluation in hop.get("policy_evaluations", []):
                            if evaluation.get("enforcement_point") is None:
                                continue
                            assessment = evaluate_return(mode=evaluation.get("statefulness", "unknown"),
                                forward_decision=evaluation["decision"], session_supported=evaluation.get("session_supported"))
                            return_evidence.append({"device_id": hop["device_id"], "enforcement_point": evaluation["enforcement_point"], **assessment})
                    coverage["return_policy"] = return_evidence
                    coverage["return_path_verified"] = False
                    verdict = derive_verdict(hops, destination_reached=reached, evidence_complete=coverage["complete"])
                    alternative_paths = None
                    if len(source) == 1 and len(destination) == 1 and source[0]["vrf"]:
                        alternative_paths = self._candidate_paths(cur, dataset, request.graph_build_id, graph, source[0], destination[0], flow)
                    results.append({"source": flow.source, "destination": flow.destination,
                        "protocol": flow.protocol, "destination_port": flow.destination_port,
                        "status": verdict["status"], "verdict": verdict, "destination_candidates": destination,
                        "source_candidates": source, "route_candidates": routes, "hops": hops, "alternative_paths": alternative_paths, "coverage": coverage, "findings": trace_findings(hops, source, destination), "reasons": reasons,
                        "aci_policy_evidence": candidate_evidence(vendor_payloads, flow.source, flow.destination, flow.protocol, flow.destination_port),
                        "load_balancer_evidence": load_balancer_evidence(vendor_payloads, flow.source, flow.destination, flow.protocol, flow.destination_port)})
                response = {"graph_build_id": str(request.graph_build_id), "results": results}
        if include_reverse:
            from types import SimpleNamespace
            from navis_common.trace import Flow
            source_port = getattr(request, "source_port", None)
            for flow, result in zip(flows, response["results"]):
                if result["status"] == "blocked":
                    result["reverse_trace"] = {"status": "not_evaluated", "reason": "forward candidate path was blocked"}
                    continue
                translated_hops = [hop for hop in result["hops"] if any(item.get("status") == "translated" for item in hop.get("nat_evidence", []))]
                if translated_hops:
                    mappings = []
                    transitions = []
                    for hop in reversed(translated_hops):
                        translated_reply, original_reply = reverse_session_packet(Packet(**hop["packet_before"]), Packet(**hop["packet_after"]))
                        # Session evidence is read from the selected build's snapshots;
                        # exact tuple and rule identity must agree with the modeled flow.
                        from psycopg.types.json import Jsonb
                        confirmed = False
                        session_rule_set = None
                        with self.connection_factory() as session_conn:
                            with session_conn.cursor() as session_cur:
                                for nat_item in hop.get("nat_evidence", []):
                                    if nat_item.get("status") != "translated" or not nat_item.get("rule_id"):
                                        continue
                                    session_cur.execute("""SELECT pr.native_rule_id, prs.id FROM navis.nat_session_evidence e
                                        JOIN navis.nat_rule r ON r.id=e.nat_rule_id
                                        JOIN navis.nat_rule_set rs ON rs.id=r.nat_rule_set_id
                                        JOIN navis.enforcement_point ep ON ep.id=rs.enforcement_point_id
                                        JOIN navis.device_snapshot s ON s.id=ep.snapshot_id
                                        JOIN navis.graph_build_snapshot bs ON bs.snapshot_id=s.id
                                        LEFT JOIN navis.policy_rule pr ON pr.id=e.policy_rule_id
                                        LEFT JOIN navis.policy_rule_set prs ON prs.id=pr.rule_set_id AND prs.enforcement_point_id=ep.id
                                        WHERE bs.graph_build_id=%s AND s.device_id=%s AND e.snapshot_id=s.id
                                          AND r.native_rule_id=%s AND e.original_packet=%s AND e.translated_packet=%s
                                          AND e.observed_at<=now() AND e.expires_at>now() LIMIT 1""",
                                        (request.graph_build_id, hop["device_id"], nat_item["rule_id"], Jsonb(hop["packet_before"]), Jsonb(hop["packet_after"])))
                                    row = session_cur.fetchone()
                                    if row:
                                        confirmed = True
                                        if row[0] and row[1] and any(evaluation.get("rule_id") == row[0] and evaluation.get("rule_set_id") == str(row[1]) and evaluation.get("decision") == "allow" for evaluation in hop.get("policy_evaluations", [])):
                                            session_rule_set = str(row[1])
                        transition = ReverseTransition(hop["device_id"], translated_reply, original_reply, confirmed, session_rule_set)
                        transitions.append(transition)
                        _, assessment = apply_reverse_mapping(hop["device_id"], translated_reply, [transition])
                        mappings.append({"device_id": hop["device_id"], "before_reverse_nat": asdict(translated_reply), "after_reverse_nat": asdict(original_reply), "session_state": "observed" if confirmed else "unknown", "assessment": assessment})
                    result["reverse_trace"] = {"status": "unknown", "reason": "reverse routing through NAT mappings is not yet verified", "nat_session_mappings": mappings}
                    if transitions and all(item.session_confirmed for item in transitions):
                        reply = transitions[0].before
                        with self.connection_factory() as reverse_conn:
                            with reverse_conn.cursor() as reverse_cur:
                                reverse_cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                                reverse_cur.execute("LOAD 'age'")
                                reverse_cur.execute("SET LOCAL search_path = ag_catalog, navis, public")
                                reverse_source = self._endpoints(reverse_cur, dataset, request.graph_build_id, reply.source)
                                reverse_destination = self._endpoints(reverse_cur, dataset, request.graph_build_id, flow.source)
                                if len(reverse_source) == 1 and len(reverse_destination) == 1 and reverse_source[0]["vrf"]:
                                    reverse_flow = Flow(reply.source, reply.destination, reply.protocol, reply.destination_port)
                                    search = self._candidate_paths(reverse_cur, dataset, request.graph_build_id, graph,
                                        reverse_source[0], reverse_destination[0], reverse_flow,
                                        reverse_transitions=transitions, source_port=reply.source_port)
                                    result["reverse_trace"]["paths"] = search
                                    result["reverse_trace"]["reason"] = "reverse search evaluated; overall connection remains unverified"
                    continue
                policy_modes = {evaluation.get("statefulness", "unknown") for hop in result["hops"]
                                for evaluation in hop.get("policy_evaluations", [])
                                if evaluation.get("enforcement_point") is not None}
                if "stateless" not in policy_modes:
                    result["reverse_trace"] = {"status": "unknown", "reason": "return route not verified; no stateless reverse policy trace requested"}
                    continue
                if flow.protocol in ("tcp", "udp") and source_port is None:
                    result["reverse_trace"] = {"status": "unknown", "reason": "source port required for reverse policy evaluation"}
                    continue
                reverse = Flow(flow.destination, flow.source, flow.protocol, source_port)
                reverse_request = SimpleNamespace(graph_build_id=request.graph_build_id)
                result["reverse_trace"] = self.trace(reverse_request, [reverse], principal, include_reverse=False)["results"][0]
                result["reverse_trace"]["purpose"] = "stateless reverse policy candidate trace"
        for result in response["results"]:
            # Do not upgrade candidate-path evidence to end-to-end proof.
            evaluations = [item["decision"] for hop in result["hops"] for item in hop.get("policy_evaluations", [])]
            policy = "blocked" if "deny" in evaluations else ("allow" if result["coverage"]["policy"]["complete"] and evaluations and all(item == "allow" for item in evaluations) else "unknown")
            alternatives = result.get("alternative_paths") or {}
            # A candidate is not an established route; only a complete search
            # with explicit all-path denial can establish blocking.
            alternatives_complete = bool(alternatives.get("complete")) and result["coverage"].get("relational_evidence_unchanged", False)
            all_blocked = alternatives_complete and alternatives.get("verdict", {}).get("status") == "blocked"
            nat_items = [item for hop in result["hops"] for item in hop.get("nat_evidence", [])]
            nat_covered = bool(result["coverage"]["devices"]) and all(item["data_types"].get("nat") == "complete" for item in result["coverage"]["devices"])
            nat = "allow" if nat_covered and all(item.get("status") in ("translated", "unchanged") for item in nat_items) else "unknown"
            forwarding = "allow" if result["coverage"]["forwarding"]["complete"] else "unknown"
            reverse = result.get("reverse_trace", {})
            reverse_coverage = reverse.get("coverage", {})
            reverse_evaluations = [item for hop in reverse.get("hops", []) for item in hop.get("policy_evaluations", [])]
            return_path = "allow" if (reverse_coverage.get("forwarding", {}).get("complete") and
                reverse_coverage.get("policy", {}).get("complete") and reverse_evaluations and
                all(item.get("decision") == "allow" for item in reverse_evaluations) and
                all(item["data_types"].get("nat") == "complete" for item in reverse_coverage.get("devices", []))) else "unknown"
            combined_coverage = overall_coverage(forwarding=forwarding == "allow", policy=policy == "allow",
                nat=nat == "allow", return_path=return_path == "allow", alternatives=alternatives_complete,
                evidence_unchanged=result["coverage"].get("relational_evidence_unchanged", False))
            result["coverage"]["complete"] = combined_coverage["complete"]
            result["coverage"]["missing"] = combined_coverage["missing"]
            result["connection_verdict"] = connection_verdict(forwarding=forwarding, nat=nat, policy=policy,
                                                               return_path=return_path, alternatives_complete=alternatives_complete,
                                                               all_paths_blocked=all_blocked)
        return response

    @staticmethod
    def _candidate_paths(cur, dataset, build_id, graph, source, destination, flow, *, reverse_transitions=None, source_port=None):
        from dataclasses import asdict
        start = ForwardingState(source["device_id"], source["vrf"], flow.destination, flow.source, flow.protocol, flow.destination_port, source_port)

        def lookup(state):
            routes = PostgresTraceProcessor._routes(cur, dataset, build_id, {"device_id": state.device_id, "vrf": state.routing_context}, state.destination)
            cur.execute("""SELECT c.coverage,c.details FROM navis.graph_dataset_snapshot ds
                JOIN navis.graph_build_snapshot bs ON bs.snapshot_id=ds.snapshot_id AND bs.graph_build_id=%s
                JOIN navis.snapshot_coverage c ON c.snapshot_id=ds.snapshot_id AND c.data_type='route'
                WHERE ds.dataset_id=%s AND ds.device_id=%s AND ds.data_type='route'""", (build_id, dataset, state.device_id))
            coverage = cur.fetchall()
            complete = len(coverage) == 1 and coverage[0][0] == "complete"
            table_kind = (coverage[0][1] or {}).get("table_kind") if len(coverage) == 1 else None
            for route in routes:
                route["next_states"] = []
                if route["route_type"] not in ("forward", "connected"):
                    continue
                edge_routes = [route]
                if not route["interface"] and route["next_hop"]:
                    def recursive_lookup(address):
                        return (PostgresTraceProcessor._routes(cur, dataset, build_id, {"device_id": state.device_id, "vrf": state.routing_context}, address), complete, table_kind)
                    resolved = resolve_recursive_alternatives(route["next_hop"], recursive_lookup)
                    if not resolved["complete"] or any(item["status"] != "resolved" for item in resolved["paths"]):
                        route["recursive_status"] = "unknown"
                        continue
                    edge_routes = [item["chain"][-1] for item in resolved["paths"]]
                unresolved_edge = False
                for edge in edge_routes:
                  edge_count = len(route["next_states"])
                  for device in next_hops(cur, graph, edge["route_id"]):
                    peers = peer_interfaces(cur, graph, edge["route_id"], device)
                    if len(peers) != 1:
                        continue
                    cur.execute("SELECT rc.native_id FROM navis.interface i LEFT JOIN navis.routing_context rc ON rc.id=i.routing_context_id WHERE i.id=%s", (peers[0],))
                    row = cur.fetchone()
                    if row and row[0]:
                        cur.execute("SELECT native_id FROM navis.interface WHERE id=%s", (peers[0],))
                        interface_row = cur.fetchone()
                        route["next_states"].append(ForwardingState(device, row[0], state.destination, state.source, state.protocol, state.destination_port, state.source_port, interface_row[0] if interface_row else None))
                  if len(route["next_states"]) == edge_count:
                      unresolved_edge = True
                if unresolved_edge:
                    route["next_states"] = []
            return routes, complete, table_kind

        def policy(state):
            packet = Packet(state.source, state.destination, state.protocol, state.destination_port, state.source_port)
            preview, nat_evidence = PostgresTraceProcessor._nat(cur, build_id, state.device_id, packet,
                dataset=dataset, vrf=state.routing_context, ingress=state.ingress_interface)
            original_stage = any(n.get("processing_stage") == ORIGINAL_ADDRESS_STAGE for n in nat_evidence)
            route_state = state
            if original_stage:
                if any(n.get("status") == "unknown" for n in nat_evidence):
                    return {"decision": "unknown", "reason": "pre-policy NAT/zone context unresolved", "nat": nat_evidence}
                from dataclasses import replace
                route_state = replace(state, destination=preview.destination)
            routes, complete, table_kind = lookup(route_state)
            selection = select_routes(route_state.destination, routes, complete=complete, table_kind=table_kind)
            selected = selection.get("routes", [])
            interfaces = {route["interface"] for route in selected}
            egress = next(iter(interfaces)) if len(interfaces) == 1 else None
            decisions = PostgresTraceProcessor._policies(cur, build_id, state.device_id, packet, state.ingress_interface, egress, application=flow.application)
            if reverse_transitions is not None and any(item.get("statefulness") != "stateless" for item in decisions):
                associated = {entry.policy_rule_set_id for entry in reverse_transitions if entry.device_id == state.device_id and entry.session_confirmed and entry.policy_rule_set_id}
                for item in decisions:
                    if item.get("statefulness") == "stateful":
                        if item.get("rule_set_id") not in associated or item.get("session_supported") is not True:
                            return {"decision": "unknown", "reason": "stateful return-policy session association is not established", "evaluations": decisions}
                        item["decision"] = "allow"
                        item["reason"] = "observed session associated with forward allow rule"
                    elif item.get("statefulness") != "stateless":
                        return {"decision": "unknown", "reason": "policy statefulness is unknown", "evaluations": decisions}
            if not decisions:
                cur.execute("""SELECT a.state,a.direction,i.native_id FROM navis.policy_applicability a
                    JOIN navis.graph_build_snapshot bs ON bs.snapshot_id=a.snapshot_id
                    JOIN navis.device_snapshot s ON s.id=a.snapshot_id
                    LEFT JOIN navis.interface i ON i.id=a.interface_id
                    WHERE bs.graph_build_id=%s AND s.device_id=%s""", (build_id, state.device_id))
                entries = [{"state": a, "direction": b, "interface": c} for a, b, c in cur.fetchall()]
                applicability = applicability_coverage(entries, state.ingress_interface, egress)
                cur.execute("""SELECT c.coverage FROM navis.snapshot_coverage c
                    JOIN navis.graph_build_snapshot bs ON bs.snapshot_id=c.snapshot_id
                    JOIN navis.device_snapshot s ON s.id=c.snapshot_id
                    WHERE bs.graph_build_id=%s AND s.device_id=%s AND c.data_type='policy'""", (build_id, state.device_id))
                policy_collection = [row[0] for row in cur.fetchall()]
                if policy_collection == ["complete"] and entries and all(value == "not_applicable" for value in applicability.values()):
                    return {"decision": "allow", "reason": "explicitly no applicable policy"}
                return {"decision": "unknown", "reason": "policy applicability not established"}
            if any(item["decision"] == "deny" for item in decisions):
                return {"decision": "deny", "evaluations": decisions}
            if all(item["decision"] == "allow" for item in decisions):
                return {"decision": "allow", "evaluations": decisions}
            return {"decision": "unknown", "evaluations": decisions}

        def nat(state):
            packet = Packet(state.source, state.destination, state.protocol, state.destination_port, state.source_port)
            translated, evidence = PostgresTraceProcessor._nat(cur, build_id, state.device_id, packet,
                dataset=dataset, vrf=state.routing_context, ingress=state.ingress_interface)
            if not evidence:
                cur.execute("""SELECT c.coverage FROM navis.snapshot_coverage c
                    JOIN navis.graph_build_snapshot bs ON bs.snapshot_id=c.snapshot_id
                    JOIN navis.device_snapshot s ON s.id=c.snapshot_id
                    WHERE bs.graph_build_id=%s AND s.device_id=%s AND c.data_type='nat'""", (build_id, state.device_id))
                coverage = [row[0] for row in cur.fetchall()]
                if coverage == ["complete"]:
                    return state, {"status": "unchanged", "reason": "complete NAT collection has no rules"}
                return state, {"status": "unknown", "reason": "NAT applicability not established"}
            if any(item["status"] == "unknown" for item in evidence):
                return state, {"status": "unknown", "evidence": evidence}
            updated = ForwardingState(state.device_id, state.routing_context, translated.destination,
                                      translated.source, translated.protocol, translated.destination_port, translated.source_port, state.ingress_interface)
            return updated, {"status": "translated" if updated != state else "unchanged", "evidence": evidence}

        # Mixed per-hop processing order is not representable in this shared
        # search yet. Only the explicitly implemented after-policy stage is used.
        def is_destination(state):
            endpoints = PostgresTraceProcessor._endpoints(cur, dataset, build_id, state.destination)
            return len(endpoints) == 1 and endpoints[0]["device_id"] == state.device_id

        if reverse_transitions is not None:
            def no_nat(state):
                cur.execute("""SELECT c.coverage FROM navis.snapshot_coverage c
                    JOIN navis.graph_build_snapshot bs ON bs.snapshot_id=c.snapshot_id
                    JOIN navis.device_snapshot s ON s.id=c.snapshot_id
                    WHERE bs.graph_build_id=%s AND s.device_id=%s AND c.data_type='nat'""", (build_id, state.device_id))
                coverage = [row[0] for row in cur.fetchall()]
                cur.execute("""SELECT 1 FROM navis.nat_rule_set ns
                    JOIN navis.enforcement_point ep ON ep.id=ns.enforcement_point_id
                    JOIN navis.device_snapshot s ON s.id=ep.snapshot_id
                    JOIN navis.graph_build_snapshot bs ON bs.snapshot_id=s.id
                    WHERE bs.graph_build_id=%s AND s.device_id=%s LIMIT 1""", (build_id, state.device_id))
                return coverage == ["complete"] and cur.fetchone() is None
            result = trace_reverse_path(start, is_destination, lookup, policy, reverse_transitions, nat_absence_confirmed=no_nat)
            result["reverse_assessment"] = assess_reverse_paths(result)
        else:
            result = explore_paths(start, is_destination, lookup,
                                   evaluate_policy=policy, evaluate_nat=nat, processing_order="policy_then_nat")
        result["verdict"] = alternative_verdict(result)
        for path in result["paths"]:
            path["hops"] = [asdict(state) for state in path["hops"]]
        return result

    @staticmethod
    def _coverage(cur, build_id, hops):
        """Report explicit per-hop collection coverage without inventing it."""
        devices = []
        for hop in hops:
            cur.execute("""SELECT c.data_type,c.coverage FROM navis.graph_build_snapshot bs
                JOIN navis.device_snapshot s ON s.id=bs.snapshot_id
                JOIN navis.snapshot_coverage c ON c.snapshot_id=s.id
                WHERE bs.graph_build_id=%s AND s.device_id=%s""", (build_id, hop["device_id"]))
            by_type = {}
            for data_type, value in cur.fetchall():
                by_type.setdefault(data_type, set()).add(value)
            # Multiple conflicting coverage statements are not complete.
            states = {kind: next(iter(values)) if len(values) == 1 else "conflicting" for kind, values in by_type.items()}
            devices.append({"device_id": hop["device_id"], "data_types": states})
        return {"devices": devices}

    @staticmethod
    def _zone_memberships(cur, build_id, device_id, enforcement):
        cur.execute("""SELECT i.native_id,z.name FROM navis.graph_build_snapshot bs
            JOIN navis.device_snapshot s ON s.id=bs.snapshot_id
            JOIN navis.enforcement_point ep ON ep.snapshot_id=s.id
            JOIN navis.security_zone z ON z.enforcement_point_id=ep.id
            JOIN navis.security_zone_member zm ON zm.security_zone_id=z.id
            JOIN navis.interface i ON i.id=zm.interface_id
            WHERE bs.graph_build_id=%s AND s.device_id=%s AND ep.native_id=%s AND z.name IS NOT NULL""", (build_id, device_id, enforcement))
        result = {}
        for interface, zone in cur.fetchall():
            result.setdefault(interface, []).append(zone)
        return result

    @staticmethod
    def _nat(cur, build_id, device_id, packet, *, dataset=None, vrf=None, ingress=None):
        cur.execute("""SELECT ns.id,ns.processing_stage,ep.native_id,s.id,
                EXISTS (SELECT 1 FROM navis.snapshot_coverage c WHERE c.snapshot_id=s.id AND c.data_type='nat' AND c.coverage='complete')
            FROM navis.graph_build_snapshot bs JOIN navis.device_snapshot s ON s.id=bs.snapshot_id
            JOIN navis.enforcement_point ep ON ep.snapshot_id=s.id
            JOIN navis.nat_rule_set ns ON ns.enforcement_point_id=ep.id
            WHERE bs.graph_build_id=%s AND s.device_id=%s""", (build_id, device_id))
        sets = cur.fetchall()
        evidence = []
        if len(sets) > 1:
            return packet, [{"status": "unknown", "reason": "NAT rule set ordering is not established"}]
        for rule_set, stage, enforcement, snapshot, complete in sets:
            if stage not in ("before_route_after_policy", ORIGINAL_ADDRESS_STAGE):
                evidence.append({"status": "unknown", "enforcement_point": enforcement,
                                 "reason": "unsupported NAT processing stage"})
                continue
            zone_context = {}
            if stage == ORIGINAL_ADDRESS_STAGE:
                def unknown_context(reason):
                    return packet, [{"status": "unknown", "enforcement_point": enforcement,
                                     "processing_stage": stage, "reason": reason}]
                if dataset is None or vrf is None:
                    return unknown_context("pre-NAT routing context unavailable")
                routes = PostgresTraceProcessor._routes(cur, dataset, build_id, {"device_id": device_id, "vrf": vrf}, packet.destination)
                cur.execute("""SELECT c.coverage,c.details FROM navis.graph_dataset_snapshot ds
                    JOIN navis.graph_build_snapshot bs ON bs.snapshot_id=ds.snapshot_id AND bs.graph_build_id=%s
                    JOIN navis.snapshot_coverage c ON c.snapshot_id=ds.snapshot_id AND c.data_type='route'
                    WHERE ds.dataset_id=%s AND ds.device_id=%s AND c.data_type='route'""", (build_id, dataset, device_id))
                coverage = cur.fetchall()
                selection = select_routes(packet.destination, routes, complete=len(coverage) == 1 and coverage[0][0] == "complete",
                    table_kind=(coverage[0][1] or {}).get("table_kind") if len(coverage) == 1 else None)
                egresses = {r.get("interface") for r in selection.get("routes", []) if r.get("route_type") in ("forward", "connected")}
                if selection["status"] != "selected" or len(egresses) != 1 or None in egresses or any(r.get("route_type") == "discard" for r in selection.get("routes", [])):
                    return unknown_context("pre-NAT installed egress missing or ambiguous")
                egress = next(iter(egresses))
                memberships = PostgresTraceProcessor._zone_memberships(cur, build_id, device_id, enforcement)
                zone_context = {"source_zone": resolve_zone(ingress, memberships).zone,
                                "destination_zone": resolve_zone(egress, memberships).zone, "interface": egress}
            cur.execute("SELECT id,native_rule_id,enabled,details FROM navis.nat_rule WHERE nat_rule_set_id=%s ORDER BY position", (rule_set,))
            rules = []
            for rule_id, native_id, enabled, details in cur.fetchall():
                cur.execute("SELECT kind,specification FROM navis.nat_translation WHERE nat_rule_id=%s ORDER BY id", (rule_id,))
                translations = cur.fetchall()
                cur.execute("""SELECT ns.role,ns.negated,ns.matches_any,ao.prefix::text,
                    so.protocol,so.destination_port_start,so.destination_port_end,
                    so.source_port_start,so.source_port_end,so.details,
                    ns.security_zone_id,ns.interface_id
                    FROM navis.nat_selector ns LEFT JOIN navis.address_object ao ON ao.id=ns.address_object_id
                    LEFT JOIN navis.service_object so ON so.id=ns.service_object_id WHERE ns.nat_rule_id=%s""", (rule_id,))
                selectors = []
                for role, negated, any_value, prefix, protocol, start, end, source_start, source_end, service_details, zone, interface in cur.fetchall():
                    if any_value:
                        kind, value = "any", None
                    elif prefix:
                        kind, value = "address", prefix
                    elif protocol is not None and start is not None and end is not None:
                        kind, value = "service", {"protocol": protocol, "start": start, "end": end}
                        if source_start is not None and source_end is not None:
                            value.update(source_port_start=source_start, source_port_end=source_end)
                        value.update({k: service_details[k] for k in ("tcp_flags_all", "tcp_flags_any") if k in (service_details or {})})
                    elif zone is not None:
                        cur.execute("SELECT name FROM navis.security_zone WHERE id=%s", (zone,))
                        row = cur.fetchone()
                        kind, value = "zone", row[0] if row else None
                    elif interface is not None:
                        cur.execute("SELECT native_id FROM navis.interface WHERE id=%s", (interface,))
                        row = cur.fetchone()
                        kind, value = "interface", row[0] if row else None
                    else:
                        kind, value = "unsupported", None
                    selectors.append({"role": role, "kind": kind, "value": value, "negated": negated})
                kind, translation = translations[0] if len(translations) == 1 else ("unsupported", {})
                rules.append({"rule_id": native_id, "enabled": enabled, "kind": kind, "translation": translation,
                              "selectors_complete": bool((details or {}).get("selectors_complete")), "selectors": selectors})
            packet, result = evaluate_nat(rules, packet, complete=complete, **zone_context)
            evidence.append({"enforcement_point": enforcement, "snapshot_id": str(snapshot), "processing_stage": stage, **result})
            if result["status"] == "unknown":
                break
        return packet, evidence

    @staticmethod
    def _policies(cur, build_id, device_id, flow, ingress=None, egress=None, *, application=None):
        cur.execute("""SELECT rs.id,rs.default_action,ep.native_id,s.id,rs.statefulness,rs.session_semantics,
                EXISTS (SELECT 1 FROM navis.snapshot_coverage c WHERE c.snapshot_id=s.id AND c.data_type='policy' AND c.coverage='complete')
            FROM navis.graph_build_snapshot bs JOIN navis.device_snapshot s ON s.id=bs.snapshot_id
            JOIN navis.enforcement_point ep ON ep.snapshot_id=s.id
            JOIN navis.policy_rule_set rs ON rs.enforcement_point_id=ep.id
            WHERE bs.graph_build_id=%s AND s.device_id=%s""", (build_id, device_id))
        sets = cur.fetchall()
        evaluations = []
        for rule_set, default, enforcement, snapshot, statefulness, session_semantics, complete in sets:
            cur.execute("SELECT id,native_rule_id,action,enabled,details FROM navis.policy_rule WHERE rule_set_id=%s ORDER BY position", (rule_set,))
            rules = []
            for rule_id, native_id, action, enabled, details in cur.fetchall():
                cur.execute("""SELECT ps.role,ps.negated,ps.matches_any,ao.prefix::text,
                        so.protocol,so.destination_port_start,so.destination_port_end,
                        ps.security_zone_id,ps.interface_id,
                        so.source_port_start,so.source_port_end,so.details
                    FROM navis.policy_selector ps LEFT JOIN navis.address_object ao ON ao.id=ps.address_object_id
                    LEFT JOIN navis.service_object so ON so.id=ps.service_object_id WHERE ps.policy_rule_id=%s""", (rule_id,))
                selectors = []
                for role, negated, any_value, prefix, protocol, start, end, zone, interface, source_start, source_end, service_details in cur.fetchall():
                    if any_value:
                        kind, value = "any", None
                    elif prefix:
                        kind, value = "address", prefix
                    elif protocol is not None and start is not None and end is not None:
                        kind, value = "service", {"protocol": protocol, "start": start, "end": end}
                        if source_start is not None and source_end is not None:
                            value.update(source_port_start=source_start, source_port_end=source_end)
                        value.update({k: service_details[k] for k in ("tcp_flags_all", "tcp_flags_any") if k in (service_details or {})})
                    elif zone is not None:
                        cur.execute("SELECT name FROM navis.security_zone WHERE id=%s", (zone,))
                        zone_row = cur.fetchone()
                        kind, value = "zone", zone_row[0] if zone_row else None
                    elif interface is not None:
                        cur.execute("SELECT native_id FROM navis.interface WHERE id=%s", (interface,))
                        interface_row = cur.fetchone()
                        kind, value = "interface", interface_row[0] if interface_row else None
                    else:
                        kind, value = "unsupported", None
                    selectors.append({"role": role, "kind": kind, "value": value, "negated": negated})
                rules.append({"rule_id": native_id, "action": action, "enabled": enabled,
                    "selectors_complete": bool((details or {}).get("selectors_complete")), "selectors": selectors,
                    "details": details or {}})
            memberships = PostgresTraceProcessor._zone_memberships(cur, build_id, device_id, enforcement)
            source_zone = resolve_zone(ingress, memberships)
            destination_zone = resolve_zone(egress, memberships)
            workload_vifs = {r["details"]["workload_condition"]["vif_external_id"] for r in rules
                             if r["details"].get("workload_condition")}
            selected_vif, traffic_direction = None, None
            if len(workload_vifs) == 1:
                target_vif = next(iter(workload_vifs))
                if ingress == target_vif and egress != target_vif:
                    selected_vif, traffic_direction = target_vif, "IN"
                elif egress == target_vif and ingress != target_vif:
                    selected_vif, traffic_direction = target_vif, "OUT"
            result = evaluate_policy(rules, default, flow.source, flow.destination, flow.protocol, flow.destination_port,
                                     complete=complete, source_zone=source_zone.zone, destination_zone=destination_zone.zone, interface=ingress,
                                     source_port=getattr(flow, "source_port", None), application=application,
                vif_external_id=selected_vif, traffic_direction=traffic_direction,
                ingress_interface=ingress, egress_interface=egress)
            result["source_zone"] = source_zone.zone
            result["destination_zone"] = destination_zone.zone
            # Session applicability must be explicitly normalized per protocol;
            # do not infer it from the word stateful alone.
            protocols = (session_semantics or {}).get("supported_protocols", [])
            session_supported = flow.protocol.lower() in [str(item).lower() for item in protocols] if protocols else None
            evaluations.append({"enforcement_point": enforcement, "rule_set_id": str(rule_set), "snapshot_id": str(snapshot),
                                "statefulness": statefulness, "session_supported": session_supported, **result})
        return evaluations

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
