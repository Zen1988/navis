"""Display incomplete paths without inventing inventory or verified links."""
import json
from uuid import NAMESPACE_URL, uuid5


def inventory_evidence():
    """Verify inventory presence only; never imply that a path was traversed."""
    return {"evidence_status": "verified", "evidence_label": "Verified evidence (inventory)",
            "verification_scope": "inventory_presence",
            "verification_message": "Present in selected Navis inventory. Configuration, policy and reachability assessments are separate."}


def unmanaged_node(key, *, reason, addresses=(), role="segment"):
    return {
        "id": "unmanaged:" + str(uuid5(NAMESPACE_URL, json.dumps(key, sort_keys=True))),
        "type": "unmanaged", "name": "Unmanaged / missing network" if role == "segment" else "Unmanaged / unresolved " + role,
        "device_id": None, "placeholder": True, "management_status": "unknown",
        "evidence_status": "unverified", "evidence_label": "Unverified / missing evidence",
        "verification_scope": None, "trace_status": "not_traced",
        "role": role, "addresses": list(addresses), "reason": reason,
        "unknown_hop_count": None,
        "message": "Navis has insufficient inventory or path evidence to trace this part of the network.",
    }


def visibility_graph(result):
    """Return managed candidate hops plus explicit endpoints and visibility gaps.

    Placeholders are presentation evidence. They never participate in route,
    policy, NAT or reachability evaluation, and do not assert a device count.
    """
    scope = [result.get(k) for k in ("source", "destination", "protocol", "source_port", "destination_port")]
    nodes, edges = {}, []
    hops = result.get("hops", [])

    def managed(device, name=None):
        nodes.setdefault(device, {"id": device, "type": "device", "name": name,
                                  "device_id": device, "placeholder": False, "addresses": [],
                                  "trace_status": "not_traced", **inventory_evidence()})
        if name and not nodes[device].get("name"):
            nodes[device]["name"] = name
        return device

    def endpoint(role):
        candidates = result.get(role + "_candidates", [])
        if role == "destination":
            for hop in reversed(hops):
                if "translated_destination_candidates" in hop:
                    candidates = hop["translated_destination_candidates"]
                    break
        if len(candidates) == 1:
            return managed(candidates[0]["device_id"])
        reason = role + ("_ambiguous" if candidates else "_inventory_missing")
        node = unmanaged_node([scope, role], reason=reason,
                              addresses=[result[role]] if result.get(role) else [], role=role)
        node["candidate_device_ids"] = sorted({c["device_id"] for c in candidates})
        nodes[node["id"]] = node
        return node["id"]

    source, destination = endpoint("source"), endpoint("destination")
    for hop in hops:
        managed(hop["device_id"], hop.get("name"))
        nodes[hop["device_id"]]["trace_status"] = "visited"
    for left, right in zip(hops, hops[1:]):
        edges.append({"source": left["device_id"], "target": right["device_id"],
                      "kind": "trace_candidate", "status": "unverified"})
    last = hops[-1] if hops else {}
    denied = any(e.get("decision") == "deny" for hop in hops for e in hop.get("policy_evaluations", []))
    terminal_route = (last.get("route") or {}).get("route_type") in ("discard", "reject", "blackhole", "unreachable", "prohibit")
    reached = result.get("coverage", {}).get("destination_reached", False)
    # A block or explicit terminal route is not evidence of a missing device.
    if not reached and not denied and not terminal_route:
        anchor = last.get("device_id", source)
        reason = last.get("visibility_stop") or last.get("stop_reason") or ("destination_inventory_missing" if not result.get("destination_candidates") else "path_evidence_missing")
        next_hop = (last.get("route") or {}).get("next_hop")
        gap = unmanaged_node([scope, anchor, destination, "gap"], reason=reason,
                             addresses=[next_hop] if next_hop else [])
        nodes[gap["id"]] = gap
        edges.append({"source": anchor, "target": gap["id"], "kind": "visibility_gap", "status": "unknown"})
        if destination != anchor:
            edges.append({"source": gap["id"], "target": destination, "kind": "untraced_remainder", "status": "unknown"})
    return {"nodes": list(nodes.values()), "connections": edges,
            "status": "incomplete" if any(n.get("placeholder") for n in nodes.values()) else "candidate_path",
            "semantics": "Visibility only; unknown edges do not establish forwarding or reachability."}


def add_visibility(response):
    """Decorate per-flow results; retain existing verdicts and coverage verbatim."""
    for result in response.get("results", []):
        graph = visibility_graph(result)
        result["visibility_graph"] = graph
        result["findings"] = [f for f in result.get("findings", [])
                              if f.get("code") not in ("UNMANAGED_PATH_SEGMENT", "ENDPOINT_VISIBILITY_MISSING")]
        for node in graph["nodes"]:
            if node.get("placeholder"):
                result.setdefault("findings", []).append({"code": "UNMANAGED_PATH_SEGMENT" if node["role"] == "segment" else "ENDPOINT_VISIBILITY_MISSING",
                    "device_id": None, "node_id": node["id"], "reason": node["reason"],
                    "message": node["message"], "unknown_hop_count": None})
    return response
