"""Derive a conservative connectivity verdict from evaluated hops."""


def derive_verdict(hops, *, destination_reached=False, evidence_complete=False):
    for hop in hops:
        for evaluation in hop.get("policy_evaluations", []):
            if evaluation.get("decision") == "deny":
                return {"status": "blocked", "scope": "candidate_path", "blocking_point": hop["device_id"],
                        "reason": evaluation.get("reason", "policy denied traffic"),
                        "rule_id": evaluation.get("rule_id")}
    if destination_reached and evidence_complete and all(
        evaluation.get("decision") == "allow"
        for hop in hops for evaluation in hop.get("policy_evaluations", [])
    ):
        return {"status": "allowed", "scope": "forward_path", "blocking_point": None,
                "reason": "Destination reached with complete forwarding, NAT and policy evidence", "rule_id": None}
    return {"status": "unknown", "scope": "end_to_end", "blocking_point": None,
            "reason": "End-to-end route, NAT and policy coverage is not established", "rule_id": None}


def connection_verdict(*, forwarding, nat, policy, return_path, alternatives_complete, all_paths_blocked=False):
    """Combine independently established evidence; unknowns cannot become allow."""
    components = {"forwarding": forwarding, "nat": nat, "policy": policy, "return_path": return_path}
    valid = {"allow", "blocked", "unknown"}
    if any(value not in valid for value in components.values()):
        raise ValueError("invalid evidence decision")
    if alternatives_complete and all_paths_blocked:
        return {"status": "blocked", "missing": [], "components": components}
    missing = [key for key, value in components.items() if value == "unknown"]
    if not alternatives_complete:
        missing.append("alternative_paths")
    if any(value == "blocked" for value in components.values()):
        missing.append("all_paths_blocked")
    if not missing and all(value == "allow" for value in components.values()):
        return {"status": "allowed", "missing": [], "components": components}
    return {"status": "unknown", "missing": missing, "components": components}
