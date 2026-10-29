"""Assess whether collected policy evidence supports a forward-path decision."""


def applicability_coverage(records, ingress, egress):
    """Assess explicit normalized enforcement declarations for both directions."""
    results = {}
    for direction, interface in (("ingress", ingress), ("egress", egress)):
        candidates = [r for r in records if r["direction"] in (direction, "both", "device")
                      and (r.get("interface") is None or r["interface"] == interface)]
        states = {r["state"] for r in candidates}
        if not candidates or "unknown" in states or len(states) != 1:
            results[direction] = "unknown"
        else:
            results[direction] = next(iter(states))
    return results


def policy_coverage(hops, *, destination_reached):
    findings = []
    if not hops:
        return {"complete": False, "findings": ["No evaluated hops"]}
    if not destination_reached:
        findings.append("Destination was not reached")
    for hop in hops:
        device = hop["device_id"]
        coverage = hop.get("policy_coverage", "unknown")
        if coverage != "complete":
            findings.append(f"{device}: policy coverage is {coverage}")
        applicability = hop.get("policy_direction_applicability", {})
        if not hop.get("policy_evaluations") and not hop.get("policy_not_applicable", False):
            findings.append(f"{device}: policy applicability is not established")
        if applicability and "unknown" in applicability.values():
            findings.append(f"{device}: directional policy applicability is unknown")
        for evaluation in hop.get("policy_evaluations", []):
            if evaluation.get("decision") not in ("allow", "deny"):
                findings.append(f"{device}: policy decision is unknown")
    return {"complete": not findings, "findings": findings}


def forwarding_coverage(hops, devices, *, destination_reached, evidence_unchanged):
    """Assess a single forward candidate using installed-route evidence."""
    findings = []
    if not evidence_unchanged:
        findings.append("Graph and relational evidence do not match")
    if not destination_reached:
        findings.append("Destination was not reached")
    if not hops:
        findings.append("No forwarding hops")
    for hop in hops[:-1] if destination_reached else hops:
        assessment = hop.get("route_assessment", {})
        if assessment.get("status") != "selected":
            findings.append(f"{hop['device_id']}: installed route not established")
        if hop.get("stop_reason"):
            findings.append(f"{hop['device_id']}: {hop['stop_reason']}")
    return {"complete": not findings, "findings": findings}


def overall_coverage(*, forwarding, policy, nat, return_path, alternatives, evidence_unchanged):
    checks = {"forwarding": forwarding, "policy": policy, "nat": nat,
              "return_path": return_path, "alternative_paths": alternatives,
              "evidence_unchanged": evidence_unchanged}
    missing = [name for name, established in checks.items() if not established]
    return {"complete": not missing, "missing": missing}
