"""Combine normalized ingress and egress policy decisions."""


def combine_directional_policy(*, source_egress, destination_ingress):
    """Combine independently evaluated directional decisions.

    Adapters establish endpoint selection, rule union, defaults and whether a
    direction is enforced; this function does not interpret Kubernetes objects.
    """
    allowed = {"allow", "not_applicable"}
    decisions = {"source_egress": source_egress, "destination_ingress": destination_ingress}
    if any(value not in ("allow", "deny", "unknown", "not_applicable") for value in decisions.values()):
        raise ValueError("invalid normalized directional policy decision")
    if "deny" in decisions.values():
        return {"decision": "deny", "directions": decisions, "reason": "a required direction denies traffic"}
    if all(value in allowed for value in decisions.values()):
        return {"decision": "allow", "directions": decisions, "reason": "both directions permit traffic"}
    return {"decision": "unknown", "directions": decisions, "reason": "directional policy evidence incomplete"}
