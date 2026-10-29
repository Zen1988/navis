"""Normalized return-traffic semantics for an enforcement point."""


def evaluate_return(*, mode, forward_decision, reverse_decision=None, session_supported=None):
    """Combine normalized forward and reverse decisions for one flow.

    A stateful rule permits return traffic only when the adapter explicitly
    confirms the protocol and flow are covered by its state tracking.
    """
    if forward_decision not in ("allow", "deny", "unknown"):
        raise ValueError("invalid forward decision")
    if forward_decision == "deny":
        return {"decision": "deny", "reason": "forward policy denied"}
    if forward_decision != "allow":
        return {"decision": "unknown", "reason": "forward policy unknown"}
    if mode == "stateful":
        if session_supported is True:
            return {"decision": "allow", "reason": "return policy modeled as permitted if a session is established"}
        return {"decision": "unknown", "reason": "state tracking applicability not established"}
    if mode == "stateless":
        if reverse_decision in ("allow", "deny"):
            return {"decision": reverse_decision, "reason": "reverse policy evaluated independently"}
        return {"decision": "unknown", "reason": "reverse policy not established"}
    return {"decision": "unknown", "reason": "statefulness unknown"}


def evaluate_connection(*, forward_decision, mode, return_route, reverse_decision=None, session_supported=None):
    """Require a return route even when stateful policy permits established traffic."""
    policy = evaluate_return(mode=mode, forward_decision=forward_decision,
                             reverse_decision=reverse_decision, session_supported=session_supported)
    if policy["decision"] == "deny":
        return {"decision": "deny", "reason": policy["reason"]}
    if return_route == "blocked":
        return {"decision": "deny", "reason": "return route blocked"}
    if policy["decision"] != "allow" or return_route != "reachable":
        return {"decision": "unknown", "reason": "return policy or route is not established"}
    return {"decision": "allow", "reason": "forward and return evidence established"}
