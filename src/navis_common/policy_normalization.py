"""Normalize enforcement evidence without assuming a vendor default."""


def normalize_enforcement(*, state, rules=None, default_action=None, complete=False):
    """Produce a uniform policy contract from adapter-supplied evidence.

    `not_applicable` must be explicitly established for the relevant context;
    absence of collected rules does not establish it.
    """
    if state == "not_applicable" and complete:
        return {"state": "not_applicable", "rules": [], "default_action": "allow", "complete": True,
                "reason": "No policy enforcement applies in this context"}
    if state == "enforced" and complete and default_action in ("allow", "deny") and rules is not None:
        return {"state": "enforced", "rules": rules, "default_action": default_action, "complete": True,
                "reason": "Enforcement and default supplied by adapter"}
    return {"state": "unknown", "rules": rules or [], "default_action": "unknown", "complete": False,
            "reason": "Enforcement applicability, rule coverage or default is unknown"}
