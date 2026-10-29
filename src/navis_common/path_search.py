"""Explore normalized forwarding alternatives without assuming all are usable."""
from dataclasses import dataclass
from .routing import select_routes


@dataclass(frozen=True)
class ForwardingState:
    device_id: str
    routing_context: str
    destination: str
    source: str = ""
    protocol: str = ""
    destination_port: int | None = None
    source_port: int | None = None
    ingress_interface: str | None = None


def explore_paths(start, is_destination, lookup, *, evaluate_policy=None, evaluate_nat=None,
                  processing_order="policy_then_nat", max_hops=64, max_paths=256):
    """Explore caller-resolved route alternatives with per-path loop detection.

    `lookup(state)` returns (routes, complete, table_kind); each selected route
    supplies `next_states`, already resolved by the caller. This function does
    not evaluate policy unless a callback is supplied. The optional NAT callback
    returns (translated state, evidence) after policy and before route lookup.
    Adapters must establish that this ordering applies to the selected context.
    """
    if max_hops < 1 or max_paths < 1:
        raise ValueError("limits must be positive")
    if processing_order not in ("policy_then_nat", "nat_then_policy"):
        raise ValueError("unsupported processing order")
    pending = [(start, [], frozenset())]
    results = []
    while pending:
        state, path, visited = pending.pop()
        if len(results) >= max_paths:
            return {"paths": results, "complete": False, "reason": "path limit reached"}
        if state in visited:
            results.append({"status": "unknown", "reason": "routing loop", "hops": path})
            continue
        path = path + [state]
        def apply_policy(current):
            return evaluate_policy(current) if evaluate_policy is not None else {"decision": "allow"}

        def apply_nat(current):
            return evaluate_nat(current) if evaluate_nat is not None else (current, {"status": "unchanged"})

        if processing_order == "policy_then_nat":
            policy = apply_policy(state)
        else:
            state, evidence = apply_nat(state)
            if evidence.get("status") not in ("translated", "unchanged"):
                results.append({"status": "unknown", "reason": "NAT decision unknown", "nat": evidence, "hops": path})
                continue
            if not isinstance(state, ForwardingState) or (state.device_id, state.routing_context) != (path[-1].device_id, path[-1].routing_context):
                raise ValueError("NAT must preserve device and routing context")
            policy = apply_policy(state)
        if evaluate_policy is not None:
            decision = policy.get("decision")
            if decision == "deny":
                results.append({"status": "blocked", "reason": "policy denied", "policy": policy, "hops": path})
                continue
            if decision != "allow":
                results.append({"status": "unknown", "reason": "policy decision unknown", "policy": policy, "hops": path})
                continue
        if processing_order == "policy_then_nat" and evaluate_nat is not None:
            translated, evidence = apply_nat(state)
            if evidence.get("status") not in ("translated", "unchanged"):
                results.append({"status": "unknown", "reason": "NAT decision unknown", "nat": evidence, "hops": path})
                continue
            if not isinstance(translated, ForwardingState) or (translated.device_id, translated.routing_context) != (state.device_id, state.routing_context):
                raise ValueError("NAT must preserve device and routing context")
            state = translated
        if is_destination(state):
            results.append({"status": "candidate", "reason": "destination reached", "hops": path})
            continue
        if len(path) >= max_hops:
            results.append({"status": "unknown", "reason": "hop limit reached", "hops": path})
            continue
        routes, complete, table_kind = lookup(state)
        selected = select_routes(state.destination, routes, complete=complete, table_kind=table_kind)
        if selected["status"] != "selected":
            results.append({"status": "unknown", "reason": selected["reason"], "hops": path})
            continue
        visited = visited | {state}
        for route in reversed(selected["routes"]):
            if route["route_type"] == "discard":
                results.append({"status": "discard", "reason": "installed discard route", "hops": path})
            elif not route.get("next_states"):
                results.append({"status": "unknown", "reason": "next hop unresolved", "hops": path})
            else:
                for next_state in reversed(route["next_states"]):
                    pending.append((next_state, path, visited))
            if len(results) >= max_paths and (pending or len(selected["routes"]) > 1):
                return {"paths": results[:max_paths], "complete": False, "reason": "path limit reached"}
    return {"paths": results, "complete": all(p["status"] != "unknown" for p in results)}


def alternative_verdict(search):
    """Summarize a search without treating a candidate as confirmed reachable."""
    paths = search.get("paths", [])
    if not paths or not search.get("complete", False) or any(p.get("status") == "unknown" for p in paths):
        return {"status": "unknown", "reason": "one or more paths are unresolved"}
    if all(p.get("status") in ("blocked", "discard") for p in paths):
        return {"status": "blocked", "reason": "all evaluated paths are blocked or discarded"}
    return {"status": "unknown", "reason": "a candidate path requires end-to-end validation"}
