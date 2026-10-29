"""Verify a modeled reverse path against recorded NAT session transitions."""
from dataclasses import dataclass
from .nat import Packet
from .path_search import ForwardingState, explore_paths


@dataclass(frozen=True)
class ReverseTransition:
    device_id: str
    before: Packet
    after: Packet
    session_confirmed: bool
    policy_rule_set_id: str | None = None


def apply_reverse_mapping(device_id, packet, transitions):
    matches = [entry for entry in transitions if entry.device_id == device_id]
    if not matches:
        return packet, {"status": "unchanged", "reason": "no recorded mapping at device"}
    if len(matches) != 1:
        return packet, {"status": "unknown", "reason": "ambiguous reverse NAT mappings"}
    mapping = matches[0]
    if not mapping.session_confirmed:
        return packet, {"status": "unknown", "reason": "NAT session is not established"}
    if packet != mapping.before:
        return packet, {"status": "unknown", "reason": "reply packet does not match recorded NAT session"}
    return mapping.after, {"status": "translated", "reason": "recorded session reverse mapping"}


def return_path_verdict(*, destination_reached, route_coverage_complete, policy_decision, nat_decision):
    if policy_decision == "deny" or nat_decision == "deny":
        return {"status": "blocked", "reason": "return traffic denied"}
    if destination_reached and route_coverage_complete and policy_decision == "allow" and nat_decision == "allow":
        return {"status": "reachable", "reason": "return path and enforcement verified"}
    return {"status": "unknown", "reason": "return path or enforcement evidence incomplete"}


def trace_reverse_path(start, destination, lookup, policy, transitions, *, nat_absence_confirmed=None, max_hops=64, max_paths=256):
    """Trace reverse forwarding, applying only confirmed session transitions."""
    def nat(state):
        packet = Packet(state.source, state.destination, state.protocol, state.destination_port, state.source_port)
        if not any(entry.device_id == state.device_id for entry in transitions):
            if nat_absence_confirmed is None or not nat_absence_confirmed(state):
                return state, {"status": "unknown", "reason": "reverse NAT applicability not established"}
        translated, evidence = apply_reverse_mapping(state.device_id, packet, transitions)
        updated = ForwardingState(state.device_id, state.routing_context, translated.destination,
                                  translated.source, translated.protocol, translated.destination_port,
                                  translated.source_port, state.ingress_interface)
        return updated, evidence

    return explore_paths(start, destination, lookup, evaluate_policy=policy, evaluate_nat=nat,
                         processing_order="policy_then_nat", max_hops=max_hops, max_paths=max_paths)


def assess_reverse_paths(search):
    """Assess modeled paths after every route, policy and mapping check passed."""
    paths = search.get("paths", [])
    if not paths or not search.get("complete"):
        return {"status": "unknown", "reason": "reverse paths are incomplete"}
    if all(path.get("status") in ("blocked", "discard") for path in paths):
        return {"status": "blocked", "reason": "all reverse alternatives are blocked"}
    if any(path.get("status") == "candidate" for path in paths):
        return {"status": "candidate_reachable", "reason": "a modeled reverse path reached its destination"}
    return {"status": "unknown", "reason": "reverse path outcome unsupported"}
