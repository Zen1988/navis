"""Deterministic traversal over already-resolved forwarding evidence."""
from dataclasses import dataclass
from ipaddress import ip_address, ip_network


@dataclass(frozen=True)
class HopEvidence:
    device_id: str
    prefix: str
    next_device_id: str | None
    route_id: str
    interface: str | None = None
    enforcement: str | None = None
    decision: str = "unknown"


def walk_path(source_device: str, destination_device: str, destination: str,
              evidence: list[HopEvidence], *, max_hops: int = 64) -> dict:
    """Walk only uniquely supported next hops; equally specific routes branch ambiguously."""
    target = ip_address(destination)
    current = source_device
    visited = set()
    hops = []
    for _ in range(max_hops):
        if current in visited:
            return {"status": "unknown", "reason": "routing loop", "hops": hops}
        visited.add(current)
        if current == destination_device:
            hops.append({"number": len(hops) + 1, "device_id": current, "type": "destination"})
            return {"status": "unknown", "reason": "destination reached; end-to-end policy not established", "hops": hops}
        matches = [e for e in evidence if e.device_id == current and target in ip_network(e.prefix)]
        if not matches:
            return {"status": "unknown", "reason": "no forwarding evidence", "hops": hops}
        length = max(ip_network(e.prefix).prefixlen for e in matches)
        best = [e for e in matches if ip_network(e.prefix).prefixlen == length]
        if len(best) != 1:
            return {"status": "unknown", "reason": "multiple equally specific route candidates", "hops": hops}
        route = best[0]
        hops.append({"number": len(hops) + 1, "device_id": current, "type": "firewall" if route.enforcement else "router", "route_id": route.route_id, "interface": route.interface, "enforcement": route.enforcement, "decision": route.decision})
        if route.decision == "deny":
            return {"status": "blocked", "reason": "explicit policy denial", "hops": hops}
        if route.next_device_id is None:
            return {"status": "unknown", "reason": "next device unresolved", "hops": hops}
        current = route.next_device_id
    return {"status": "unknown", "reason": "hop limit reached", "hops": hops}
