"""Route selection over adapter-supplied installed forwarding entries."""
from ipaddress import ip_address, ip_network


def select_routes(destination, routes, *, complete, table_kind):
    """Select all most-specific installed routes; do not compare vendor metrics.

    Candidate routing tables require platform-specific selection before they can
    be treated as forwarding evidence. Discard routes remain explicit outcomes.
    """
    address = ip_address(destination)
    if not complete or table_kind != "installed":
        return {"status": "unknown", "routes": [], "reason": "installed forwarding coverage unavailable"}
    matching = []
    for route in routes:
        network = ip_network(route["prefix"], strict=True)
        if network.version == address.version and address in network:
            matching.append((network.prefixlen, route))
    if not matching:
        return {"status": "no_route", "routes": [], "reason": "no matching installed route"}
    best = max(length for length, _ in matching)
    selected = [route for length, route in matching if length == best]
    if any(route.get("route_type") not in ("forward", "connected", "discard") for route in selected):
        return {"status": "unknown", "routes": selected, "reason": "unsupported route behavior"}
    return {"status": "selected", "routes": selected, "reason": "longest matching installed prefix"}


def resolve_recursive(next_hop, lookup, *, max_depth=32):
    """Resolve an installed next-hop address using a caller-supplied table lookup."""
    current = str(ip_address(next_hop))
    visited = set()
    chain = []
    for _ in range(max_depth):
        if current in visited:
            return {"status": "unknown", "reason": "recursive next-hop loop", "chain": chain}
        visited.add(current)
        routes, complete, table_kind = lookup(current)
        result = select_routes(current, routes, complete=complete, table_kind=table_kind)
        if result["status"] != "selected" or len(result["routes"]) != 1:
            return {"status": "unknown", "reason": "recursive route unresolved or ambiguous", "chain": chain}
        route = result["routes"][0]
        chain.append(route)
        if route["route_type"] == "discard":
            return {"status": "discard", "reason": "recursive discard route", "chain": chain}
        if route.get("interface"):
            return {"status": "resolved", "interface": route["interface"], "chain": chain}
        if not route.get("next_hop"):
            return {"status": "unknown", "reason": "recursive next hop missing", "chain": chain}
        current = str(ip_address(route["next_hop"]))
    return {"status": "unknown", "reason": "recursive depth exceeded", "chain": chain}


def resolve_recursive_alternatives(next_hop, lookup, *, max_depth=32, max_paths=256):
    """Resolve all installed recursive next-hop branches, retaining unknowns."""
    pending = [(str(ip_address(next_hop)), [], frozenset())]
    paths = []
    while pending:
        if len(paths) >= max_paths:
            return {"complete": False, "paths": paths, "reason": "path limit reached"}
        address, chain, visited = pending.pop()
        if address in visited or len(chain) >= max_depth:
            paths.append({"status": "unknown", "reason": "recursive loop or depth limit", "chain": chain})
            continue
        routes, complete, kind = lookup(address)
        result = select_routes(address, routes, complete=complete, table_kind=kind)
        if result["status"] != "selected":
            paths.append({"status": "unknown", "reason": result["reason"], "chain": chain})
            continue
        for route in result["routes"]:
            new_chain = chain + [route]
            if route["route_type"] == "discard":
                paths.append({"status": "discard", "chain": new_chain})
            elif route.get("interface"):
                paths.append({"status": "resolved", "interface": route["interface"], "chain": new_chain})
            elif route.get("next_hop"):
                pending.append((str(ip_address(route["next_hop"])), new_chain, visited | {address}))
            else:
                paths.append({"status": "unknown", "reason": "next hop missing", "chain": new_chain})
            if len(paths) >= max_paths and (pending or len(result["routes"]) > 1):
                return {"complete": False, "paths": paths[:max_paths], "reason": "path limit reached"}
    return {"complete": bool(paths) and all(path["status"] != "unknown" for path in paths), "paths": paths}
