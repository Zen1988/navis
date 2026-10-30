"""Find potentially relevant ACI candidates without issuing policy decisions."""
from ipaddress import ip_address, ip_network


def _list(value):
    return value if isinstance(value, list) else []


def candidate_evidence(payloads, source, destination, protocol, destination_port, limit=1000):
    src, dst = ip_address(source), ip_address(destination)
    matches = []
    for snapshot, payload in payloads:
        if not isinstance(payload, dict) or payload.get("kind") != "aci_fabric_evidence" or payload.get("version") != 1:
            continue
        semantics = payload.get("semantics")
        if not isinstance(semantics, dict):
            continue
        groups = {}
        for group in _list(semantics.get("endpoint_groups")):
            if not isinstance(group, dict) or not isinstance(group.get("native_id"), str):
                continue
            addresses = set()
            for endpoint in _list(group.get("endpoints")):
                if isinstance(endpoint, dict):
                    addresses.update(x for x in _list(endpoint.get("addresses")) if isinstance(x, str))
            groups[group["native_id"]] = (addresses, [])
        for network in _list(semantics.get("external_networks")):
            if not isinstance(network, dict):
                continue
            for group in _list(network.get("external_epgs")):
                if not isinstance(group, dict) or not isinstance(group.get("native_id"), str):
                    continue
                prefixes = []
                for subnet in _list(group.get("subnets")):
                    if not isinstance(subnet, dict) or "import-security" not in [s.strip() for s in str(subnet.get("scope") or "").split(",")]:
                        continue
                    try:
                        prefixes.append(ip_network(subnet.get("prefix"), strict=False))
                    except (TypeError, ValueError):
                        continue
                groups[group["native_id"]] = (set(), prefixes)

        def contains(group, address):
            if not isinstance(group, str):
                return False
            addresses, prefixes = groups.get(group, (set(), []))
            return str(address) in addresses or any(address.version == p.version and address in p for p in prefixes)

        candidates = semantics.get("directional_rules", semantics.get("policy_candidates"))
        for candidate in _list(candidates):
            if not isinstance(candidate, dict):
                continue
            consumer, provider = candidate.get("consumer_epg"), candidate.get("provider_epg")
            forward = contains(consumer, src) and contains(provider, dst)
            reverse = contains(provider, src) and contains(consumer, dst)
            direction = candidate.get("packet_direction", "unknown")
            membership_match = forward if direction == "consumer_to_provider" else reverse if direction == "provider_to_consumer" else forward or reverse
            if not membership_match:
                continue
            item_protocol = candidate.get("protocol")
            if isinstance(item_protocol, str) and item_protocol and item_protocol.lower() != protocol.lower():
                continue
            # Source ports and TCP flags may be absent from the trace request;
            # preserve uncertainty even when direction/destination port match.
            ports = candidate.get("destination_ports")
            if direction != "unknown" and isinstance(ports, dict) and destination_port is not None:
                if not ports["start"] <= destination_port <= ports["end"]:
                    continue
            matches.append({"snapshot_id": str(snapshot), "candidate": candidate,
                            "membership": "observed_unverified", "packet_direction": direction,
                            "service_match": "unknown", "decision": "unknown"})
            if len(matches) >= limit:
                return {"candidates": matches, "status": "unknown", "truncated": True}
    return {"candidates": matches, "status": "unknown", "truncated": False}
