"""Expose frontend/backend connection candidates without inventing LB sessions."""
from ipaddress import ip_address


def candidate_evidence(payloads, source, destination, protocol, destination_port, limit=1000):
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise ValueError("positive candidate limit required")
    source, destination = str(ip_address(source)), str(ip_address(destination))
    matches = []
    remaining = limit
    for snapshot, payload in payloads:
        if not isinstance(payload, dict) or payload.get("kind") not in ("avi_load_balancer_evidence", "f5_load_balancer_evidence") or payload.get("version") != 1:
            continue
        semantics = payload.get("semantics")
        if not isinstance(semantics, dict):
            continue
        services = semantics.get("virtual_services")
        if not isinstance(services, list):
            continue
        for service in services:
            if not isinstance(service, dict) or service.get("enabled") is not True or not isinstance(service.get("vip_addresses"), list) or destination not in service["vip_addresses"]:
                continue
            if not all(isinstance(service.get(k), str) for k in ("uuid", "vrf_uuid", "tenant_uuid")) or not isinstance(service.get("listeners"), list) or not isinstance(service.get("backends"), list):
                continue
            for listener in service["listeners"]:
                if not isinstance(listener, dict) or any(type(listener.get(k)) is not int for k in ("start", "end")) or not 1 <= listener["start"] <= listener["end"] <= 65535:
                    continue
                if listener.get("protocol") != protocol.lower():
                    continue
                if destination_port is not None and not listener["start"] <= destination_port <= listener["end"]:
                    continue
                branches = []
                for backend in service["backends"]:
                    if not isinstance(backend, dict) or backend.get("port_mode") not in ("preserve_listener", "fixed") or not isinstance(backend.get("pool_uuid"), str):
                        continue
                    try:
                        ip_address(backend.get("address"))
                    except (ValueError, TypeError):
                        continue
                    if backend["port_mode"] == "fixed" and (type(backend.get("port")) is not int or not 1 <= backend["port"] <= 65535):
                        continue
                    port = destination_port if backend["port_mode"] == "preserve_listener" else backend["port"]
                    branches.append({"pool_uuid": backend["pool_uuid"], "destination": backend["address"],
                        "destination_port": port, "source": None, "source_port": None,
                        "source_translation": service.get("source_translation"), "health": "unknown",
                        "selection": "unknown", "backend_tls": backend.get("backend_tls"),
                        "pool_group_member": backend.get("pool_group_member")})
                    remaining -= 1
                    if remaining <= 0:
                        break
                matches.append({"snapshot_id": str(snapshot), "virtualservice_uuid": service["uuid"],
                    "evidence_kind": payload["kind"],
                    "vrf_uuid": service["vrf_uuid"], "tenant_uuid": service["tenant_uuid"],
                    "frontend": {"source": source, "destination": destination, "protocol": protocol.lower(), "destination_port": destination_port},
                    "listener": listener, "backend_connection_candidates": branches,
                    "conditions_complete": service.get("conditions_complete", False),
                    "unresolved": service.get("unresolved", []), "decision": "unknown",
                    "reason": "configuration candidates do not establish selection, health, SNAT allocation or return path"})
                if len(matches) >= limit or remaining <= 0:
                    return {"candidates": matches, "status": "unknown", "truncated": True}
    return {"candidates": matches, "status": "unknown", "truncated": False}
