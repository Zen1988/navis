"""Firewall interface-to-zone resolution and recommendation preparation."""
from dataclasses import dataclass


@dataclass(frozen=True)
class ZoneResolution:
    status: str
    zone: str | None
    candidates: tuple[str, ...]


def resolve_zone(interface: str | None, memberships: dict[str, list[str]]) -> ZoneResolution:
    if not interface:
        return ZoneResolution("unknown", None, ())
    candidates = tuple(sorted(set(memberships.get(interface, []))))
    if len(candidates) == 1:
        return ZoneResolution("resolved", candidates[0], candidates)
    return ZoneResolution("ambiguous" if candidates else "unknown", None, candidates)


def rule_recommendation(*, device_id: str, source: str, destination: str, protocol: str,
                        destination_port: int | None, ingress: str | None, egress: str | None,
                        memberships: dict[str, list[str]], reason: str) -> dict:
    source_zone = resolve_zone(ingress, memberships)
    destination_zone = resolve_zone(egress, memberships)
    return {
        "device_id": device_id, "action": "allow", "source": source, "destination": destination,
        "protocol": protocol, "destination_port": destination_port,
        "ingress_interface": ingress, "egress_interface": egress,
        "source_zone": source_zone.zone, "destination_zone": destination_zone.zone,
        "source_zone_status": source_zone.status, "destination_zone_status": destination_zone.status,
        "reason": reason,
        "status": "draft" if source_zone.zone and destination_zone.zone and destination_port is not None else "incomplete",
    }
