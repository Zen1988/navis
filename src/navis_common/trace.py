"""Validate and expand connectivity trace requests."""
from dataclasses import dataclass
from ipaddress import ip_address
import re


@dataclass(frozen=True)
class Flow:
    source: str
    destination: str
    protocol: str
    destination_port: int | None
    application: str | None = None


def _addresses(value: str) -> list[str]:
    parts = re.split(r"[,;]", value)
    if not parts or any(not part.strip() for part in parts):
        raise ValueError("addresses must be nonempty and separated by commas or semicolons")
    return list(dict.fromkeys(str(ip_address(part.strip())) for part in parts))


def expand_flows(source: str, destination: str, protocol: str, destination_port: int | None = None, *, max_flows: int = 1000, application: str | None = None) -> list[Flow]:
    sources, destinations = _addresses(source), _addresses(destination)
    if application is not None and (not isinstance(application, str) or not application.strip()):
        raise ValueError("application must be a named identity")
    protocol = protocol.strip().lower()
    if protocol not in ("tcp", "udp", "icmp", "icmpv6"):
        raise ValueError("unsupported protocol")
    if destination_port is not None and (isinstance(destination_port, bool) or not 0 <= destination_port <= 65535):
        raise ValueError("invalid destination port")
    if protocol in ("icmp", "icmpv6") and destination_port is not None:
        raise ValueError("ICMP does not use a destination port")
    if len(sources) * len(destinations) > max_flows:
        raise ValueError("too many flows")
    return [Flow(src, dst, protocol, destination_port, application) for src in sources for dst in destinations]
