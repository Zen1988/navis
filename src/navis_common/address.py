"""Address sets used for packet matching, independent of interface subnets."""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network

IPAddress = IPv4Address | IPv6Address


@dataclass(frozen=True)
class AddressRange:
    start: IPAddress
    end: IPAddress

    def __post_init__(self) -> None:
        if self.start.version != self.end.version or int(self.start) > int(self.end):
            raise ValueError("address range must be ordered and use one IP version")

    def contains(self, address: str | IPAddress) -> bool:
        candidate = ip_address(address)
        return candidate.version == self.start.version and int(self.start) <= int(candidate) <= int(self.end)


def parse_address_selector(value: str) -> AddressRange:
    """Parse a host, CIDR, or inclusive range. CIDRs normalize host bits.

    Adapters must establish native semantics before using this generic parser;
    some platforms reject noncanonical prefixes or interpret them differently.
    """
    if "-" in value:
        start, end = value.split("-", 1)
        return AddressRange(ip_address(start.strip()), ip_address(end.strip()))
    network = ip_network(value.strip(), strict=False)
    return AddressRange(network.network_address, network.broadcast_address)
