"""Conservative matching of submitted device identity evidence."""

from dataclasses import dataclass
from ipaddress import ip_address
from uuid import UUID


@dataclass(frozen=True)
class DeviceEvidence:
    device_id: UUID
    identities: frozenset[tuple[str, str]] = frozenset()
    platform: str | None = None
    display_name: str | None = None
    addresses: frozenset[str] = frozenset()


@dataclass(frozen=True)
class DeviceMatch:
    status: str
    device_id: UUID | None
    candidates: tuple[UUID, ...]
    reason: str

    @property
    def requires_confirmation(self) -> bool:
        """Whether the caller must resolve candidates before associating data."""
        return self.status in ("review", "ambiguous")


def match_device(*, namespace: str | None, external_id: str | None,
                 platform: str | None, display_name: str | None,
                 addresses: frozenset[str], devices: list[DeviceEvidence]) -> DeviceMatch:
    """Resolve a trusted current source mapping, or return candidates for review.

    Callers supply only mappings valid at the relevant time and source namespace.
    Candidate metadata never authorizes an automatic merge. The caller must
    obtain confirmation for review or ambiguous results before associating data.
    """
    if (namespace is None) != (external_id is None):
        raise ValueError("namespace and external ID must be supplied together")
    if namespace is not None and (not namespace.strip() or not external_id.strip()):
        raise ValueError("namespace and external ID must be nonempty")
    incoming_ips = {ip_address(value) for value in addresses}
    if namespace is not None:
        exact = {d.device_id for d in devices if (namespace, external_id) in d.identities}
        if len(exact) == 1:
            return DeviceMatch("matched", next(iter(exact)), tuple(exact), "trusted external identity mapping")
        if len(exact) > 1:
            return DeviceMatch("ambiguous", None, tuple(sorted(exact, key=str)), "conflicting external identity mappings")

    candidates = set()
    for device in devices:
        name_match = bool(display_name and device.display_name and display_name.casefold() == device.display_name.casefold())
        ip_match = bool(incoming_ips & {ip_address(value) for value in device.addresses})
        platform_match = not platform or not device.platform or platform.casefold() == device.platform.casefold()
        if platform_match and (name_match or ip_match):
            candidates.add(device.device_id)
    ordered = tuple(sorted(candidates, key=str))
    if ordered:
        return DeviceMatch("review", None, ordered, "metadata suggests candidates but does not establish identity")
    return DeviceMatch("unresolved", None, (), "no matching identity or candidate evidence")
