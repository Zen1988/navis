"""Canonical comparison of 48-bit MAC addresses."""

import re


def normalize_mac(value: str) -> str:
    """Return lowercase colon notation for a supported 48-bit MAC address.

    Accept colon- or hyphen-separated octets, Cisco dotted groups, and
    twelve hexadecimal digits. Reject mixed separators and partial addresses.
    """
    text = value.strip()
    if re.fullmatch(r"[0-9a-fA-F]{12}", text):
        digits = text
    elif re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", text):
        digits = text.replace(":", "")
    elif re.fullmatch(r"(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}", text):
        digits = text.replace("-", "")
    elif re.fullmatch(r"[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}", text):
        digits = text.replace(".", "")
    else:
        raise ValueError("invalid 48-bit MAC address")
    digits = digits.lower()
    return ":".join(digits[index:index + 2] for index in range(0, 12, 2))


def mac_addresses_equal(first: str, second: str) -> bool:
    """Compare complete MAC addresses regardless of supported notation."""
    return normalize_mac(first) == normalize_mac(second)
