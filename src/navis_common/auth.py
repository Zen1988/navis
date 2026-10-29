"""Shared authentication provider contract; implementations must validate tokens."""

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class Principal:
    subject: str
    scopes: frozenset[str]
    issuer: str = ""


class TokenVerifier(Protocol):
    def verify(self, token: str) -> Principal | None:
        """Return a principal only after validating token authenticity and claims."""


class DenyAllVerifier:
    def verify(self, token: str) -> Principal | None:
        return None
