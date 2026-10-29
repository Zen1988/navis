"""Single application bearer credential for controlled local test deployments."""
import hashlib
import hmac
from .auth import Principal


class LocalTokenVerifier:
    def __init__(self, token, principal):
        if len(token) < 32:
            raise ValueError("local token must be at least 32 characters")
        self._digest = hashlib.sha256(token.encode()).digest()
        self._principal = principal

    def verify(self, token):
        candidate = hashlib.sha256(token.encode()).digest()
        return self._principal if hmac.compare_digest(self._digest, candidate) else None
