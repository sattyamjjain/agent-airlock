"""HMAC-SHA256 broadcast signer."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from ..exceptions import AirlockError


class InvalidBroadcastSignature(AirlockError):
    """Raised when a kill-switch broadcast fails signature verification."""


@dataclass(frozen=True)
class HMACBroadcastSigner:
    """Sign / verify kill-switch broadcasts with a shared secret.

    The shared secret must be at least 32 bytes — same minimum we
    enforce for the audit-log signing keys (matches v0.5.7 discipline).
    """

    keyid: str
    key: bytes

    def __post_init__(self) -> None:
        if len(self.key) < 32:
            raise InvalidBroadcastSignature("kill-switch signing key must be at least 32 bytes")

    def sign(self, payload: bytes) -> str:
        """Return the canonical hex MAC for ``payload``."""
        return hmac.new(self.key, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        """Constant-time MAC verification."""
        expected = self.sign(payload)
        return hmac.compare_digest(expected, signature)


__all__ = ["HMACBroadcastSigner", "InvalidBroadcastSignature"]
