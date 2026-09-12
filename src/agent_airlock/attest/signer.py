"""Pluggable signers for v0.5.8 attestation envelopes.

Three implementations ship today:

- :class:`FileSigner` — key bytes from a path on disk.
- :class:`EnvSigner` — key bytes from an environment variable.
- :class:`KMSStubSigner` — placeholder. A real KMS / Sigstore Fulcio
  signer is **still not implemented**. This said "lands in v0.5.9
  (issue #75)"; we are past v0.9.0 and issue #75 does not exist, so
  that was a date and a tracker neither of which was real.

All three sign with HMAC-SHA256, which stays replaceable by swapping
the ``sign`` body without changing the :class:`Signer` protocol or
envelope shape — that is why no release is named here: the swap does
not need one, and naming a version that passes without the work being
done is how the old claim went stale.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


class Signer(Protocol):
    keyid: str

    def sign(self, payload: bytes) -> str: ...

    def verify(self, payload: bytes, signature: str) -> bool: ...


@dataclass
class FileSigner:
    """Read the signing key from a file. Useful for local tests / dev."""

    keyid: str
    key_path: Path

    def _key(self) -> bytes:
        return self.key_path.read_bytes()

    def sign(self, payload: bytes) -> str:
        return hmac.new(self._key(), payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


@dataclass
class EnvSigner:
    """Read the signing key from an environment variable."""

    keyid: str
    env_var: str = "AIRLOCK_ATTEST_SIGNING_KEY"

    def _key(self) -> bytes:
        raw = os.environ.get(self.env_var, "")
        if not raw:
            raise RuntimeError(f"signing key env {self.env_var!r} not set")
        return raw.encode("utf-8")

    def sign(self, payload: bytes) -> str:
        return hmac.new(self._key(), payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


@dataclass
class KMSStubSigner:
    """Placeholder for AWS / GCP KMS / Sigstore Fulcio. **Not implemented.**

    Uses HMAC-SHA256 with a dev-only key so the envelope shape, CLI, and
    ``verify_envelope`` flow can be exercised end-to-end. It is not a KMS
    signer and does not become one by being installed.

    Production deployments must substitute their own :class:`Signer`. This
    docstring previously pointed at a "v0.5.9 KMS adapter"; that release
    shipped long ago without it, so there is no version to wait for.
    """

    keyid: str = "kms-stub"
    dev_only_key: bytes = b"do-not-use-in-prod-this-is-a-dev-only-stub-key"

    def sign(self, payload: bytes) -> str:
        return hmac.new(self.dev_only_key, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


__all__ = ["EnvSigner", "FileSigner", "KMSStubSigner", "Signer"]
