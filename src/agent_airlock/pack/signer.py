"""Pack-manifest HMAC-SHA256 signing (v0.5.8+).

The signing key is loaded from ``AIRLOCK_PACK_SIGNING_KEY`` (≥ 32 bytes
encoded). For local development tests, callers pass a key explicitly.
"""

from __future__ import annotations

import hashlib
import hmac
import os

from ..exceptions import AirlockError
from .manifest import PackManifest, manifest_canonical_bytes

_KEY_ENV = "AIRLOCK_PACK_SIGNING_KEY"
_KEY_MIN = 32


class PackSignatureError(AirlockError):
    """Signing key missing / too short."""


class PackVerificationError(AirlockError):
    """Stored signature does not verify."""


def _load_key(explicit: bytes | None = None) -> bytes:
    if explicit is not None:
        if len(explicit) < _KEY_MIN:
            raise PackSignatureError(f"signing key shorter than {_KEY_MIN} bytes")
        return explicit
    raw = os.environ.get(_KEY_ENV, "")
    if len(raw) < _KEY_MIN:
        raise PackSignatureError(f"{_KEY_ENV} missing or shorter than {_KEY_MIN} bytes")
    return raw.encode("utf-8")


def sign_manifest(
    manifest: PackManifest,
    *,
    signing_key: bytes | None = None,
) -> str:
    """Return the HMAC-SHA256 hex digest over the canonical manifest bytes."""
    key = _load_key(signing_key)
    return hmac.new(key, manifest_canonical_bytes(manifest), hashlib.sha256).hexdigest()


def verify_manifest(
    manifest: PackManifest,
    signature: str,
    *,
    signing_key: bytes | None = None,
) -> None:
    """Raise :class:`PackVerificationError` on mismatch."""
    expected = sign_manifest(manifest, signing_key=signing_key)
    if not hmac.compare_digest(expected, signature):
        raise PackVerificationError(
            f"pack {manifest.pack_id}@{manifest.version}: signature mismatch"
        )


__all__ = [
    "PackSignatureError",
    "PackVerificationError",
    "sign_manifest",
    "verify_manifest",
]
