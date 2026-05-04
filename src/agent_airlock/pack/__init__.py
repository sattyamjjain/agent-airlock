"""``airlock pack``: signed, hash-pinned policy bundles (v0.5.8+).

Operators don't want to hand-wire 6 presets to harden one CI agent.
A pack is a signed manifest that names a set of preset factories +
version pins + a SHA-256 of the manifest itself. ``airlock pack
install <pack>@<version>`` resolves and configures every preset in
one command.

Surfaces
--------
- :class:`PackManifest` — typed manifest from a YAML file.
- :func:`load_manifest` — parse + validate.
- :func:`sign_manifest` — HMAC-SHA256 with a configured key.
- :func:`verify_manifest` — round-trip check, refuse on mismatch.
- :class:`PackInstaller` — resolve every named preset and return
  the configured chain.

CLI: ``airlock.cli.pack``.
"""

from __future__ import annotations

from .installer import InstalledPack, PackInstaller
from .lock import (
    LOCK_SCHEMA_VERSION,
    LockEntry,
    LockfileDriftError,
    LockfileFormatError,
    PolicyBundleLock,
    build_lock,
    hash_preset,
    parse_lock,
    read_lock,
    render_lock,
    verify_lock,
    write_lock,
)
from .manifest import PackManifest, load_manifest
from .signer import (
    PackSignatureError,
    PackVerificationError,
    sign_manifest,
    verify_manifest,
)

__all__ = [
    "InstalledPack",
    "LOCK_SCHEMA_VERSION",
    "LockEntry",
    "LockfileDriftError",
    "LockfileFormatError",
    "PackInstaller",
    "PackManifest",
    "PackSignatureError",
    "PackVerificationError",
    "PolicyBundleLock",
    "build_lock",
    "hash_preset",
    "load_manifest",
    "parse_lock",
    "read_lock",
    "render_lock",
    "sign_manifest",
    "verify_lock",
    "verify_manifest",
    "write_lock",
]
