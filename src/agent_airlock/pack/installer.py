"""Pack installer — resolves every named preset factory (v0.5.8+)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

from .manifest import PackManifest, PackManifestError

logger = structlog.get_logger("agent-airlock.pack.installer")

# Where shipped packs live inside the package.
SHIPPED_PACKS_ROOT = Path(__file__).resolve().parent.parent / "packs"


@dataclass
class InstalledPack:
    """The output of :meth:`PackInstaller.install` — every resolved preset."""

    manifest: PackManifest
    composed: dict[str, Any] = field(default_factory=dict)


class PackInstaller:
    """Resolve every preset named in a manifest against ``policy_presets``.

    Disabled entries are skipped. Factories with required arguments
    are skipped with a warning (the caller can rebuild them by hand).
    """

    def install(self, manifest: PackManifest) -> InstalledPack:
        from .. import policy_presets  # late import to avoid cycle

        composed: dict[str, Any] = {}
        for entry in manifest.presets:
            if not entry.enabled:
                continue
            factory = getattr(policy_presets, entry.factory, None)
            if factory is None:
                raise PackManifestError(
                    f"unknown factory {entry.factory!r} in pack "
                    f"{manifest.pack_id}@{manifest.version}"
                )
            try:
                composed[entry.factory] = factory()
            except TypeError:
                logger.warning(
                    "pack_factory_skipped_needs_args",
                    factory=entry.factory,
                    pack_id=manifest.pack_id,
                )
        logger.info(
            "pack_installed",
            pack_id=manifest.pack_id,
            version=manifest.version,
            preset_count=len(composed),
        )
        return InstalledPack(manifest=manifest, composed=composed)


def discover_shipped_packs() -> list[Path]:
    """Return the manifest paths of every pack shipped with the wheel."""
    if not SHIPPED_PACKS_ROOT.exists():
        return []
    out: list[Path] = []
    for sub in sorted(SHIPPED_PACKS_ROOT.iterdir()):
        if not sub.is_dir():
            continue
        manifest = sub / "manifest.yaml"
        if manifest.exists():
            out.append(manifest)
    return out


def find_shipped_pack(pack_id: str) -> Path | None:
    """Return the manifest path for a shipped pack, or None."""
    candidate = SHIPPED_PACKS_ROOT / pack_id / "manifest.yaml"
    if candidate.exists():
        return candidate
    return None


__all__ = [
    "InstalledPack",
    "PackInstaller",
    "SHIPPED_PACKS_ROOT",
    "discover_shipped_packs",
    "find_shipped_pack",
]
