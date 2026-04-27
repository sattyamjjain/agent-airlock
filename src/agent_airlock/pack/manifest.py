"""Pack-manifest dataclass + restricted-grammar YAML loader (v0.5.8+)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from ..exceptions import AirlockError


class PackManifestError(AirlockError):
    """Raised on malformed / missing / drift-detected pack manifest."""


@dataclass(frozen=True)
class PresetEntry:
    """One preset reference inside a pack manifest."""

    factory: str
    cve_id: str = ""
    primary_source: str = ""
    enabled: bool = True


@dataclass
class PackManifest:
    """Signed, hash-pinned policy bundle."""

    pack_id: str
    version: str
    description: str
    primary_source: str
    presets: tuple[PresetEntry, ...] = field(default_factory=tuple)


def _coerce(raw: str) -> object:
    raw = raw.strip()
    if not raw or raw == "null":
        return None
    if raw == "true":
        return True
    if raw == "false":
        return False
    if (raw.startswith('"') and raw.endswith('"')) or (raw.startswith("'") and raw.endswith("'")):
        return raw[1:-1]
    if raw.lstrip("-").isdigit():
        return int(raw)
    return raw


def _parse_yaml(text: str) -> dict[str, object]:
    """Subset YAML parser sufficient for pack manifest shape."""
    out: dict[str, object] = {}
    lines = [
        line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")
    ]
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith(" "):
            raise PackManifestError(f"unexpected indent on line {i + 1}: {line!r}")
        if ":" not in line:
            raise PackManifestError(f"missing ':' on line {i + 1}: {line!r}")
        key, _, rest = line.partition(":")
        key = key.strip()
        rest = rest.lstrip()
        if rest:
            out[key] = _coerce(rest)
            i += 1
            continue
        # Block: subsequent lines either ``  - key: val`` (list item) or
        # ``    key: val`` (continuation of current list item).
        items: list[dict[str, object]] = []
        i += 1
        while i < len(lines):
            sub = lines[i]
            if not sub.startswith("  "):
                break
            if sub.lstrip().startswith("- "):
                first = sub.lstrip()[2:]
                k, _, v = first.partition(":")
                items.append({k.strip(): _coerce(v.lstrip())})
                i += 1
                while i < len(lines):
                    nxt = lines[i]
                    if not nxt.startswith("    "):
                        break
                    if nxt.lstrip().startswith("- "):
                        break
                    k2, _, v2 = nxt.lstrip().partition(":")
                    items[-1][k2.strip()] = _coerce(v2.lstrip())
                    i += 1
            else:
                break
        out[key] = items
    return out


def load_manifest(path: Path) -> PackManifest:
    """Load + validate a pack manifest file."""
    if not path.exists():
        raise PackManifestError(f"pack manifest not found: {path}")
    raw = _parse_yaml(path.read_text(encoding="utf-8"))
    for required in ("pack_id", "version", "primary_source", "presets"):
        if required not in raw:
            raise PackManifestError(f"manifest missing required field {required!r}: {path}")
    presets_raw = raw["presets"]
    if not isinstance(presets_raw, list) or not presets_raw:
        raise PackManifestError(f"manifest 'presets' must be a non-empty list: {path}")
    entries: list[PresetEntry] = []
    for p in presets_raw:
        if not isinstance(p, dict):
            raise PackManifestError(f"manifest preset entry must be a dict: {p!r}")
        if "factory" not in p:
            raise PackManifestError(f"manifest preset entry missing 'factory': {p!r}")
        entries.append(
            PresetEntry(
                factory=str(p["factory"]),
                cve_id=str(p.get("cve_id", "")),
                primary_source=str(p.get("primary_source", "")),
                enabled=bool(p.get("enabled", True)),
            )
        )
    return PackManifest(
        pack_id=str(raw["pack_id"]),
        version=str(raw["version"]),
        description=str(raw.get("description", "")),
        primary_source=str(raw["primary_source"]),
        presets=tuple(entries),
    )


def manifest_canonical_bytes(manifest: PackManifest) -> bytes:
    """Stable serialisation for HMAC signing."""
    return json.dumps(
        {
            "pack_id": manifest.pack_id,
            "version": manifest.version,
            "description": manifest.description,
            "primary_source": manifest.primary_source,
            "presets": [
                {
                    "factory": p.factory,
                    "cve_id": p.cve_id,
                    "primary_source": p.primary_source,
                    "enabled": p.enabled,
                }
                for p in manifest.presets
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def manifest_sha256(manifest: PackManifest) -> str:
    return hashlib.sha256(manifest_canonical_bytes(manifest)).hexdigest()


__all__ = [
    "PackManifest",
    "PackManifestError",
    "PresetEntry",
    "load_manifest",
    "manifest_canonical_bytes",
    "manifest_sha256",
]
