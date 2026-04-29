"""Versioned, hash-pinned indirect-prompt-injection payload corpora (v0.5.8+).

Each corpus is a directory of YAML files (one payload per file) with
``payload``, ``source``, ``sha256``, and ``expected_verdict``. Operators
run the corpus through their installed guard chain via the ``airlock
replay`` CLI; PR review on a guard change must keep every payload
blocked.

The first corpus, ``wild-2026-04``, curates the 10 indirect-prompt-
injection payloads catalogued by [Help Net Security
2026-04-24](https://www.helpnetsecurity.com/2026/04/24/indirect-prompt-injection-in-the-wild/).

Drift policy: payload SHA-256s are pinned. A weekly CI job flags any
upstream advisory that edits its PoC; the corpus does **not**
auto-update.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from ..exceptions import AirlockError

CORPUS_ROOT = Path(__file__).resolve().parent / "wild_payload_corpus"


class CorpusError(AirlockError):
    """Raised when a corpus file is malformed or its hash mismatches."""


@dataclass(frozen=True)
class CorpusEntry:
    """One indirect-prompt-injection payload."""

    id: str
    payload: str
    source: str
    sha256: str
    expected_verdict: Literal["block", "warn", "allow"]
    description: str = ""
    namespace: str = ""
    """Namespace tag for filtering (e.g. ``"short_form_video"``).

    Empty string means the payload belongs to the corpus root.
    """
    provisional: bool = False
    """``True`` for payloads reconstructed from a talk abstract before
    the official slide deck was posted. Refresh once the artefact is
    public; do not auto-promote."""


@dataclass
class Corpus:
    """A versioned + hash-pinned payload set."""

    name: str
    entries: tuple[CorpusEntry, ...] = field(default_factory=tuple)


# -----------------------------------------------------------------------------
# Restricted-grammar YAML parser (v0.5.7 preset_loader pattern)
# -----------------------------------------------------------------------------
#
# Each corpus YAML is exactly five top-level keys:
#   id: <string>
#   payload: <string, possibly multi-line via |-block or quoted>
#   source: <url string>
#   sha256: <hex string>
#   expected_verdict: <"block" | "warn" | "allow">
# Plus an optional ``description: <string>``.
#
# We reuse ``preset_loader._parse_yaml_restricted`` would be ideal,
# but corpora need block-scalar (``payload: |``) support that the
# preset parser doesn't have. So we hand-parse here with a small
# extension.


def _parse_corpus_file(path: Path) -> CorpusEntry:
    """Parse one corpus YAML file."""
    text = path.read_text(encoding="utf-8")
    fields: dict[str, str] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        if ":" not in line:
            raise CorpusError(f"{path}: unparseable line {i + 1}: {line!r}")
        key, _, rest = line.partition(":")
        key = key.strip()
        rest = rest.lstrip()

        if rest == "|":
            # Block scalar: subsequent indented lines until dedent.
            i += 1
            buf: list[str] = []
            while i < len(lines):
                nxt = lines[i]
                if nxt.startswith("  "):
                    buf.append(nxt[2:])
                    i += 1
                elif nxt.strip() == "":
                    buf.append("")
                    i += 1
                else:
                    break
            fields[key] = "\n".join(buf).rstrip("\n")
        else:
            value = rest
            if (
                value.startswith('"')
                and value.endswith('"')
                and len(value) >= 2
                or value.startswith("'")
                and value.endswith("'")
                and len(value) >= 2
            ):
                value = value[1:-1]
            fields[key] = value
            i += 1

    for required in ("id", "payload", "source", "sha256", "expected_verdict"):
        if required not in fields:
            raise CorpusError(f"{path}: missing required key {required!r}")

    actual_sha = hashlib.sha256(fields["payload"].encode("utf-8")).hexdigest()
    if actual_sha != fields["sha256"]:
        raise CorpusError(
            f"{path}: sha256 mismatch — pinned={fields['sha256']!r} "
            f"actual={actual_sha!r}. Drift detected; do NOT auto-update."
        )

    verdict = fields["expected_verdict"].strip()
    if verdict not in {"block", "warn", "allow"}:
        raise CorpusError(
            f"{path}: expected_verdict must be one of block/warn/allow, got {verdict!r}"
        )

    namespace = fields.get("namespace", "").strip()
    provisional_raw = fields.get("provisional", "false").strip().lower()
    provisional = provisional_raw in {"true", "1", "yes"}

    return CorpusEntry(
        id=fields["id"].strip(),
        payload=fields["payload"],
        source=fields["source"].strip(),
        sha256=fields["sha256"].strip(),
        expected_verdict=verdict,  # type: ignore[arg-type]
        description=fields.get("description", "").strip(),
        namespace=namespace,
        provisional=provisional,
    )


def load_corpus(name: str, *, namespace: str | None = None) -> Corpus:
    """Load a named corpus (e.g. ``"wild-2026-04"``).

    Args:
        name: Corpus name. Must match a subdirectory under
            ``CORPUS_ROOT``. The current shipped corpus is
            ``"wild-2026-04"``.
        namespace: Optional namespace filter. When supplied, only
            entries whose ``namespace`` field matches are returned.
            Namespaced entries also live in the corresponding
            subdirectory (e.g. ``2026-04/short_form_video/``) so the
            filter is both file-tree and metadata aware.

    Raises:
        CorpusError: Unknown corpus, malformed file, or SHA-256
            mismatch on any payload.
    """
    # ``wild-2026-04`` lives in ``wild_payload_corpus/2026-04``
    sub = CORPUS_ROOT / "2026-04" if name == "wild-2026-04" else CORPUS_ROOT / name
    if not sub.is_dir():
        raise CorpusError(f"unknown corpus: {name!r} (expected dir at {sub})")
    entries: list[CorpusEntry] = []
    if namespace is None:
        # Default: only root-level YAMLs (backward-compat). Subdirs
        # belong to namespaces that the caller must opt into.
        for f in sorted(sub.glob("*.yaml")):
            entries.append(_parse_corpus_file(f))
    else:
        ns_dir = sub / namespace
        if not ns_dir.is_dir():
            raise CorpusError(
                f"corpus {name!r}: namespace {namespace!r} not found "
                f"(expected dir at {ns_dir})"
            )
        for f in sorted(ns_dir.glob("*.yaml")):
            parsed = _parse_corpus_file(f)
            # The on-disk subdir is the source of truth for the
            # namespace tag — fall back when the YAML omits it.
            if not parsed.namespace:
                parsed = CorpusEntry(
                    id=parsed.id,
                    payload=parsed.payload,
                    source=parsed.source,
                    sha256=parsed.sha256,
                    expected_verdict=parsed.expected_verdict,
                    description=parsed.description,
                    namespace=namespace,
                    provisional=parsed.provisional,
                )
            if parsed.namespace == namespace:
                entries.append(parsed)
    if not entries:
        raise CorpusError(
            f"corpus {name!r} (namespace={namespace!r}) is empty"
        )
    corpus_name = f"{name}/{namespace}" if namespace else name
    return Corpus(name=corpus_name, entries=tuple(entries))


def list_namespaces(name: str) -> tuple[str, ...]:
    """Return every distinct ``namespace`` present in the corpus.

    A namespace is any subdirectory that contains at least one
    ``*.yaml`` file; namespace tag inside the file is informational
    but the subdir name is the canonical id.
    """
    sub = CORPUS_ROOT / "2026-04" if name == "wild-2026-04" else CORPUS_ROOT / name
    if not sub.is_dir():
        return ()
    out: list[str] = []
    for p in sorted(sub.iterdir()):
        if p.is_dir() and any(p.glob("*.yaml")):
            out.append(p.name)
    return tuple(out)


__all__ = [
    "Corpus",
    "CorpusEntry",
    "CorpusError",
    "CORPUS_ROOT",
    "list_namespaces",
    "load_corpus",
]
