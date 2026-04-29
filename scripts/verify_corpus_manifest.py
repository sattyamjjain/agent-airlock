#!/usr/bin/env python3
"""Verify wild_payload_corpus/2026-04/MANIFEST.sha256 (Issue #3, v0.6.0+).

Walks every entry in MANIFEST.sha256 and re-hashes the referenced
file. Exits 0 on full match, 1 on any drift. Used by ``make
verify-corpus`` and a test in ``tests/corpus/test_manifest.py``.
"""

from __future__ import annotations

import hashlib
import pathlib
import sys


def main() -> int:
    root = pathlib.Path(
        "src/agent_airlock/corpus/wild_payload_corpus/2026-04"
    ).resolve()
    if not root.is_dir():
        # The script is also runnable from inside the 2026-04 dir.
        if pathlib.Path("MANIFEST.sha256").exists():
            root = pathlib.Path.cwd()
        else:
            print(f"corpus root not found: {root}", file=sys.stderr)
            return 2

    manifest = root / "MANIFEST.sha256"
    if not manifest.exists():
        print(f"manifest not found: {manifest}", file=sys.stderr)
        return 2

    errors = 0
    seen = 0
    for line in manifest.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        digest, _, rel = line.partition("  ")
        if not digest or not rel:
            print(f"unparseable manifest line: {line!r}", file=sys.stderr)
            errors += 1
            continue
        target = root / rel.strip()
        if not target.exists():
            print(f"DRIFT: {rel} missing on disk", file=sys.stderr)
            errors += 1
            continue
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        seen += 1
        if actual != digest:
            print(
                f"DRIFT: {rel} expected={digest[:12]} actual={actual[:12]}",
                file=sys.stderr,
            )
            errors += 1
    if errors:
        return 1
    print(f"OK: {seen} entries match MANIFEST.sha256")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
