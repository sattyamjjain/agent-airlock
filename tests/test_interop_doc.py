"""CI guard: the interop doc's stated MCP revision list matches the code.

``docs/interop/openid-aiim-2026.md`` tells an interop partner which
``MCP-Protocol-Version`` values airlock accepts. That list must equal the set the
wire path actually enforces — ``transport._SUPPORTED_PROTOCOL_VERSIONS``, what
``validate_streamable_http_request`` checks against (post-refactor the same object
as the public ``SUPPORTED_PROTOCOL_VERSIONS``) — and its status labels must match
``SPEC_REVISIONS``, so a partner reading the doc can trust it against the running
code. Same claims-integrity habit as ``tests/test_public_metadata.py`` and
``tests/test_badge_test_count_honesty.py``.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_airlock.mcp_spec import SPEC_REVISIONS
from agent_airlock.mcp_spec.transport import (
    _SUPPORTED_PROTOCOL_VERSIONS as _WIRE_SUPPORTED_VERSIONS,
)

_INTEROP_DIR = Path(__file__).resolve().parents[1] / "docs" / "interop"
_DOC = _INTEROP_DIR / "openid-aiim-2026.md"
_SCOPE = _INTEROP_DIR / "CONFORMANCE-SCOPE.md"

# The revision table rows: | `YYYY-MM-DD` | status |
_ROW = re.compile(r"^\|\s*`(\d{4}-\d{2}-\d{2})`\s*\|\s*(\w+)\s*\|", re.MULTILINE)


def _doc_rows() -> list[tuple[str, str]]:
    return _ROW.findall(_DOC.read_text(encoding="utf-8"))


def test_interop_doc_and_scope_exist() -> None:
    assert _DOC.is_file(), f"interop doc not found at {_DOC}"
    assert _SCOPE.is_file(), f"conformance-scope doc not found at {_SCOPE}"


def test_doc_revision_list_matches_the_wire_enforced_versions() -> None:
    # Bind to the value validate_streamable_http_request actually enforces on the
    # wire (transport's imported set), not a second copy that could drift from it.
    doc_versions = tuple(v for v, _ in _doc_rows())
    assert doc_versions == _WIRE_SUPPORTED_VERSIONS, (
        f"interop doc revision table {doc_versions} != the versions the wire path "
        f"enforces {_WIRE_SUPPORTED_VERSIONS} — regenerate the doc from the code"
    )


def test_doc_revision_labels_match_spec_revisions() -> None:
    rows = _doc_rows()
    assert rows, "interop doc has no parseable revision table"
    for version, label in rows:
        assert SPEC_REVISIONS.get(version) == label, (
            f"interop doc labels {version} as {label!r} but SPEC_REVISIONS says "
            f"{SPEC_REVISIONS.get(version)!r}"
        )


def test_conformance_scope_keeps_the_no_claim_position() -> None:
    scope = _SCOPE.read_text(encoding="utf-8").lower()
    assert "no conformance claim" in scope or "no mcp conformance suite has been run" in scope, (
        "CONFORMANCE-SCOPE.md dropped the no-conformance-claim position"
    )
    assert "conformant" in scope, "scope doc should state the claim strength is never 'conformant'"
