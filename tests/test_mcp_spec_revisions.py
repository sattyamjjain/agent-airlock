"""Guard: MCP spec-revision provenance stays honest (ratified vs release candidate).

agent-airlock's mcp_spec guards target two MCP revisions. This pins the honest
statement of which is which so the module docstring, the ``SPEC_REVISIONS``
constant, and the README caveat cannot drift into an accidental conformance claim:

* the negotiated ``MCP-Protocol-Version`` stays the RATIFIED ``2025-11-25`` (verified
  2026-07-28: ``/specification/latest`` 307-redirects to ``/specification/2025-11-25``);
* ``2026-07-28`` is recorded as a release candidate (release tag ``2026-07-28-RC``,
  ``prerelease: true``, published 2026-05-29);
* the README says the 2026-07-28 guards are forward-compatible hardening, not a
  conformance claim.
"""

from __future__ import annotations

from pathlib import Path

from agent_airlock.mcp_spec import PROTOCOL_VERSION, SPEC_REVISIONS

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"


def test_protocol_version_is_the_ratified_revision() -> None:
    # The MCP-Protocol-Version header value MUST stay the ratified revision, never a
    # release candidate.
    assert PROTOCOL_VERSION == "2025-11-25"


def test_spec_revisions_records_status() -> None:
    assert SPEC_REVISIONS["2025-11-25"] == "ratified"
    assert SPEC_REVISIONS["2026-07-28"] == "release-candidate"


def test_readme_flags_2026_07_28_as_release_candidate() -> None:
    text = README.read_text(encoding="utf-8")
    # Stable phrases from the caveat above the OWASP MCP Top-10 table — if the README
    # drops the caveat, this fails alongside the docstring/constant it mirrors.
    assert "not a conformance claim" in text, "README lost the RC caveat"
    assert "negotiated protocol version remains" in text, "README lost the RC caveat"
