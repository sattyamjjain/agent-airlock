"""CVE-2026-11624 (MCP HTTP-transport Origin/Host DNS-rebinding) regression.

Google MCP Toolbox for Databases < 0.25.0 (CWE-346 Origin Validation Error,
CVSS 9.4): the MCP server exposed an HTTP/SSE transport that did **not
validate the ``Origin`` (or ``Host``) header**, so a browser the developer
visits can DNS-rebind to ``127.0.0.1`` and script MCP tool calls at the local
server (file reads, command execution, database access). Fixed in 0.25.0 with
an ``--allowed-hosts`` flag alongside ``--allowed-origins``, warning when
either is left at the ``*`` wildcard.

This suite pins, per the brief:

(a) a forged ``Host`` / ``Origin`` not on the allow-list is denied;
(b) a loopback / allow-listed origin passes;
(c) the startup warning fires when the allow-list is ``*`` or unset.

Primary sources (retrieved 2026-06-21):
  https://nvd.nist.gov/vuln/detail/CVE-2026-11624
  https://github.com/googleapis/mcp-toolbox/issues/3113
"""

from __future__ import annotations

import pytest

from agent_airlock import (
    McpOriginHostGuard,
    McpOriginHostRebindingError,
    McpOriginHostVerdict,
)
from agent_airlock.policy_presets import mcp_origin_host_guard_defaults

CVE = "CVE-2026-11624"
TRUSTED_ORIGIN = "https://app.example.com"
TRUSTED_HOST = "app.example.com"
FORGED_ORIGIN = "https://evil.example"
FORGED_HOST = "evil.example"


def _guard() -> McpOriginHostGuard:
    return McpOriginHostGuard(
        allowed_origins=[TRUSTED_ORIGIN], allowed_hosts=[TRUSTED_HOST], advisory=CVE
    )


# ---------------------------------------------------------------------------
# (a) a forged Host / Origin is denied
# ---------------------------------------------------------------------------


class TestForgedHeadersDenied:
    def test_forged_host_denied(self) -> None:
        d = _guard().check_headers({"Host": FORGED_HOST, "Origin": TRUSTED_ORIGIN})
        assert d.allowed is False
        assert d.verdict is McpOriginHostVerdict.DENY_FORBIDDEN_HOST
        assert d.matched_host == FORGED_HOST

    def test_forged_origin_denied(self) -> None:
        d = _guard().check_headers({"Host": TRUSTED_HOST, "Origin": FORGED_ORIGIN})
        assert d.allowed is False
        assert d.verdict is McpOriginHostVerdict.DENY_FORBIDDEN_ORIGIN
        assert d.matched_origin == FORGED_ORIGIN

    def test_rebinding_browser_request_denied(self) -> None:
        # The canonical DNS-rebinding shape: browser at evil.example whose name
        # now resolves to localhost, so Host is the rebound name.
        d = _guard().check_headers({"Host": FORGED_HOST, "Origin": FORGED_ORIGIN})
        assert d.allowed is False

    def test_validate_raises_with_cve_hint(self) -> None:
        with pytest.raises(McpOriginHostRebindingError) as exc:
            _guard().validate({"Host": FORGED_HOST})
        assert any(CVE in h for h in exc.value.fix_hints)


# ---------------------------------------------------------------------------
# (b) a loopback / allow-listed origin passes
# ---------------------------------------------------------------------------


class TestTrustedRequestsPass:
    def test_allowlisted_host_and_origin_pass(self) -> None:
        d = _guard().check_headers({"Host": TRUSTED_HOST, "Origin": TRUSTED_ORIGIN + "/"})
        assert d.allowed is True
        assert d.verdict is McpOriginHostVerdict.ALLOW_ALLOWLISTED

    def test_loopback_passes_with_no_allowlist(self) -> None:
        guard = McpOriginHostGuard()  # unset -> loopback-only
        for host, origin in [
            ("127.0.0.1:8080", "http://localhost:8080"),
            ("localhost", "http://127.0.0.1"),
            ("[::1]:3000", "http://[::1]:3000"),
        ]:
            d = guard.check_headers({"Host": host, "Origin": origin})
            assert d.allowed is True, f"loopback should pass: {host} / {origin}"
            assert d.verdict is McpOriginHostVerdict.ALLOW_LOOPBACK

    def test_non_browser_client_without_origin_judged_on_host(self) -> None:
        # A non-browser MCP client may omit Origin; it is judged on Host alone.
        guard = McpOriginHostGuard()
        assert guard.check_headers({"Host": "localhost"}).allowed is True
        assert guard.check_headers({"Host": FORGED_HOST}).allowed is False

    def test_case_insensitive_header_lookup(self) -> None:
        d = _guard().check_headers({"host": TRUSTED_HOST, "origin": TRUSTED_ORIGIN})
        assert d.allowed is True


# ---------------------------------------------------------------------------
# (c) the startup warning fires when the allow-list is * or unset
# ---------------------------------------------------------------------------


class TestStartupWarnings:
    def test_unset_allowlists_warn(self) -> None:
        guard = McpOriginHostGuard()
        assert len(guard.startup_warnings) == 2  # origins + hosts
        assert all("loopback" in w or "non-loopback" in w for w in guard.startup_warnings)

    def test_wildcard_warns_and_disables(self) -> None:
        guard = McpOriginHostGuard(allowed_origins=["*"], allowed_hosts=["*"])
        assert guard.origin_wildcard is True
        assert guard.host_wildcard is True
        assert len(guard.startup_warnings) == 2
        assert all("'*'" in w and "DISABLED" in w for w in guard.startup_warnings)
        # Wildcard allows an otherwise-forged request (protection disabled).
        assert guard.check_headers({"Host": FORGED_HOST, "Origin": FORGED_ORIGIN}).allowed is True

    def test_explicit_allowlist_does_not_warn(self) -> None:
        guard = _guard()
        assert guard.startup_warnings == []

    def test_partial_config_warns_only_unset_axis(self) -> None:
        # Hosts configured, origins unset -> exactly one warning (origins).
        guard = McpOriginHostGuard(allowed_hosts=[TRUSTED_HOST])
        assert len(guard.startup_warnings) == 1
        assert "allowed_origins" in guard.startup_warnings[0]


# ---------------------------------------------------------------------------
# Preset wiring + footgun guards
# ---------------------------------------------------------------------------


class TestPreset:
    def test_canonical_metadata(self) -> None:
        p = mcp_origin_host_guard_defaults(allowed_hosts=[TRUSTED_HOST])
        assert p["preset_id"] == "mcp_origin_host_guard"
        assert p["severity"] == "critical"
        assert p["default_action"] == "deny"
        assert p["owasp"] == "MCP07"
        assert p["cwe"] == ("CWE-346",)
        assert p["cves"] == ("CVE-2026-11624",)
        assert isinstance(p["guard"], McpOriginHostGuard)

    def test_check_raises_on_forged_passes_on_trusted(self) -> None:
        p = mcp_origin_host_guard_defaults(
            allowed_hosts=[TRUSTED_HOST], allowed_origins=[TRUSTED_ORIGIN]
        )
        assert p["check"]({"Host": TRUSTED_HOST, "Origin": TRUSTED_ORIGIN}) is None
        with pytest.raises(McpOriginHostRebindingError):
            p["check"]({"Host": FORGED_HOST, "Origin": FORGED_ORIGIN})

    @pytest.mark.parametrize("kw", ["allowed_origins", "allowed_hosts"])
    def test_bare_str_allowlist_raises(self, kw: str) -> None:
        with pytest.raises(TypeError, match="bare str"):
            McpOriginHostGuard(**{kw: "app.example.com"})  # type: ignore[arg-type]
