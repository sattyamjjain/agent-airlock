"""CVE-2026-44211 (Cline Kanban cross-origin WebSocket hijack) regression.

Cline Kanban server (npm ``kanban`` < 2.13.0, CVSS 9.7, CWE-1385 + CWE-306,
published 2026-06): the agent's control WebSocket server on
``127.0.0.1:3484`` accepts every upgrade **without validating the ``Origin``
header**. Because browsers do not apply same-origin/CORS to ``ws://``, any
website the developer visits can open a WebSocket to the loopback control
server and drive the agent (leak workspace data, inject prompts → RCE, kill
tasks). Fixed in 2.13.0 by validating the upgrade ``Origin``.

This suite pins, end-to-end:

- The no-Origin-validation case the brief calls out: a forged-Origin upgrade
  is rejected; an allow-listed Origin passes.
- The static exposure audit (surface a): an endpoint with no Origin
  allow-list is flagged; loopback is not a mitigation.
- The runtime wrapper (surface b): a wrapped handler refuses a forged Origin
  before running and serves an allow-listed one.
- Preset wiring + the bare-str allow-list footgun guard.

Primary sources (retrieved 2026-06-21):
  https://advisories.gitlab.com/npm/cline/CVE-2026-44211/
  https://www.oasis.security/blog/cline-kanban-websocket-hijack
  https://cwe.mitre.org/data/definitions/1385.html
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from agent_airlock import (
    WebSocketOriginDecision,
    WebSocketOriginGuard,
    WebSocketOriginHijackError,
    WebSocketOriginVerdict,
)
from agent_airlock.policy_presets import cline_cve_2026_44211_defaults

CVE = "CVE-2026-44211"
# The Cline agent UI Origin (allow-listed); a drive-by attacker page Origin.
TRUSTED_ORIGIN = "vscode-webview://0ff1ce"
FORGED_ORIGIN = "https://evil.example"


def _guard() -> WebSocketOriginGuard:
    return WebSocketOriginGuard(allowed_origins=[TRUSTED_ORIGIN], advisory=CVE)


# ---------------------------------------------------------------------------
# The brief's core case: no Origin validation
# ---------------------------------------------------------------------------


class TestUpgradeOriginGate:
    def test_forged_origin_rejected(self) -> None:
        d = _guard().check_upgrade(FORGED_ORIGIN)
        assert d.allowed is False
        assert d.verdict is WebSocketOriginVerdict.DENY_FORBIDDEN_ORIGIN
        assert d.matched_origin == FORGED_ORIGIN

    def test_allowlisted_origin_passes(self) -> None:
        d = _guard().check_upgrade(TRUSTED_ORIGIN)
        assert d.allowed is True
        assert d.verdict is WebSocketOriginVerdict.ALLOW_ORIGIN_ALLOWLISTED

    def test_origin_comparison_is_case_insensitive_on_scheme_host(self) -> None:
        # Origin scheme/host are case-insensitive; a trailing slash is ignored.
        d = _guard().check_upgrade("VSCODE-WEBVIEW://0ff1ce/")
        assert d.allowed is True

    def test_missing_origin_header_rejected(self) -> None:
        # A browser always sends Origin; its absence on a control surface is
        # untrusted and rejected by default.
        d = _guard().check_upgrade(None)
        assert d.allowed is False
        assert d.verdict is WebSocketOriginVerdict.DENY_MISSING_ORIGIN_HEADER

    def test_empty_allowlist_rejects_everything(self) -> None:
        guard = WebSocketOriginGuard(advisory=CVE)  # no allow-list
        assert guard.check_upgrade(TRUSTED_ORIGIN).allowed is False

    def test_enforce_raises_on_forged(self) -> None:
        with pytest.raises(WebSocketOriginHijackError) as exc:
            _guard().enforce_upgrade(FORGED_ORIGIN)
        assert exc.value.decision.verdict is WebSocketOriginVerdict.DENY_FORBIDDEN_ORIGIN
        assert any(CVE in h for h in exc.value.fix_hints)

    def test_enforce_passes_on_allowlisted(self) -> None:
        _guard().enforce_upgrade(TRUSTED_ORIGIN)  # no raise


# ---------------------------------------------------------------------------
# Surface (a): static exposure audit — the no-validation misconfiguration
# ---------------------------------------------------------------------------


class TestExposureAudit:
    def test_unguarded_loopback_endpoint_flagged(self) -> None:
        # The exact CVE shape: 127.0.0.1:3484 with no Origin allow-list.
        d = _guard().audit_endpoint(
            host="127.0.0.1", port=3484, scheme="ws", origin_allowlist_enforced=False
        )
        assert d.allowed is False
        assert d.verdict is WebSocketOriginVerdict.DENY_MISSING_ORIGIN_ALLOWLIST
        assert "127.0.0.1" in d.detail
        assert any(CVE in h for h in d.fix_hints)

    def test_guarded_endpoint_passes(self) -> None:
        d = _guard().audit_endpoint(host="127.0.0.1", port=3484, origin_allowlist_enforced=True)
        assert d.allowed is True
        assert d.verdict is WebSocketOriginVerdict.ALLOW


# ---------------------------------------------------------------------------
# Surface (b): runtime wrapper rejects the upgrade before the handler runs
# ---------------------------------------------------------------------------


class TestRuntimeWrapper:
    def test_wrapper_blocks_forged_origin_before_handler(self) -> None:
        served: list[object] = []

        @_guard().wrap_handler
        def handler(request: object) -> str:
            served.append(request)
            return "served"

        class Request:
            def __init__(self, origin: str) -> None:
                self.headers = {"Origin": origin}

        with pytest.raises(WebSocketOriginHijackError):
            handler(Request(FORGED_ORIGIN))
        assert served == [], "handler must not run on a forged Origin"

    def test_wrapper_serves_allowlisted_origin(self) -> None:
        @_guard().wrap_handler
        def handler(request: object) -> str:
            return "served"

        class Request:
            def __init__(self, origin: str) -> None:
                self.headers = {"Origin": origin}

        assert handler(Request(TRUSTED_ORIGIN)) == "served"

    def test_wrapper_extracts_origin_from_asgi_scope(self) -> None:
        # ASGI scope header list of (bytes, bytes) pairs.
        @_guard().wrap_handler
        def app(scope: dict[str, object]) -> str:
            return "ok"

        forged = {"type": "websocket", "headers": [(b"origin", FORGED_ORIGIN.encode())]}
        good = {"type": "websocket", "headers": [(b"origin", TRUSTED_ORIGIN.encode())]}
        with pytest.raises(WebSocketOriginHijackError):
            app(forged)
        assert app(good) == "ok"

    @pytest.mark.asyncio
    async def test_async_wrapper_blocks_forged_origin(self) -> None:
        @_guard().wrap_handler
        async def handler(*, origin: str) -> str:
            return "served"

        with pytest.raises(WebSocketOriginHijackError):
            await handler(origin=FORGED_ORIGIN)
        assert await handler(origin=TRUSTED_ORIGIN) == "served"


# ---------------------------------------------------------------------------
# Preset wiring
# ---------------------------------------------------------------------------


class TestPreset:
    def test_canonical_metadata(self) -> None:
        p = cline_cve_2026_44211_defaults(allowed_origins=[TRUSTED_ORIGIN])
        assert p["preset_id"] == "ws_origin_hijack_guard"
        assert p["severity"] == "critical"
        assert p["default_action"] == "deny"
        assert p["owasp"] == "ASI05"
        assert p["cwe"] == ("CWE-1385", "CWE-306")
        assert p["cves"] == ("CVE-2026-44211",)
        assert isinstance(p["guard"], WebSocketOriginGuard)

    def test_check_raises_on_forged_passes_on_allowlisted(self) -> None:
        p = cline_cve_2026_44211_defaults(allowed_origins=[TRUSTED_ORIGIN])
        assert p["check"](TRUSTED_ORIGIN) is None
        with pytest.raises(WebSocketOriginHijackError) as exc:
            p["check"](FORGED_ORIGIN)
        assert any(CVE in h for h in exc.value.fix_hints)

    def test_bare_str_allowlist_raises(self) -> None:
        with pytest.raises(TypeError, match="bare str"):
            WebSocketOriginGuard(allowed_origins="vscode-webview://x")  # type: ignore[arg-type]

    def test_decision_is_frozen_dataclass(self) -> None:
        d = _guard().check_upgrade(TRUSTED_ORIGIN)
        assert isinstance(d, WebSocketOriginDecision)
        with pytest.raises(FrozenInstanceError):
            d.allowed = False  # type: ignore[misc]
