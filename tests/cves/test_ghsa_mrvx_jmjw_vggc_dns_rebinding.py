"""GHSA-mrvx-jmjw-vggc (SafeURL DNS-rebinding SSRF) regression.

SearXNG MCP Server (High, disclosed 2026-06-19): ``assertUrlAllowed()`` validated
only the **syntactic** hostname string against a private-IP/host blocklist,
**without resolving DNS**. An attacker-controlled domain resolving to a
private/loopback IP (wildcard DNS like ``nip.io``, or a custom record) passes the
string check; the server then reads arbitrary internal HTTP services — SSRF via
DNS rebinding.

agent-airlock's ``SafeURLValidator(dns_rebinding_guard=True)`` closes the gap by
resolving the host at call time and re-validating every resolved A/AAAA address.

The required regression: a wildcard-DNS host whose *string* passes the syntactic
allowlist but which **resolves** to 127.0.0.1 / 169.254.169.254 is BLOCKED
post-resolution.

Primary source (retrieved 2026-06-21):
  https://github.com/advisories/GHSA-mrvx-jmjw-vggc
"""

from __future__ import annotations

import pytest

from agent_airlock.policy_presets import dns_rebinding_safe_url_defaults
from agent_airlock.safe_types import SafeURLValidationError, SafeURLValidator

GHSA = "GHSA-mrvx-jmjw-vggc"
# A hostname whose STRING form is innocuous and passes the syntactic allowlist.
REBINDING_HOST = "https://internal-app.attacker-controlled.example/admin"


def _validator(resolves_to: list[str], **kw: object) -> SafeURLValidator:
    return SafeURLValidator(
        allowed_schemes=["http", "https"],
        dns_rebinding_guard=True,
        resolver=lambda _h: resolves_to,
        **kw,  # type: ignore[arg-type]
    )


class TestDnsRebindingBlockedPostResolution:
    @pytest.mark.parametrize(
        ("resolved_ip", "label"),
        [
            ("127.0.0.1", "loopback"),
            ("169.254.169.254", "metadata"),
            ("10.0.0.5", "rfc1918-10"),
            ("172.16.0.1", "rfc1918-172"),
            ("192.168.1.1", "rfc1918-192"),
            ("::1", "ipv6-loopback"),
            ("fc00::1", "ipv6-ula"),
            ("fe80::1", "ipv6-link-local"),
            ("::ffff:169.254.169.254", "ipv6-mapped-metadata"),
        ],
    )
    def test_host_passing_syntactic_allowlist_blocked_after_resolution(
        self, resolved_ip: str, label: str
    ) -> None:
        # The hostname string passes the syntactic checks (it is not a literal
        # private IP, not localhost, not in the blocklist) — proving the block
        # comes from POST-RESOLUTION re-validation, not the string check.
        v = _validator([resolved_ip])
        with pytest.raises(SafeURLValidationError) as exc:
            v(REBINDING_HOST)
        assert exc.value.reason == "dns_rebinding"
        assert resolved_ip in str(exc.value)

    def test_syntactic_check_alone_would_have_passed(self) -> None:
        # With the guard OFF (the pre-fix behaviour), the same wildcard host
        # whose string is innocuous passes — this is exactly the GHSA gap.
        unguarded = SafeURLValidator(
            allowed_schemes=["http", "https"],
            resolver=lambda _h: ["127.0.0.1"],  # never consulted when guard off
        )
        assert unguarded(REBINDING_HOST) == REBINDING_HOST

    def test_multiple_records_blocks_if_any_is_internal(self) -> None:
        # A/AAAA round-robin: one public, one loopback → must block.
        v = _validator(["93.184.216.34", "127.0.0.1"])
        with pytest.raises(SafeURLValidationError):
            v(REBINDING_HOST)

    def test_unresolvable_host_fails_closed(self) -> None:
        v = SafeURLValidator(
            allowed_schemes=["http", "https"],
            dns_rebinding_guard=True,
            resolver=lambda _h: (_ for _ in ()).throw(OSError("nxdomain")),
        )
        with pytest.raises(SafeURLValidationError) as exc:
            v("https://nope.invalid/")
        assert exc.value.reason == "dns_rebinding"


class TestLegitimateHostsPass:
    def test_public_resolution_passes(self) -> None:
        v = _validator(["93.184.216.34"])
        assert v("https://example.com/data") == "https://example.com/data"

    def test_literal_public_ip_not_resolved(self) -> None:
        # A literal public IP needs no resolution and passes.
        v = SafeURLValidator(
            allowed_schemes=["http", "https"],
            dns_rebinding_guard=True,
            resolver=lambda _h: ["127.0.0.1"],  # must NOT be consulted
        )
        assert v("https://93.184.216.34/") == "https://93.184.216.34/"

    def test_guard_off_is_backward_compatible(self) -> None:
        # Default (guard off) preserves prior behaviour: no resolution happens.
        v = SafeURLValidator(allowed_schemes=["http", "https"])
        assert v("https://example.com/") == "https://example.com/"


class TestResolveAndPin:
    def test_pin_returns_validated_url_and_pinned_ips(self) -> None:
        v = _validator(["93.184.216.34"])
        url, pinned = v.resolve_and_pin("https://example.com/")
        assert url == "https://example.com/"
        assert pinned == ["93.184.216.34"]

    def test_pin_blocks_rebinding(self) -> None:
        v = _validator(["127.0.0.1"])
        with pytest.raises(SafeURLValidationError):
            v.resolve_and_pin(REBINDING_HOST)

    def test_pin_literal_ip_returns_itself(self) -> None:
        v = _validator(["10.0.0.1"])  # resolver unused for a literal
        url, pinned = v.resolve_and_pin("https://93.184.216.34/")
        assert pinned == ["93.184.216.34"]


class TestPreset:
    def test_canonical_metadata(self) -> None:
        p = dns_rebinding_safe_url_defaults()
        assert p["preset_id"] == "dns_rebinding_safe_url"
        assert p["severity"] == "high"
        assert p["default_action"] == "deny"
        assert p["owasp"] == "MCP06"
        assert p["ghsa"] == (GHSA,)
        assert isinstance(p["guard"], SafeURLValidator)

    def test_preset_guard_has_rebinding_on_by_default(self) -> None:
        assert dns_rebinding_safe_url_defaults()["guard"].dns_rebinding_guard is True

    def test_preset_check_blocks_internal_resolution(self) -> None:
        # Build a preset, then point its guard's resolver at loopback.
        p = dns_rebinding_safe_url_defaults()
        p["guard"]._resolver = lambda _h: ["127.0.0.1"]  # type: ignore[attr-defined]
        with pytest.raises(SafeURLValidationError):
            p["check"](REBINDING_HOST)
