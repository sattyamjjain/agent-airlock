"""Tests for CVE-2026-41361 OpenClaw IPv6 SSRF guard bypass (v0.5.5+).

Primary source (cited per v0.5.1+ convention):
- <https://www.redpacketsecurity.com/cve-alert-cve-2026-41361-openclaw-openclaw/>
  (CVSS 7.1, disclosed 2026-04-23).

The bypass was that OpenClaw's IPv6 guard covered only the four
canonical ranges (``::/128``, ``::1/128``, ``fe80::/10``, ``fc00::/7``)
and left IPv4-mapped / NAT64 / 6to4 / documentation ranges routable.
Attackers used ``::ffff:169.254.169.254`` to reach AWS IMDS through
the bypass. These tests exercise all eight ranges explicitly.
"""

from __future__ import annotations

import pytest

from agent_airlock.network import _is_private_ip, is_blocked_ipv6_range
from agent_airlock.policy_presets import (
    openclaw_cve_2026_41361_ipv6_ssrf_defaults,
)


class TestPublicRoutableBaseline:
    """A genuinely public IPv6 address must NOT be blocked.

    Baseline that proves the guard doesn't false-positive every v6.
    """

    def test_public_google_dns_ipv6_is_allowed(self) -> None:
        # 2001:4860:4860::8888 — Google Public DNS IPv6
        assert is_blocked_ipv6_range("2001:4860:4860::8888") is False

    def test_ipv4_is_not_flagged_by_ipv6_guard(self) -> None:
        """is_blocked_ipv6_range is IPv6-only; IPv4 falls through."""
        assert is_blocked_ipv6_range("8.8.8.8") is False

    def test_garbage_input_is_not_flagged(self) -> None:
        assert is_blocked_ipv6_range("not-an-ip") is False


class TestBlockedRanges:
    """One positive case per range — all eight must fire."""

    @pytest.mark.parametrize(
        ("addr", "range_name"),
        [
            ("::", "all-zeros"),
            ("::1", "IPv6 loopback"),
            ("fe80::1", "IPv6 link-local"),
            ("fc00::1", "IPv6 ULA"),
            ("2001:db8::1", "IPv6 documentation"),
            ("::ffff:169.254.169.254", "IPv4-mapped IMDS"),
            ("64:ff9b::c0a8:101", "NAT64 wrapping 192.168.1.1"),
            ("2002:c0a8:101::", "6to4 wrapping 192.168.1.1"),
        ],
    )
    def test_blocked_range(self, addr: str, range_name: str) -> None:
        assert is_blocked_ipv6_range(addr) is True, (
            f"{addr!r} ({range_name}) must be blocked by CVE-2026-41361 guard"
        )


class TestNegativeEdgePerRange:
    """A close-but-not-inside IPv6 address per range must NOT be blocked.

    Guards against a regression where somebody widens a prefix by accident.
    """

    def test_just_outside_link_local(self) -> None:
        # fec0::1 is site-local (deprecated, RFC 3879), NOT in fe80::/10
        assert is_blocked_ipv6_range("fec0::1") is False

    def test_just_outside_documentation(self) -> None:
        # 2001:db9:: is outside 2001:db8::/32
        assert is_blocked_ipv6_range("2001:db9::1") is False


class TestIntegrationWithPrivateIpCheck:
    """The existing ``_is_private_ip`` rolls up the IPv6 guard."""

    def test_ipv4_mapped_imds_is_private_ip(self) -> None:
        """This is the exact CVE-2026-41361 payload."""
        assert _is_private_ip("::ffff:169.254.169.254") is True

    def test_6to4_wrapping_rfc1918_is_private_ip(self) -> None:
        assert _is_private_ip("2002:c0a8:101::") is True


class TestPresetRoundTrip:
    """``openclaw_cve_2026_41361_ipv6_ssrf_defaults`` wiring."""

    def test_preset_exports_callable(self) -> None:
        cfg = openclaw_cve_2026_41361_ipv6_ssrf_defaults()
        assert callable(cfg["is_blocked"])
        assert cfg["is_blocked"]("::1") is True
        assert cfg["is_blocked"]("2001:4860:4860::8888") is False

    def test_preset_exports_all_eight_ranges(self) -> None:
        cfg = openclaw_cve_2026_41361_ipv6_ssrf_defaults()
        networks = cfg["networks"]
        assert len(networks) == 8
        # Sanity: each entry is (cidr, reason) string tuple
        for cidr, reason in networks:
            assert isinstance(cidr, str)
            assert isinstance(reason, str)
