"""IPv6 site-local ``fec0::/10`` is internal to every egress check (CVE-2026-134492).

mcp-server-fetch from 2026.10.10 and before 2026.11.11 treated ``fec0::/10`` as public, so
its SSRF check let a request reach a site-local host (CWE-918; NVD 2026-11-23). Python's
``ipaddress`` marks the range ``is_site_local`` but neither private nor reserved, so a check
built on ``is_private`` admits it.

https://nvd.nist.gov/vuln/detail/CVE-2026-134492
https://github.com/advisories/GHSA-w65g-fgjf-hh6q

On 881b66ce ``SSRFEgressGuard().check_url`` allowed the three URLs below and
``network._is_private_ip("fec0::1")`` was False; 0.10.36 fixed both. On 099fcef0
``SafeURLValidator`` still admitted ``https://[fec0::1]/`` and a host its resolver answered
with ``fec0::1``, and the LAN guard read a ``fec0::1`` bind as not on the LAN: fixed here.

``is_blocked_ipv6_range`` stays the CVE-2026-41361 set, whose signed fixture pins
``fec0::1`` outside it; every caller checks ``is_site_local`` beside it. No test opens a
socket: resolvers are stubs.
"""

from __future__ import annotations

import pytest

from agent_airlock.mcp_spec.lan_unauth_rce_guard import _is_lan_bound
from agent_airlock.network import _is_private_ip
from agent_airlock.safe_types import (
    SafeURLValidationError,
    SafeURLValidator,
    _resolved_ip_is_internal,
)
from agent_airlock.ssrf_egress_guard import SSRFEgressGuard, SSRFEgressVerdict

V = SSRFEgressVerdict
SITE_LOCAL_URLS = (
    "http://[fec0::1]/",
    "http://[fec0::a:b]:8080/admin",
    "http://[feff:ffff::1]/",
)
SCHEMES = ["http", "https"]


class TestTheSsrfEgressGuard:
    @pytest.mark.parametrize("url", SITE_LOCAL_URLS)
    def test_each_site_local_url_is_refused(self, url: str) -> None:
        decision = SSRFEgressGuard().check_url(url)
        assert decision.verdict is V.DENY_IPV6_INTERNAL
        assert any("site-local" in line for line in decision.explain), decision.explain

    def test_a_name_resolving_to_it_is_refused(self) -> None:
        guard = SSRFEgressGuard(resolver=lambda host: ["fec0::1"])
        assert guard.check_url("http://intranet.example/").verdict is V.DENY_IPV6_INTERNAL

    @pytest.mark.parametrize(
        ("url", "verdict"),
        [
            ("http://[2606:4700::1]/", V.ALLOW),
            ("http://[fd00::1]/", V.DENY_IPV6_INTERNAL),
            ("http://[fe80::1]/", V.DENY_LINK_LOCAL),
        ],
    )
    def test_the_controls_keep_their_verdicts(self, url: str, verdict: SSRFEgressVerdict) -> None:
        assert SSRFEgressGuard().check_url(url).verdict is verdict


class TestTheOtherChecks:
    @pytest.mark.parametrize("address", ["fec0::1", "fec0::a:b", "feff:ffff::1"])
    def test_network_policy_reads_it_as_private(self, address: str) -> None:
        assert _is_private_ip(address) is True

    def test_network_policy_leaves_a_public_address_alone(self) -> None:
        assert _is_private_ip("2606:4700::1") is False

    def test_the_lan_guard_reads_a_site_local_bind_as_lan(self) -> None:
        assert _is_lan_bound("fec0::1") is True
        assert _is_lan_bound("[fec0::1]") is True
        assert _is_lan_bound("2606:4700::1") is False


class TestSafeUrl:
    @pytest.mark.parametrize("url", ["https://[fec0::1]/", "https://[feff:ffff::1]/x"])
    def test_a_site_local_literal_is_refused(self, url: str) -> None:
        with pytest.raises(SafeURLValidationError) as raised:
            SafeURLValidator(allowed_schemes=SCHEMES)(url)
        assert raised.value.reason == "private_ip"

    def test_a_host_resolving_to_it_is_refused(self) -> None:
        validator = SafeURLValidator(
            allowed_schemes=SCHEMES, dns_rebinding_guard=True, resolver=lambda host: ["fec0::1"]
        )
        with pytest.raises(SafeURLValidationError) as raised:
            validator("https://rebind.example/")
        assert raised.value.reason == "dns_rebinding"
        assert "site-local" in str(raised.value)
        assert _resolved_ip_is_internal("fec0::1") == "site-local"

    def test_resolve_and_pin_refuses_it_too(self) -> None:
        validator = SafeURLValidator(
            allowed_schemes=SCHEMES, dns_rebinding_guard=False, resolver=lambda host: ["fec0::1"]
        )
        with pytest.raises(SafeURLValidationError):
            validator.resolve_and_pin("https://rebind.example/")

    def test_the_controls_keep_their_answers(self) -> None:
        validator = SafeURLValidator(allowed_schemes=SCHEMES)
        assert validator("https://[2606:4700::1]/") == "https://[2606:4700::1]/"
        with pytest.raises(SafeURLValidationError):
            validator("https://[fd00::1]/")
        public = SafeURLValidator(
            allowed_schemes=SCHEMES,
            dns_rebinding_guard=True,
            resolver=lambda host: ["2606:4700::1"],
        )
        assert public("https://example.com/") == "https://example.com/"
