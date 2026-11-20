"""SSRF egress: Alibaba Cloud metadata, shared address space and multicast (v0.10.36).

GHSA-m5xq-h2p4-962g (``@fdcasj_dfew/md-doc-mcp`` 1.0.0 and 1.0.1, malware) queries
Alibaba Cloud's instance metadata service at ``100.100.100.200`` when its module loads.
https://github.com/advisories/GHSA-m5xq-h2p4-962g

On ffdc4306 ``SSRFEgressGuard().check_url`` allowed that address, ``100.64.0.0/10`` and
multicast: Python calls ``100.100.100.200`` neither private, global nor reserved, so none
of the existing checks matched. No test opens a socket; resolvers are stubs.
"""

from __future__ import annotations

import pytest

from agent_airlock.network import _is_private_ip
from agent_airlock.ssrf_egress_guard import SSRFEgressGuard, SSRFEgressVerdict

V = SSRFEgressVerdict


class TestSharedAddressMulticastAndAlibabaMetadata:
    @pytest.mark.parametrize(
        ("url", "verdict"),
        [
            ("http://100.100.100.200/latest/meta-data/", V.DENY_METADATA),
            ("http://100.64.0.1/", V.DENY_SHARED_ADDRESS),
            ("http://100.127.255.254/", V.DENY_SHARED_ADDRESS),
            ("http://224.0.0.1/", V.DENY_MULTICAST),
            ("http://239.255.255.250/", V.DENY_MULTICAST),
            ("http://[ff02::1]/", V.DENY_MULTICAST),
        ],
    )
    def test_each_target_is_refused(self, url: str, verdict: SSRFEgressVerdict) -> None:
        decision = SSRFEgressGuard().check_url(url)
        assert decision.allowed is False
        assert decision.verdict is verdict

    def test_the_verdict_values_are_stable(self) -> None:
        assert V.DENY_SHARED_ADDRESS.value == "deny_shared_address_cgnat"
        assert V.DENY_MULTICAST.value == "deny_multicast"

    @pytest.mark.parametrize(
        "url", ["http://100.63.255.255/", "http://100.128.0.1/", "http://8.8.8.8/"]
    )
    def test_the_addresses_either_side_stay_allowed(self, url: str) -> None:
        assert SSRFEgressGuard().check_url(url).verdict is V.ALLOW

    def test_alternate_encodings_of_the_alibaba_address_are_refused(self) -> None:
        guard = SSRFEgressGuard()
        for host in ("1684301000", "0x646464c8", "0144.0144.0144.0310"):
            assert guard.check_url(f"http://{host}/").verdict is V.DENY_METADATA, host

    def test_a_name_resolving_to_it_is_refused(self) -> None:
        guard = SSRFEgressGuard(resolver=lambda host: ["100.100.100.200"])
        assert guard.check_url("http://metadata.example/").verdict is V.DENY_METADATA
        guard = SSRFEgressGuard(resolver=lambda host: ["100.64.3.4"])
        assert guard.check_url("http://cgnat.example/").verdict is V.DENY_SHARED_ADDRESS

    def test_allow_internal_hosts_still_admits_a_listed_address(self) -> None:
        guard = SSRFEgressGuard(allow_internal_hosts={"100.64.0.1", "239.255.255.250"})
        assert guard.check_url("http://100.64.0.1/").verdict is V.ALLOW_HOST_ALLOWLISTED
        assert guard.check_url("http://239.255.255.250/").verdict is V.ALLOW_HOST_ALLOWLISTED

    def test_an_allowlisted_name_rebinding_to_alibaba_metadata_is_refused(self) -> None:
        guard = SSRFEgressGuard(
            allow_internal_hosts={"svc.internal"}, resolver=lambda host: ["100.100.100.200"]
        )
        assert guard.check_url("http://svc.internal/").verdict is V.DENY_METADATA

    @pytest.mark.parametrize(
        ("address", "internal"),
        [
            ("100.100.100.200", True),
            ("100.64.0.1", True),
            ("100.127.255.254", True),
            ("224.0.0.1", True),
            ("239.255.255.250", True),
            ("ff02::1", True),
            ("100.63.255.255", False),
            ("8.8.8.8", False),
        ],
    )
    def test_network_policy_agrees(self, address: str, internal: bool) -> None:
        assert _is_private_ip(address) is internal
