"""CVE-2026-48782 (SafeURL IPv6-transition cloud-metadata SSRF bypass) regression.

pydantic-ai 1.56.0–1.101.0 / 2.0.0b1–b2 (CWE-918 SSRF): the cloud-metadata
blocklist compared the *hostname string*, so encoding the metadata IP
``169.254.169.254`` in an IPv6-transition form (IPv4-mapped, IPv4-compatible,
6to4, Teredo) or as a decimal/octal/hex integer slipped past it while the HTTP
client still connected to the metadata endpoint — exposing cloud IAM
credentials. This is an **incomplete-fix** follow-up to CVE-2026-46678 (which
closed the canonical and some IPv6 forms but left the transition-form gap).
Fixed upstream in 2.0.0b3.

agent-airlock's ``SafeURLValidator`` closes the gap by normalizing the host to
its packed ``ipaddress`` form(s) BEFORE the blocklist comparison, so every
encoding collapses to the same value.

This suite pins, per the brief:
- every encoded-metadata-IP bypass vector is rejected;
- legitimate public IPv6 hosts still pass (no false positives).

Primary sources (retrieved 2026-06-21):
  https://github.com/pydantic/pydantic-ai/security/advisories/GHSA-cg7w-rg45-pc59
  https://radar.offseq.com/threat/cve-2026-48782-cwe-918-server-side-request-forgery-4a9d43f1
  https://cwe.mitre.org/data/definitions/918.html
"""

from __future__ import annotations

import pytest

from agent_airlock.safe_types import (
    SafeURLValidationError,
    SafeURLValidator,
    metadata_ip_candidates,
)

CVE = "CVE-2026-48782"


def _validator() -> SafeURLValidator:
    # Default posture: block_metadata_urls=True (deny-by-default).
    return SafeURLValidator(allowed_schemes=["http", "https"])


class TestEncodedMetadataBypassRejected:
    @pytest.mark.parametrize(
        "url",
        [
            # canonical baseline (must remain blocked)
            "http://169.254.169.254/latest/meta-data/",
            "https://[fd00:ec2::254]/",
            # IPv4-mapped IPv6
            "http://[::ffff:169.254.169.254]/latest/meta-data/",
            "http://[::ffff:a9fe:a9fe]/",  # same, hextet form
            # IPv4-compatible IPv6 (deprecated ::a.b.c.d)
            "http://[::169.254.169.254]/",
            # 6to4 (2002::/16 wrapping the metadata IPv4)
            "http://[2002:a9fe:a9fe::]/",
            # decimal / octal / hex integer IPv4 encodings
            "http://2852039166/",  # int(169.254.169.254)
            "http://0xa9fea9fe/",  # hex
            "http://0251.0376.0251.0376/",  # dotted octal
            # GCP secondary + Alibaba metadata
            "http://169.254.169.253/",
            "http://100.100.100.200/",  # Alibaba ECS metadata
        ],
    )
    def test_metadata_bypass_vector_rejected(self, url: str) -> None:
        with pytest.raises(SafeURLValidationError) as exc:
            _validator()(url)
        assert exc.value.reason in {"metadata_url", "private_ip", "link_local"}

    def test_gcp_metadata_hostname_rejected(self) -> None:
        with pytest.raises(SafeURLValidationError):
            _validator()("http://metadata.google.internal/computeMetadata/v1/")

    def test_alibaba_metadata_hostname_rejected(self) -> None:
        with pytest.raises(SafeURLValidationError):
            _validator()("http://metadata.aliyuncs.com/latest/meta-data/")

    def test_mapped_metadata_blocked_even_when_private_ips_allowed(self) -> None:
        # The metadata canonicalization lives under block_metadata_urls, so it
        # fires independently of block_private_ips.
        v = SafeURLValidator(
            allowed_schemes=["http", "https"],
            block_private_ips=False,
            block_metadata_urls=True,
        )
        with pytest.raises(SafeURLValidationError) as exc:
            v("http://[::ffff:169.254.169.254]/")
        assert exc.value.reason == "metadata_url"


class TestLegitimateIPv6Passes:
    @pytest.mark.parametrize(
        "url",
        [
            "https://[2606:4700:4700::1111]/",  # Cloudflare DNS
            "https://[2001:4860:4860::8888]/dns",  # Google DNS
            "https://[2620:fe::fe]/",  # Quad9
        ],
    )
    def test_public_ipv6_host_passes(self, url: str) -> None:
        assert _validator()(url) == url

    def test_public_ipv4_host_passes(self) -> None:
        assert _validator()("https://93.184.216.34/") == "https://93.184.216.34/"


class TestCanonicalizationHelper:
    """The packed-form normalizer underpinning the fix."""

    def test_ipv4_mapped_yields_embedded_ipv4(self) -> None:
        import ipaddress

        cands = metadata_ip_candidates("::ffff:169.254.169.254")
        assert ipaddress.ip_address("169.254.169.254") in cands

    def test_sixtofour_yields_embedded_ipv4(self) -> None:
        import ipaddress

        cands = metadata_ip_candidates("2002:a9fe:a9fe::")
        assert ipaddress.ip_address("169.254.169.254") in cands

    def test_integer_encoding_yields_ipv4(self) -> None:
        import ipaddress

        assert ipaddress.ip_address("169.254.169.254") in metadata_ip_candidates("0xa9fea9fe")

    def test_plain_dns_name_yields_empty(self) -> None:
        assert metadata_ip_candidates("example.com") == set()

    def test_public_ipv6_does_not_yield_metadata(self) -> None:
        import ipaddress

        cands = metadata_ip_candidates("2606:4700:4700::1111")
        assert ipaddress.ip_address("169.254.169.254") not in cands
