"""CVE-2026-47390 (SSRF-protection bypass via alternate IP encodings) regression.

CWE-918: an agent egress filter that validates the *literal hostname string*
of an outbound URL — rather than the **resolved IP** — is bypassed by encoding
a loopback / link-local / cloud-metadata address in a form ``ipaddress``
rejects but ``socket.inet_aton`` (and the HTTP client / kernel) resolves
straight back to an internal address, or by DNS rebinding.

This suite pins, per the brief:

- EACH alternate-loopback encoding is denied: 127.0.0.0/8, ``127.1``, decimal
  ``2130706433``, octal ``0177.0.0.1``, hex ``0x7f000001``, ``0.0.0.0``.
- IPv6 loopback / mapped: ``::1``, ``[::1]``, ``::ffff:127.0.0.1``,
  ``0:0:0:0:0:0:0:1``.
- Link-local + metadata: ``169.254.169.254``; ULA ``fd00::/8``; ``fe80::/10``.
- RFC1918 (10/8, 172.16/12, 192.168/16) denied unless allow-listed.
- DNS rebinding: a public-looking host whose resolved IP is loopback is denied
  (the guard evaluates the resolved address, not the literal string).
- A 3-line explain trace accompanies every denial.

Primary sources (retrieved 2026-06-21):
  https://www.cve.org/CVERecord?id=CVE-2026-47390
  https://cwe.mitre.org/data/definitions/918.html
"""

from __future__ import annotations

import pytest

from agent_airlock import (
    SSRFEgressBlocked,
    SSRFEgressGuard,
    SSRFEgressVerdict,
)
from agent_airlock.policy_presets import ssrf_egress_guard_defaults

CVE = "CVE-2026-47390"


def _guard(**kw: object) -> SSRFEgressGuard:
    # No real DNS for literal-IP cases; inject a resolver that refuses names so
    # a stray hostname can never accidentally pass via the system resolver.
    kw.setdefault("resolver", lambda h: (_ for _ in ()).throw(OSError("no dns in test")))
    return SSRFEgressGuard(**kw)  # type: ignore[arg-type]


class TestAlternateLoopbackEncodingsDenied:
    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1/",
            "http://127.0.0.5/",  # anywhere in 127.0.0.0/8
            "http://127.1/",  # short form
            "http://2130706433/",  # decimal
            "http://0177.0.0.1/",  # octal
            "http://0x7f000001/",  # hex
            "http://0.0.0.0/",  # unspecified
            "http://[::1]/",  # IPv6 loopback
            "http://[::ffff:127.0.0.1]/",  # IPv4-mapped IPv6
            "http://[0:0:0:0:0:0:0:1]/",  # expanded IPv6 loopback
        ],
    )
    def test_each_encoding_denied(self, url: str) -> None:
        d = _guard().check_url(url)
        assert d.allowed is False, f"must deny loopback encoding: {url}"
        assert d.verdict in {
            SSRFEgressVerdict.DENY_LOOPBACK,
            SSRFEgressVerdict.DENY_UNSPECIFIED,
        }
        # A resolved IP is always reported on a denial. Its exact string form
        # for IPv4-mapped IPv6 (``::ffff:127.0.0.1`` vs ``::ffff:7f00:1``) is
        # not stable across platforms, so assert presence, not the literal.
        assert d.resolved_ip is not None

    def test_hex_encoding_records_encoding_label(self) -> None:
        d = _guard().check_url("http://0x7f000001/")
        assert d.encoding == "hex_ipv4"
        assert d.resolved_ip == "127.0.0.1"

    def test_decimal_and_octal_labels(self) -> None:
        assert _guard().check_url("http://2130706433/").encoding == "decimal_ipv4"
        assert _guard().check_url("http://0177.0.0.1/").encoding == "octal_ipv4"


class TestLinkLocalAndMetadataDenied:
    def test_aws_imds_denied_as_metadata(self) -> None:
        d = _guard().check_url("http://169.254.169.254/latest/meta-data/")
        assert d.allowed is False
        assert d.verdict is SSRFEgressVerdict.DENY_METADATA

    def test_link_local_range_denied(self) -> None:
        assert _guard().check_url("http://169.254.10.20/").verdict is (
            SSRFEgressVerdict.DENY_LINK_LOCAL
        )

    def test_ipv6_ula_denied(self) -> None:
        d = _guard().check_url("http://[fd00::1]/")
        assert d.allowed is False

    def test_ipv6_link_local_denied(self) -> None:
        d = _guard().check_url("http://[fe80::1]/")
        assert d.allowed is False


class TestRFC1918:
    @pytest.mark.parametrize(
        "url", ["http://10.0.0.5/", "http://172.16.0.1/", "http://192.168.1.1/"]
    )
    def test_private_ranges_denied_by_default(self, url: str) -> None:
        d = _guard().check_url(url)
        assert d.allowed is False
        assert d.verdict is SSRFEgressVerdict.DENY_PRIVATE

    def test_allowlisted_internal_host_passes(self) -> None:
        guard = _guard(allow_internal_hosts=["10.0.0.5"])
        d = guard.check_url("http://10.0.0.5/internal/api")
        assert d.allowed is True
        assert d.verdict is SSRFEgressVerdict.ALLOW_HOST_ALLOWLISTED

    def test_allowlist_does_not_leak_to_other_private_hosts(self) -> None:
        guard = _guard(allow_internal_hosts=["10.0.0.5"])
        assert guard.check_url("http://10.0.0.6/").allowed is False


class TestDNSRebinding:
    def test_resolved_loopback_is_denied_even_with_public_name(self) -> None:
        # The literal string is innocuous; only the resolved IP is internal.
        guard = SSRFEgressGuard(resolver=lambda h: ["127.0.0.1"])
        d = guard.check_url("http://totally-legit.example/")
        assert d.allowed is False
        assert d.verdict is SSRFEgressVerdict.DENY_LOOPBACK
        assert d.encoding == "dns"

    def test_resolved_metadata_is_denied(self) -> None:
        guard = SSRFEgressGuard(resolver=lambda h: ["169.254.169.254"])
        assert guard.check_url("http://rebind.example/").verdict is (
            SSRFEgressVerdict.DENY_METADATA
        )

    def test_public_resolution_passes(self) -> None:
        guard = SSRFEgressGuard(resolver=lambda h: ["93.184.216.34"])
        assert guard.check_url("http://example.com/").allowed is True

    def test_unresolvable_host_fails_closed(self) -> None:
        guard = SSRFEgressGuard(resolver=lambda h: (_ for _ in ()).throw(OSError("nxdomain")))
        d = guard.check_url("http://nope.invalid/")
        assert d.allowed is False
        assert d.verdict is SSRFEgressVerdict.DENY_UNRESOLVABLE

    def test_unresolvable_can_be_allowed_when_opted_out(self) -> None:
        guard = SSRFEgressGuard(
            resolver=lambda h: (_ for _ in ()).throw(OSError("nxdomain")),
            deny_on_resolution_failure=False,
        )
        assert guard.check_url("http://nope.invalid/").allowed is True


class TestExplainTrace:
    def test_denial_has_three_line_explain(self) -> None:
        d = _guard().check_url("http://0x7f000001/")
        assert len(d.explain) == 3
        assert d.explain[0].startswith("rule=deny_loopback")
        assert "resolved_ip=127.0.0.1" in d.explain[1]
        assert d.explain[2] == "encoding=hex_ipv4"


class TestArgScanAndEnforce:
    def test_check_scans_nested_url_args(self) -> None:
        d = _guard().check({"payload": {"callback": "http://0x7f000001/hook"}})
        assert d.allowed is False
        assert d.verdict is SSRFEgressVerdict.DENY_LOOPBACK

    def test_check_passes_when_no_url_args(self) -> None:
        assert _guard().check({"name": "alice", "count": 3}).allowed is True

    def test_enforce_raises_with_explain(self) -> None:
        with pytest.raises(SSRFEgressBlocked) as exc:
            _guard().enforce("http://169.254.169.254/")
        assert len(exc.value.explain) == 3
        assert any(CVE in h for h in exc.value.fix_hints)

    def test_bare_str_allowlist_raises(self) -> None:
        with pytest.raises(TypeError, match="bare str"):
            SSRFEgressGuard(allow_internal_hosts="10.0.0.5")  # type: ignore[arg-type]


class TestPreset:
    def test_canonical_metadata(self) -> None:
        p = ssrf_egress_guard_defaults()
        assert p["preset_id"] == "ssrf_egress_guard"
        assert p["severity"] == "high"
        assert p["default_action"] == "deny"
        assert p["owasp"] == "ASI02"
        assert p["cwe"] == ("CWE-918",)
        assert p["cves"] == ("CVE-2026-47390",)
        assert isinstance(p["guard"], SSRFEgressGuard)

    def test_check_raises_on_hex_loopback_and_metadata(self) -> None:
        p = ssrf_egress_guard_defaults()
        for url in ("http://0x7f000001/", "http://169.254.169.254/"):
            with pytest.raises(SSRFEgressBlocked):
                p["check"](url)

    def test_preset_allowlist_passes_internal(self) -> None:
        p = ssrf_egress_guard_defaults(allow_internal_hosts=["10.1.2.3"])
        assert p["check"]("http://10.1.2.3/") is None
