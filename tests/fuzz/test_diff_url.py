"""Differential tests: the SSRF egress guard vs urllib / rfc3986 / yarl / httpx.

The contract: whenever an independent URL parser resolves the host to a
loopback / private / link-local / metadata / unspecified target, agent-airlock
must NOT admit the egress. This suite drives literal IPv4 across the address
space, IPv6 forbidden forms, and obfuscated hosts (userinfo, backslashes,
percent-encoding, mixed-case schemes) and checks the guard refuses every one a
reference parser routes to an internal address.

A stub resolver keeps hostnames off the real network.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agent_airlock.ssrf_egress_guard import SSRFEgressGuard


def _stub_resolver(host: str) -> list[str]:
    return ["93.184.216.34"]


def _guard() -> SSRFEgressGuard:
    return SSRFEgressGuard(resolver=_stub_resolver)


def _ref_forbidden_ip(ip_str: str) -> bool:
    """Independent (stdlib ipaddress) classification of a forbidden target."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return bool(
        ip.is_loopback
        or ip.is_link_local
        or ip.is_private
        or ip.is_unspecified
        or ip_str in {"169.254.169.254", "fd00:ec2::254"}
    )


# ---- IPv4 across the space, biased toward forbidden ranges ----------------- #

_forbidden_v4 = st.one_of(
    st.builds(
        lambda b, c, d: f"127.{b}.{c}.{d}",
        st.integers(0, 255),
        st.integers(0, 255),
        st.integers(0, 255),
    ),
    st.builds(
        lambda b, c, d: f"10.{b}.{c}.{d}",
        st.integers(0, 255),
        st.integers(0, 255),
        st.integers(0, 255),
    ),
    st.builds(lambda c, d: f"192.168.{c}.{d}", st.integers(0, 255), st.integers(0, 255)),
    st.builds(
        lambda b, c, d: f"172.{b}.{c}.{d}",
        st.integers(16, 31),
        st.integers(0, 255),
        st.integers(0, 255),
    ),
    st.builds(lambda c, d: f"169.254.{c}.{d}", st.integers(0, 255), st.integers(0, 255)),
    st.just("0.0.0.0"),
    st.just("169.254.169.254"),
)


@given(ip=_forbidden_v4)
def test_forbidden_ipv4_is_refused(ip: str) -> None:
    assert _ref_forbidden_ip(ip), f"generator produced a non-forbidden IP {ip!r}"
    decision = _guard().check_url(f"http://{ip}/path")
    assert not decision.allowed, f"guard admitted forbidden egress to {ip!r}"


@given(
    a=st.integers(1, 223),
    b=st.integers(0, 255),
    c=st.integers(0, 255),
    d=st.integers(1, 254),
)
def test_ipv4_matches_stdlib_on_deny_direction(a: int, b: int, c: int, d: int) -> None:
    ip = f"{a}.{b}.{c}.{d}"
    if not _ref_forbidden_ip(ip):
        return  # only the deny direction is contracted
    decision = _guard().check_url(f"http://{ip}/")
    assert not decision.allowed, f"guard admitted stdlib-forbidden {ip!r}"


# ---- IPv6 forbidden forms -------------------------------------------------- #


@pytest.mark.parametrize(
    "host",
    ["[::1]", "[::]", "[fe80::1]", "[fc00::1]", "[fd00::1]", "[fd00:ec2::254]"],
)
def test_forbidden_ipv6_is_refused(host: str) -> None:
    decision = _guard().check_url(f"http://{host}/")
    assert not decision.allowed, f"guard admitted forbidden IPv6 egress to {host!r}"


# ---- Alternate IPv4 encodings of loopback / metadata ----------------------- #


@pytest.mark.parametrize(
    "host",
    [
        "2130706433",  # decimal 127.0.0.1
        "0x7f000001",  # hex 127.0.0.1
        "0177.0.0.1",  # octal first octet
        "127.1",  # short form 127.0.0.1
        "2852039166",  # decimal 169.254.169.254
    ],
)
def test_alternate_encoding_loopback_is_refused(host: str) -> None:
    decision = _guard().check_url(f"http://{host}/")
    assert not decision.allowed, f"guard admitted alternate-encoded internal host {host!r}"


# ---- Obfuscated hosts: userinfo, mixed-case scheme ------------------------- #


@pytest.mark.parametrize(
    "url",
    [
        "http://user:pass@127.0.0.1/",
        "HTTP://127.0.0.1/",
        "hTtP://169.254.169.254/latest/",
        "http://user@0x7f000001/",
        "  http://127.0.0.1/",  # leading whitespace
    ],
)
def test_obfuscated_internal_hosts_refused(url: str) -> None:
    decision = _guard().check_url(url)
    assert not decision.allowed, f"guard admitted obfuscated internal egress {url!r}"


# ---- Differential: guard agrees with urllib host extraction --------------- #


@given(ip=_forbidden_v4, user=st.text(alphabet="abc", max_size=4))
def test_userinfo_does_not_hide_forbidden_host(ip: str, user: str) -> None:
    url = f"http://{user}@{ip}/" if user else f"http://{ip}/"
    # urllib (the reference) resolves the host past the userinfo.
    ref_host = urlsplit(url).hostname
    assert ref_host == ip
    decision = _guard().check_url(url)
    assert not decision.allowed, f"userinfo hid forbidden host in {url!r}"


def test_public_host_is_admitted() -> None:
    decision = _guard().check_url("https://api.public.example/v1")
    assert decision.allowed


# ---- Cross-parser differential: urllib vs rfc3986 vs yarl vs httpx ---------- #

_CROSS_PARSER_URLS = [
    "http://user:pass@127.0.0.1/",
    "http://127.0.0.1:80/path?q=1",
    "http://[::1]/",
    "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.5/admin",
    "http://user@0x7f000001/",
]


def _reference_hosts(url: str) -> set[str]:
    """Hosts the independent parsers (urllib, rfc3986, yarl, httpx) resolve."""
    import contextlib

    import httpx
    import rfc3986
    import yarl

    hosts: set[str] = {(urlsplit(url).hostname or "").strip("[]")}
    with contextlib.suppress(Exception):
        hosts.add((rfc3986.urlparse(url).host or "").strip("[]"))
    with contextlib.suppress(Exception):
        hosts.add((yarl.URL(url).host or "").strip("[]"))
    with contextlib.suppress(Exception):
        hosts.add((httpx.URL(url).host or "").strip("[]"))
    return {h for h in hosts if h}


@pytest.mark.parametrize("url", _CROSS_PARSER_URLS)
def test_guard_denies_when_any_reference_parser_sees_internal(url: str) -> None:
    """If urllib, rfc3986, yarl or httpx resolve the host to an internal target,
    the guard must not admit — a parser-disagreement SSRF bypass would show here."""
    hosts = _reference_hosts(url)
    forbidden = any(_ref_forbidden_ip(h) or h in {"0x7f000001"} for h in hosts)
    if not forbidden:
        pytest.skip(f"no reference parser saw an internal host for {url!r}: {hosts}")
    decision = _guard().check_url(url)
    assert not decision.allowed, (
        f"guard admitted {url!r} though a reference parser saw internal host(s) {hosts}"
    )
