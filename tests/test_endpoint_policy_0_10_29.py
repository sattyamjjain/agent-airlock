"""0.10.29: EndpointPolicy reads the address a host stands for, and the airgap every connect.

Found while verifying the outside-feedback work order (pydantic-ai#8426, smolagents#2750,
firecrawl#4459, browser-use#5815). Step 5's ``validate_endpoint`` compared the literal host
string: ``_is_private_ip`` parsed only canonical IPs and the metadata check was a string
match, so a default ``EndpointPolicy()`` admitted ``http://2130706433/``,
``http://0x7f000001/``, ``http://127.1/``, ``http://0xa9fea9fe/latest/meta-data/``,
``http://0251.0376.0251.0376/`` and the wildcard-DNS ``http://169.254.169.254.nip.io/``.
``SafeURLValidator`` and ``SSRFEgressGuard`` already decoded those forms; step 5 now reuses
their decoding (``metadata_ip_candidates``), resolves a hostname it would admit, and the
airgap's ``NetworkPolicy(block_private_ips=True)`` refuses an internal address at connect
time, which covers redirect hops and rebinds an argument check never sees. No test here
touches a real network: resolvers are injected and servers listen on loopback.
"""

from __future__ import annotations

import contextlib
import socket
import threading
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

from agent_airlock import Airlock, AirlockConfig
from agent_airlock.network import (
    EndpointPolicy,
    NetworkBlockedError,
    NetworkPolicy,
    validate_endpoint,
)

PUBLIC = "93.184.216.34"

_ANSWERS = {
    "example.com": [PUBLIC],
    "api.example.test": [PUBLIC],
    "169.254.169.254.nip.io": ["169.254.169.254"],
    "meta.attacker.test": ["169.254.169.254"],
    "rebind.attacker.test": [PUBLIC, "10.0.0.5"],
    "empty.attacker.test": [],
    "garbage.attacker.test": ["not-an-address"],
    "localhost.": ["127.0.0.1"],
}


class _Resolver:
    """A deterministic resolver that records what it was asked."""

    def __init__(self) -> None:
        self.asked: list[str] = []

    def __call__(self, host: str) -> list[str]:
        self.asked.append(host)
        if host not in _ANSWERS:
            raise OSError(f"no such host: {host}")
        return list(_ANSWERS[host])


def _reason(url: str, policy: EndpointPolicy) -> str:
    """The refusal reason ``validate_endpoint`` gives ``url``, or "admitted"."""
    try:
        validate_endpoint(url, policy)
    except NetworkBlockedError as exc:
        return str(exc.details["reason"])
    return "admitted"


class TestAlternateEncodings:
    """Every IP a host could stand for is checked, not the literal string."""

    @pytest.mark.parametrize(
        ("url", "reason"),
        [
            ("http://2130706433/", "private_ip"),
            ("http://0x7f000001/", "private_ip"),
            ("http://127.1/", "private_ip"),
            ("http://0xa9fea9fe/latest/meta-data/", "metadata_url"),
            ("http://0251.0376.0251.0376/", "metadata_url"),
            ("http://169.254.169.254.nip.io/", "metadata_url"),
            ("http://0/", "private_ip"),
            ("http://localhost./", "private_ip"),
        ],
    )
    def test_alternate_encoding_is_refused(self, url: str, reason: str) -> None:
        assert _reason(url, EndpointPolicy(resolver=_Resolver())) == reason

    def test_ipv4_mapped_metadata_stays_refused(self) -> None:
        assert _reason("http://[::ffff:a9fe:a9fe]/", EndpointPolicy()) == "metadata_url"

    @pytest.mark.parametrize("url", ["https://example.com/", f"http://{PUBLIC}/"])
    def test_public_targets_are_admitted(self, url: str) -> None:
        """Controls."""
        assert _reason(url, EndpointPolicy(resolver=_Resolver())) == "admitted"

    def test_allow_private_ips_still_refuses_metadata(self) -> None:
        policy = EndpointPolicy(allow_private_ips=True, resolver=_Resolver())
        assert _reason("http://2130706433/", policy) == "admitted"
        assert _reason("http://0xa9fea9fe/", policy) == "metadata_url"


class TestResolution:
    """A hostname the policy would admit is resolved, and every answer is checked."""

    def test_a_name_resolving_to_metadata_is_refused(self) -> None:
        policy = EndpointPolicy(resolver=_Resolver())
        assert _reason("http://meta.attacker.test/latest/", policy) == "metadata_url"

    def test_one_internal_answer_among_public_ones_is_refused(self) -> None:
        policy = EndpointPolicy(resolver=_Resolver())
        assert _reason("https://rebind.attacker.test/", policy) == "private_ip"

    def test_a_name_resolving_to_a_public_address_is_admitted(self) -> None:
        """Control."""
        assert _reason("https://api.example.test/", EndpointPolicy(resolver=_Resolver())) == (
            "admitted"
        )

    @pytest.mark.parametrize(
        "host", ["nowhere.attacker.test", "empty.attacker.test", "garbage.attacker.test"]
    )
    def test_an_unresolvable_host_is_refused(self, host: str) -> None:
        policy = EndpointPolicy(resolver=_Resolver())
        assert _reason(f"https://{host}/", policy) == "unresolvable_host"

    def test_resolution_failure_can_be_admitted_by_opt_out(self) -> None:
        policy = EndpointPolicy(resolver=_Resolver(), deny_on_resolution_failure=False)
        assert _reason("https://nowhere.attacker.test/", policy) == "admitted"

    def test_resolve_hostnames_off_skips_the_lookup(self) -> None:
        resolver = _Resolver()
        policy = EndpointPolicy(resolver=resolver, resolve_hostnames=False)
        assert _reason("http://meta.attacker.test/", policy) == "admitted"
        assert resolver.asked == []

    def test_a_name_the_allowlist_refuses_is_never_looked_up(self) -> None:
        """A lookup of a model-chosen name can carry data out over DNS; refuse it first."""
        resolver = _Resolver()
        policy = EndpointPolicy(allowed_endpoints=["api.example.test"], resolver=resolver)
        assert _reason("https://secret-value.attacker.test/", policy) == "not_in_allowlist"
        assert resolver.asked == []

    def test_an_allowlisted_name_rebound_inside_is_refused(self) -> None:
        resolver = _Resolver()
        policy = EndpointPolicy(allowed_endpoints=["*.attacker.test"], resolver=resolver)
        assert _reason("https://meta.attacker.test/", policy) == "metadata_url"
        assert resolver.asked == ["meta.attacker.test"]

    def test_nothing_is_looked_up_when_internal_targets_are_allowed(self) -> None:
        resolver = _Resolver()
        policy = EndpointPolicy(allow_private_ips=True, allow_metadata_urls=True, resolver=resolver)
        assert _reason("https://meta.attacker.test/", policy) == "admitted"
        assert resolver.asked == []

    def test_a_resolver_that_raises_anything_fails_closed(self) -> None:
        def broken(host: str) -> list[str]:
            raise RuntimeError("resolver bug")

        assert _reason("https://api.example.test/", EndpointPolicy(resolver=broken)) == (
            "unresolvable_host"
        )

    def test_toml_reads_the_options(self, tmp_path: Path) -> None:
        toml = tmp_path / "airlock.toml"
        toml.write_text(
            "[airlock.endpoints.fetch]\n"
            'allowed_endpoints = ["api.example.test"]\n'
            "resolve_hostnames = false\n"
            "deny_on_resolution_failure = false\n"
            "[airlock.network]\n"
            "block_private_ips = true\n"
            'allowed_private_ips = ["127.0.0.1"]\n'
        )
        config = AirlockConfig.from_toml(toml)
        endpoint = config.endpoint_policies["fetch"]
        assert (endpoint.resolve_hostnames, endpoint.deny_on_resolution_failure) == (False, False)
        assert config.network_policy is not None
        assert config.network_policy.block_private_ips is True
        assert config.network_policy.allowed_private_ips == ["127.0.0.1"]


class TestDecoratorPath:
    """Step 5 through ``@Airlock``."""

    @staticmethod
    def _fetch(policy: EndpointPolicy) -> Callable[..., Any]:
        @Airlock(config=AirlockConfig(endpoint_policies={"fetch": policy}))
        def fetch(url: str) -> str:
            return f"fetched {url}"

        return fetch

    def test_a_decimal_loopback_url_is_refused(self) -> None:
        result = self._fetch(EndpointPolicy())(url="http://2130706433/")
        assert isinstance(result, dict)
        assert result["block_reason"] == "endpoint_blocked"

    def test_a_wildcard_dns_metadata_name_is_refused(self) -> None:
        result = self._fetch(EndpointPolicy(resolver=_Resolver()))(
            url="http://169.254.169.254.nip.io/"
        )
        assert isinstance(result, dict)
        assert result["block_reason"] == "endpoint_blocked"

    def test_a_public_url_runs(self) -> None:
        """Control."""
        fetch = self._fetch(EndpointPolicy(resolver=_Resolver()))
        assert fetch(url="https://api.example.test/") == "fetched https://api.example.test/"


@contextlib.contextmanager
def _listener(host: str = "127.0.0.1", family: int = socket.AF_INET) -> Iterator[int]:
    """A TCP socket listening on this machine, yielding its port."""
    server = socket.socket(family, socket.SOCK_STREAM)
    try:
        server.bind((host, 0))
        server.listen(4)
        yield int(server.getsockname()[1])
    finally:
        server.close()


def _connect(host: str, port: int) -> str:
    """Connect inside the airgap: "refused" by it, else "connected"."""
    sock = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET)
    sock.settimeout(2)
    try:
        sock.connect((host, port))
    except NetworkBlockedError:
        return "refused"
    finally:
        sock.close()
    return "connected"


def _airgapped(policy: NetworkPolicy, body: Callable[[], str]) -> Any:
    @Airlock(config=AirlockConfig(network_policy=policy, enable_audit_log=False))
    def tool() -> str:
        return body()

    return tool()


def _ipv6_loopback() -> bool:
    try:
        with _listener("::1", socket.AF_INET6):
            return True
    except OSError:
        return False


class _RedirectHandler(BaseHTTPRequestHandler):
    """Answers 302 to ``target`` when set, else 200 with a body."""

    target: str | None = None

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's name
        if self.target:
            self.send_response(302)
            self.send_header("Location", self.target)
            self.end_headers()
            return
        body = b"internal secret"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - inherited name
        return


class _IPv6HTTPServer(HTTPServer):
    address_family = socket.AF_INET6


@contextlib.contextmanager
def _http_server(host: str, target: str | None = None) -> Iterator[int]:
    handler = type("Handler", (_RedirectHandler,), {"target": target})
    server_class = _IPv6HTTPServer if ":" in host else HTTPServer
    server = server_class((host, 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _fetch(url: str) -> str:
    try:
        with urllib.request.urlopen(url, timeout=2) as response:  # nosec B310 - loopback only
            return str(response.read().decode())
    except NetworkBlockedError:
        return "refused"


class TestAirgapPrivateConnect:
    """``NetworkPolicy(block_private_ips=True)`` refuses internal addresses at connect."""

    def test_a_loopback_connect_is_refused(self) -> None:
        with _listener() as port:
            result = _airgapped(
                NetworkPolicy(block_private_ips=True), lambda: _connect("127.0.0.1", port)
            )
        assert result == "refused"  # the tool caught the airgap's NetworkBlockedError

    def test_a_name_connect_is_resolved_and_refused(self) -> None:
        with _listener() as port:
            result = _airgapped(
                NetworkPolicy(block_private_ips=True), lambda: _connect("localhost", port)
            )
        assert result == "refused"  # the tool caught the airgap's NetworkBlockedError

    def test_a_datagram_to_loopback_is_refused(self) -> None:
        def send() -> str:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.sendto(b"x", ("127.0.0.1", 9))
            finally:
                sock.close()
            return "sent"

        result = _airgapped(NetworkPolicy(block_private_ips=True), send)
        assert isinstance(result, dict)
        assert result["block_reason"] == "network_blocked"

    def test_the_allowlist_does_not_exempt_an_internal_address(self) -> None:
        policy = NetworkPolicy(block_private_ips=True, allowed_hosts=["127.0.0.1"])
        with _listener() as port:
            result = _airgapped(policy, lambda: _connect("127.0.0.1", port))
        assert result == "refused"  # the tool caught the airgap's NetworkBlockedError

    def test_an_exempted_address_connects(self) -> None:
        policy = NetworkPolicy(block_private_ips=True, allowed_private_ips=["127.0.0.1"])
        with _listener() as port:
            assert _airgapped(policy, lambda: _connect("127.0.0.1", port)) == "connected"

    def test_option_off_connects(self) -> None:
        """Control: the option is opt-in."""
        with _listener() as port:
            assert _airgapped(NetworkPolicy(), lambda: _connect("127.0.0.1", port)) == "connected"

    @pytest.mark.skipif(not _ipv6_loopback(), reason="no IPv6 loopback on this host")
    def test_a_redirect_hop_to_an_internal_address_is_refused(self) -> None:
        """The first hop is exempted; the 302 it answers points at another internal
        address, which only a connect-time check sees."""
        policy = NetworkPolicy(block_private_ips=True, allowed_private_ips=["127.0.0.1"])
        with (
            _http_server("::1") as inner,
            _http_server("127.0.0.1", target=f"http://[::1]:{inner}/") as outer,
        ):
            result = _airgapped(policy, lambda: _fetch(f"http://127.0.0.1:{outer}/"))
        assert result == "refused"  # the tool caught the airgap's NetworkBlockedError

    @pytest.mark.skipif(not _ipv6_loopback(), reason="no IPv6 loopback on this host")
    def test_the_redirect_is_followed_when_both_hops_are_allowed(self) -> None:
        """Control: the same redirect with both hops exempted reaches the second server."""
        policy = NetworkPolicy(block_private_ips=True, allowed_private_ips=["127.0.0.1", "::1"])
        with (
            _http_server("::1") as inner,
            _http_server("127.0.0.1", target=f"http://[::1]:{inner}/") as outer,
        ):
            assert _airgapped(policy, lambda: _fetch(f"http://127.0.0.1:{outer}/")) == (
                "internal secret"
            )
