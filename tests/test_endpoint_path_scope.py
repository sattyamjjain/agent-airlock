"""Path-scoped URL allowlist (EndpointPolicy.allowed_url_prefixes), CVE-2026-120492.

A host-only allowlist cannot say "only https://api.example.com/v1/tools/". The
``..;`` path-parameter and ``%2e`` dot-segment spellings let a URL whose literal
path passes a prefix check collapse, at the origin server, to a path outside the
prefix (CWE-918). These feed URL strings to ``validate_endpoint``; no network.
"""

from __future__ import annotations

import pytest

from agent_airlock.network import EndpointPolicy, NetworkBlockedError, validate_endpoint

PREFIX = "https://api.example.com/v1/tools/"


def _policy(**kw: object) -> EndpointPolicy:
    # resolve_hostnames off: these tests are about the path scope, not DNS.
    kw.setdefault("allowed_url_prefixes", [PREFIX])
    kw.setdefault("resolve_hostnames", False)
    return EndpointPolicy(**kw)  # type: ignore[arg-type]


def _reason(url: str, policy: EndpointPolicy) -> str | None:
    try:
        validate_endpoint(url, policy)
        return None
    except NetworkBlockedError as e:
        return str(e.details.get("reason"))


class TestPrefixAllowed:
    @pytest.mark.parametrize(
        "url",
        [
            "https://api.example.com/v1/tools/run",
            "https://api.example.com/v1/tools/./run",
            "https://api.example.com/v1/tools/sub/deep/run",
            "https://api.example.com/v1/tools",  # the prefix dir itself
            "https://api.example.com/v1/tools/",
            "https://api.example.com:443/v1/tools/run",  # explicit default port
        ],
    )
    def test_allowed(self, url: str) -> None:
        assert _reason(url, _policy()) is None


class TestPrefixRefused:
    @pytest.mark.parametrize(
        ("url", "reason"),
        [
            ("https://api.example.com/v1/admin", "outside_url_prefix"),
            ("https://api.example.com/v1/toolsx", "outside_url_prefix"),
            # ..; and %2e%2e;x collapse to /v1/admin at a servlet container.
            ("https://api.example.com/v1/tools/..;/admin", "outside_url_prefix"),
            ("https://api.example.com/v1/tools/%2e%2e;x/admin", "outside_url_prefix"),
            ("https://api.example.com/v1/tools/..;jsessionid=x/admin", "outside_url_prefix"),
            # Encoded slash / backslash / NUL: no single reading, refused outright.
            ("https://api.example.com/v1/tools/..%2fadmin", "ambiguous_path_encoding"),
            ("https://api.example.com/v1/tools/x%5cadmin", "ambiguous_path_encoding"),
            ("https://api.example.com/v1/tools/x%00", "ambiguous_path_encoding"),
            # Scheme and port must match the entry.
            ("http://api.example.com/v1/tools/run", "outside_url_prefix"),
            ("https://api.example.com:8443/v1/tools/run", "outside_url_prefix"),
        ],
    )
    def test_refused(self, url: str, reason: str) -> None:
        assert _reason(url, _policy()) == reason

    def test_refusal_names_resolved_path_and_closest(self) -> None:
        try:
            validate_endpoint("https://api.example.com/v1/tools/..;/admin", _policy())
            raise AssertionError("expected refusal")
        except NetworkBlockedError as e:
            assert e.details["reason"] == "outside_url_prefix"
            # The resolved path is what the server would see, not the literal input.
            # (Named on the log line; the detail carries the hostname and reason.)
            assert e.details["hostname"] == "api.example.com"


class TestMultiplePrefixes:
    def test_second_entry_matches(self) -> None:
        policy = _policy(
            allowed_url_prefixes=[
                "https://api.example.com/v1/tools/",
                "https://api.example.com/v2/read/",
            ]
        )
        assert _reason("https://api.example.com/v2/read/x", policy) is None
        assert _reason("https://api.example.com/v3/x", policy) == "outside_url_prefix"


class TestEmptyPrefixesIsTodaysBehaviour:
    """With no prefixes, the path is not scoped: host-level checks decide, as before."""

    def test_any_path_allowed_when_host_allowed(self) -> None:
        policy = EndpointPolicy(allowed_endpoints=["api.example.com"], resolve_hostnames=False)
        assert _reason("https://api.example.com/v1/admin", policy) is None
        assert _reason("https://api.example.com/anything/at/all", policy) is None

    def test_host_allowlist_still_applies(self) -> None:
        policy = EndpointPolicy(allowed_endpoints=["api.example.com"], resolve_hostnames=False)
        assert _reason("https://evil.example.com/v1/tools/run", policy) == "not_in_allowlist"


class TestPrefixRunsAfterHostAndMetadataChecks:
    """A blocked pattern, private or metadata target is refused before the path matters."""

    def test_blocked_pattern_wins(self) -> None:
        policy = _policy(blocked_patterns=["api.example.com"])
        assert _reason("https://api.example.com/v1/tools/run", policy) == "blocked_pattern"

    def test_metadata_host_refused_even_with_matching_path(self) -> None:
        policy = EndpointPolicy(
            allowed_url_prefixes=["https://169.254.169.254/v1/tools/"],
            resolve_hostnames=False,
        )
        # The prefix names the metadata IP, but the metadata check runs first.
        assert _reason("https://169.254.169.254/v1/tools/run", policy) == "metadata_url"
