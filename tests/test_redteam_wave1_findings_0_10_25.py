"""Regressions for the two guard hardening leads found by adaptive red-team wave 1.

Both are parser-differential fail-opens the campaign oracle could not score itself (its
reference detectors share ``urllib.parse`` and do not model text pickles), so they were
triaged by hand against the live guards and fixed in 0.10.25:

1. ``UnsafeDeserializationGuard`` admitted a protocol-0 **text pickle behind non-newline
   leading whitespace** (``"   cos\\nsystem\\n(S'id'\\ntR."``): ``_TEXT_PICKLE_GLOBAL``
   anchored on ``^`` / ``[\\n(]`` only, so spaces or tabs moved the GLOBAL opcode off the
   anchor, and the data-only branch needs a memo opcode this payload lacks. A tool that
   strips before ``pickle.loads`` would still execute it. Now the opcode is matched on the
   left-stripped value too.

2. The endpoint gate (``validate_endpoint``) and ``SSRFEgressGuard`` both admitted
   ``http://127.0.0.1\\@api.allowed.example/``: ``urllib.parse`` reads the host as the
   allowlisted ``api.allowed.example`` (the ``\\`` sits in userinfo), but a WHATWG client
   treats ``\\`` as ``/`` and connects to ``127.0.0.1`` — a loopback SSRF past the
   allowlist. ``network.authority_has_differential`` now refuses a backslash or raw
   tab/newline/CR anywhere in the URL authority, before the allowlist check.
"""

from __future__ import annotations

import pytest

from agent_airlock.network import (
    EndpointPolicy,
    NetworkBlockedError,
    authority_has_differential,
    validate_endpoint,
)
from agent_airlock.safe_types import UnsafeDeserializationGuard
from agent_airlock.ssrf_egress_guard import SSRFEgressGuard, SSRFEgressVerdict


class TestTextPickleLeadingWhitespace:
    """Finding 1: a text pickle behind leading whitespace must be refused."""

    @pytest.fixture
    def guard(self) -> UnsafeDeserializationGuard:
        return UnsafeDeserializationGuard(advisory="CVE-2026-25874")

    @pytest.mark.parametrize(
        "prefix",
        ["   ", "\t", "\t ", "\r", "\x0b", "\x0c", " \t \t "],
    )
    def test_leading_whitespace_global_pickle_is_refused(
        self, guard: UnsafeDeserializationGuard, prefix: str
    ) -> None:
        payload = prefix + "cos\nsystem\n(S'id'\ntR."
        decision = guard.evaluate({"blob": payload})
        assert decision.allowed is False
        assert decision.verdict.value == "deny_text_pickle"

    def test_inst_opcode_behind_spaces_is_refused(self, guard: UnsafeDeserializationGuard) -> None:
        # ``i`` (INST) is the other code-executing opcode the GLOBAL pattern matches.
        payload = "  i__main__\nFoo\n(S'x'\ntR."
        assert guard.evaluate({"blob": payload}).allowed is False

    def test_the_stripped_form_stays_refused(self, guard: UnsafeDeserializationGuard) -> None:
        assert guard.evaluate({"blob": "cos\nsystem\n(S'id'\ntR."}).allowed is False

    @pytest.mark.parametrize(
        "benign",
        [
            '{"a": 1, "b": "hello"}',
            "please read the config file and continue",
            "   just some indented prose, nothing to load",
            "c:\\\\Users\\\\x\\\\notes.txt",  # a Windows path, not a pickle
        ],
    )
    def test_benign_values_still_admitted(
        self, guard: UnsafeDeserializationGuard, benign: str
    ) -> None:
        assert guard.evaluate({"blob": benign}).allowed is True


class TestAuthorityParserDifferential:
    """Finding 2: a backslash/control char in the URL authority must be refused."""

    def test_helper_flags_backslash_userinfo(self) -> None:
        assert authority_has_differential(r"http://127.0.0.1\@api.allowed.example/") is True

    @pytest.mark.parametrize(
        "ctrl",
        ["\\", "\t", "\n", "\r"],
    )
    def test_helper_flags_each_differential_char(self, ctrl: str) -> None:
        assert authority_has_differential(f"http://127.0.0.1{ctrl}@allowed.example/") is True

    @pytest.mark.parametrize(
        "url",
        [
            "https://api.allowed.example/v1/x?q=1#frag",
            r"https://api.allowed.example/a\b",  # backslash in the PATH is harmless
            "https://api.allowed.example",
            "api.allowed.example:443",  # bare host
        ],
    )
    def test_helper_passes_well_formed_urls(self, url: str) -> None:
        assert authority_has_differential(url) is False

    def test_validate_endpoint_refuses_backslash_host(self) -> None:
        policy = EndpointPolicy(allowed_endpoints=["api.allowed.example"])
        with pytest.raises(NetworkBlockedError) as excinfo:
            validate_endpoint(r"http://127.0.0.1\@api.allowed.example/", policy)
        assert excinfo.value.details["reason"] == "malformed_authority"

    def test_validate_endpoint_still_admits_the_allowlisted_host(self) -> None:
        policy = EndpointPolicy(allowed_endpoints=["api.allowed.example"])
        validate_endpoint("https://api.allowed.example/v1/data", policy)  # no raise

    def test_ssrf_guard_refuses_backslash_host(self) -> None:
        guard = SSRFEgressGuard(
            allow_internal_hosts=["api.allowed.example"],
            resolver=lambda h: ["93.184.216.34"] if h == "api.allowed.example" else ["127.0.0.1"],
        )
        decision = guard.check_url(r"http://127.0.0.1\@api.allowed.example/")
        assert decision.allowed is False
        assert decision.verdict is SSRFEgressVerdict.DENY_MALFORMED_AUTHORITY

    def test_ssrf_guard_still_admits_the_allowlisted_host(self) -> None:
        guard = SSRFEgressGuard(
            allow_internal_hosts=["api.allowed.example"],
            resolver=lambda h: ["93.184.216.34"],
        )
        assert guard.check_url("https://api.allowed.example/ok").allowed is True
