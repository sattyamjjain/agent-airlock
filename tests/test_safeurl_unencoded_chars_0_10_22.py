"""Regressions for 0.10.22: ``SafeURL`` checked where a URL points, never what it carries.

It refused a bad scheme, a metadata host, a private address. It did not look at the
characters, so ``https://example.com/";open -a Calculator;# `` passed. A tool that hands
its URL to a shell inside double quotes, as pi-llm-wiki did (CVE-2026-102911, issue #256),
runs that. ``SafeURL`` now refuses the ASCII characters RFC 3986 requires to be
percent-encoded, and the shell command substitution ``$(``, which is legal URL syntax but
which no URL needs unencoded.
"""

from __future__ import annotations

import pytest

from agent_airlock import Airlock, SafeURL, SafeURLAllowHttp
from agent_airlock.safe_types import SafeURLValidationError, SafeURLValidator
from agent_airlock.self_heal import BlockReason

#: One of each ASCII character RFC 3986 never allows unencoded, controls sampled.
MUST_BE_ENCODED = (
    " ",
    '"',
    "<",
    ">",
    "\\",
    "^",
    "`",
    "{",
    "|",
    "}",
    "\n",
    "\r",
    "\t",
    "\x00",
    "\x7f",
)


class TestSafeURLRefusesWhatAURLMustEncode:
    @pytest.mark.parametrize("char", MUST_BE_ENCODED, ids=[repr(c) for c in MUST_BE_ENCODED])
    def test_each_character_is_refused(self, char: str) -> None:
        with pytest.raises(SafeURLValidationError) as exc:
            SafeURLValidator()(f"https://example.com/a{char}b")

        assert exc.value.reason == "unencoded_character"
        assert repr(char) in str(exc.value)

    def test_shell_command_substitution_is_refused(self) -> None:
        with pytest.raises(SafeURLValidationError) as exc:
            SafeURLValidator()("https://example.com/$(whoami)")

        assert exc.value.reason == "shell_substitution"
        assert "%24(" in str(exc.value)

    def test_the_scheme_is_still_checked_first(self) -> None:
        # A string that is not a URL at all keeps its old, more basic reason.
        with pytest.raises(SafeURLValidationError) as exc:
            SafeURLValidator()('";open -a Calculator;# ')

        assert exc.value.reason == "invalid_scheme"


class TestRealURLsStillPass:
    @pytest.mark.parametrize(
        "url",
        [
            "https://graph.microsoft.com/v1.0/users?$select=displayName&$top=5",
            "https://en.wikipedia.org/wiki/Python_(programming_language)",
            "https://例え.jp/パス?q=café",
            "https://example.com/my%20file.pdf?q=%24(id)",
            "https://example.com/a;b=c,d!e*f'g+h&i=j~k@l",
            "https://[2606:4700::1111]/dns-query",
        ],
        ids=["OData $select", "parentheses", "IRI", "percent-encoded", "sub-delims", "IPv6"],
    )
    def test_it_passes(self, url: str) -> None:
        assert SafeURLValidator()(url) == url


class TestThroughTheDecorator:
    def test_a_raw_space_is_refused_with_a_hint_the_model_can_follow(self) -> None:
        @Airlock()
        def fetch(url: SafeURL) -> str:
            return "fetched"

        result = fetch(url="https://example.com/my file.pdf")

        assert isinstance(result, dict)
        assert result["block_reason"] == BlockReason.VALIDATION_ERROR.value
        assert "percent-encoded" in result["error"]
        assert fetch(url="https://example.com/my%20file.pdf") == "fetched"

    def test_safe_url_allow_http_applies_the_same_rule(self) -> None:
        @Airlock()
        def fetch(url: SafeURLAllowHttp) -> str:
            return "fetched"

        result = fetch(url='http://example.com/"|sh')

        assert isinstance(result, dict)
        assert result["block_reason"] == BlockReason.VALIDATION_ERROR.value
