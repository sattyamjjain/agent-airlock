"""Regressions for 0.10.25: refusals no longer map a deny list for the model.

A blocked call returns ``AirlockResponse.to_dict()`` so the model can retry against it.
Until 0.10.25:

- A path refusal's metadata handed the model the deny pattern that matched and where a
  refused symlink sits.
- A ``tool_denied`` policy refusal quoted the ``denied_tools`` glob that matched.
- A ``SafePath`` deny-list match quoted the pattern in its validation message.

The rule: a refusal reaches a model whose context may be attacker-influenced. It discloses
the space the model may use (allowed roots, allowed endpoints, argument names, the tool's
own schema constraints) and withholds the space it may not (deny patterns, deny globs,
symlink locations). A deny list is incomplete by nature, and publishing its coverage helps
a search for the entries it lacks. The operator keeps all of it, through ``on_blocked`` and
the log.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from agent_airlock import (
    Airlock,
    AirlockConfig,
    EndpointPolicy,
    FilesystemPolicy,
    SafePath,
    SecurityPolicy,
)
from agent_airlock.self_heal import handle_path_violation


def _refused(result: Any) -> dict[str, Any]:
    """``result`` as a refusal dict, failing the test if the call was not refused."""
    assert isinstance(result, dict), f"the call ran: {result!r}"
    assert result.get("success") is False, f"the call was not refused: {result!r}"
    return result


@pytest.fixture
def roots(tmp_path: Path) -> tuple[Path, Path]:
    """An allowed root holding a file, and a file outside it."""
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    (allowed / "ok.txt").write_text("fine")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret")
    return allowed, outside / "secret.txt"


class TestPathHints:
    def test_a_deny_pattern_match_is_not_quoted_back(self, roots: tuple[Path, Path]) -> None:
        allowed, _ = roots
        (allowed / "notes.sekret").write_text("x")
        policy = FilesystemPolicy([allowed], deny_patterns=["*.sekret"])

        @Airlock(config=AirlockConfig(filesystem_policy=policy))
        def read(path: str) -> str:
            return Path(path).read_text()

        result = _refused(read(path=str(allowed / "notes.sekret")))

        assert result["metadata"]["violation_type"] == "denied_pattern"
        assert "*.sekret" not in json.dumps(result)
        assert "pattern" not in result["metadata"]

    def test_the_operator_still_sees_the_pattern(self, roots: tuple[Path, Path]) -> None:
        allowed, _ = roots
        seen: list[str] = []
        config = AirlockConfig(
            filesystem_policy=FilesystemPolicy([allowed], deny_patterns=["**/private/**"]),
            on_blocked=lambda name, message, info: seen.append(message),
        )

        @Airlock(config=config)
        def read(path: str) -> str:
            return "ran"

        result = _refused(read(path=str(allowed / "private" / "a.txt")))

        assert "**/private/**" not in json.dumps(result)
        assert seen and "**/private/**" in seen[0]

    def test_a_symlink_refusal_withholds_where_the_link_is(self, tmp_path: Path) -> None:
        real = tmp_path / "real"
        real.mkdir()
        (real / "a.txt").write_text("x")
        link = tmp_path / "linked"
        try:
            os.symlink(real, link)
        except (OSError, NotImplementedError):
            pytest.skip("this platform cannot create a symlink")

        @Airlock(config=AirlockConfig(filesystem_policy=FilesystemPolicy([tmp_path])))
        def read(path: str) -> str:
            return "ran"

        result = _refused(read(path=str(link / "a.txt")))

        assert result["metadata"]["violation_type"] == "symlink_detected"
        assert "symlink_location" not in result["metadata"]

    def test_withheld_details_are_dropped_and_the_rest_kept(self) -> None:
        response = handle_path_violation(
            "t",
            "/srv/.env",
            "denied_pattern",
            {"pattern": "*.env", "resolved_path": "/srv/.env", "symlink_location": "/srv"},
        )

        assert "pattern" not in response.metadata
        assert "symlink_location" not in response.metadata
        assert response.metadata["resolved_path"] == "/srv/.env"


class TestPolicyDenialHidesGlob:
    def test_the_denied_tools_glob_is_not_quoted_back(self) -> None:
        @Airlock(policy=SecurityPolicy(denied_tools=["rm_*"]))
        def rm_rf(target: str) -> str:
            return "ran"

        result = _refused(rm_rf(target="/"))

        assert "rm_*" not in json.dumps(result)
        assert "Tool 'rm_rf' is denied by policy" in result["error"]

    def test_the_operator_still_gets_the_glob(self) -> None:
        seen: list[tuple[str, dict[str, Any]]] = []

        @Airlock(
            policy=SecurityPolicy(denied_tools=["rm_*"]),
            config=AirlockConfig(
                on_blocked=lambda name, message, info: seen.append((message, info))
            ),
        )
        def rm_rf(target: str) -> str:
            return "ran"

        _refused(rm_rf(target="/"))

        assert len(seen) == 1
        message, info = seen[0]
        assert message == "Tool 'rm_rf' is denied by policy (matches 'rm_*')"
        assert info["violation_type"] == "tool_denied"
        assert info["pattern"] == "rm_*"


class TestOtherRefusalsWithholdDenyLists:
    def test_a_safepath_deny_list_match_is_not_quoted_back(self) -> None:
        @Airlock()
        def read(path: SafePath) -> str:
            return "ran"

        # Strict mode admits only a Path instance here; a host that converts the model's
        # string to one reaches the deny-list check.
        result = _refused(read(path=Path("/srv/app/.env")))

        assert result["block_reason"] == "validation_error"
        assert "denied pattern" not in json.dumps(result)
        assert result["metadata"]["errors"][0]["message"] == (
            "Value error, this path matches a protected location"
        )

    def test_a_safepath_structural_rule_is_still_named(self) -> None:
        @Airlock()
        def read(path: SafePath) -> str:
            return "ran"

        result = _refused(read(path=Path("../etc/passwd")))

        assert "parent traversal" in result["error"]

    def test_an_endpoint_refusal_does_not_quote_the_blocked_pattern(self) -> None:
        policy = EndpointPolicy(
            allowed_endpoints=["api.example.com"], blocked_patterns=["*.exfil-host.test"]
        )

        @Airlock(config=AirlockConfig(endpoint_policies={"fetch": policy}))
        def fetch(url: str) -> str:
            return "ran"

        result = _refused(fetch(url="https://drop.exfil-host.test/x"))

        assert result["block_reason"] == "endpoint_blocked"
        assert "*.exfil-host.test" not in json.dumps(result)
        assert any("api.example.com" in hint for hint in result["fix_hints"])
