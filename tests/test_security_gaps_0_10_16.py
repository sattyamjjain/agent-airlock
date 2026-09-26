"""Regressions for the gaps 0.10.16 closes: what was left unmasked, downgraded or unrecorded.

- The API-key pattern allowed no "_" or "-" after ``sk-``, so OpenAI's project,
  service-account and admin keys (the default since 2024) passed through unmasked, and an
  Anthropic key was masked only up to its first "_".
- The private-key rule matched the ``-----BEGIN ... PRIVATE KEY-----`` line alone, so the
  key material under it was returned as-is.
- Card numbers matched only as contiguous digits; "4111-1111-1111-1111" was not masked.
- ``AIRLOCK_STRICT_MODE`` (deprecated) was applied after ``AIRLOCK_UNKNOWN_ARGS``, so
  ``AIRLOCK_STRICT_MODE=false`` turned ``AIRLOCK_UNKNOWN_ARGS=block`` into stripping.
- An identity set with ``with AirlockContext(...)`` was checked by the policy but never
  written to the audit record.

Key-shaped test values are assembled at runtime, so this file holds nothing a secret
scanner would file as a leaked credential.
"""

from __future__ import annotations

import json
import random
import string
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from agent_airlock import Airlock, AirlockContext, get_current_context, sanitize_output
from agent_airlock.config import AirlockConfig
from agent_airlock.unknown_args import UnknownArgsMode

_RNG = random.Random(16)
_ALNUM = string.ascii_letters + string.digits


def _body(n: int, extra: str = "") -> str:
    return "".join(_RNG.choices(_ALNUM + extra, k=n))


def _visible_chunks(secret: str, text: str, skip: int = 12) -> list[str]:
    """8-character pieces of the secret's body that survived into ``text``."""
    return [
        secret[i : i + 8] for i in range(skip, len(secret) - 12, 8) if secret[i : i + 8] in text
    ]


class TestCurrentKeyFormatsAreMasked:
    @pytest.mark.parametrize(
        "key",
        [
            "sk-" + "proj-" + _body(120, "_-"),
            "sk-" + "svcacct-" + _body(80, "_-"),
            "sk-" + "admin-" + _body(64, "_-"),
            "sk-" + "ant-api03-" + _body(93, "_-") + "AA",
        ],
        ids=["openai-project", "openai-service-account", "openai-admin", "anthropic"],
    )
    def test_no_part_of_the_key_body_is_left(self, key: str) -> None:
        out = sanitize_output(f"here is {key} for you", mask_secrets=True).content

        assert _visible_chunks(key, out) == []
        assert out.endswith(" for you")

    def test_the_legacy_openai_form_is_still_masked(self) -> None:
        key = "sk-" + _body(48)

        out = sanitize_output(f"key {key}", mask_secrets=True).content

        assert _visible_chunks(key, out, skip=8) == []


class TestPrivateKeyMaterialIsMasked:
    @staticmethod
    def _pem(kind: str = "") -> tuple[str, list[str]]:
        lines = [_body(64, "+/") for _ in range(4)]
        head = f"-----BEGIN {kind}" + "PRIVATE KEY-----"
        tail = f"-----END {kind}" + "PRIVATE KEY-----"
        return "\n".join([head, *lines, tail]), lines

    @pytest.mark.parametrize("kind", ["", "RSA ", "EC ", "OPENSSH ", "ENCRYPTED "])
    def test_the_whole_block_is_masked(self, kind: str) -> None:
        pem, lines = self._pem(kind)

        out = sanitize_output(f"before\n{pem}\nafter", mask_secrets=True).content

        assert not any(line in out for line in lines)
        assert out.startswith("before\n") and out.endswith("\nafter")

    def test_a_block_cut_off_before_its_end_line_is_masked(self) -> None:
        pem, lines = self._pem("RSA ")
        truncated = "\n".join(pem.splitlines()[:3])

        out = sanitize_output(truncated, mask_secrets=True).content

        assert not any(line in out for line in lines[:2])


class TestSeparatedCardNumbers:
    @pytest.mark.parametrize(
        "card",
        ["4111-1111-1111-1111", "4111 1111 1111 1111", "5500-0000-0000-0004", "3782-822463-10005"],
    )
    def test_dashes_or_spaces_between_groups(self, card: str) -> None:
        out = sanitize_output(f"card {card} on file", mask_pii=True).content

        assert card not in out
        assert out.startswith("card ") and out.endswith(" on file")

    def test_contiguous_digits_still_match(self) -> None:
        assert "4111111111111111" not in sanitize_output("4111111111111111").content

    def test_a_date_is_not_a_card(self) -> None:
        assert sanitize_output("order 2024-01-15").content == "order 2024-01-15"


class TestTheLegacyStrictModeVariableCannotDowngrade:
    def test_unknown_args_block_survives_strict_mode_false(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AIRLOCK_UNKNOWN_ARGS", "block")
        monkeypatch.setenv("AIRLOCK_STRICT_MODE", "false")

        with pytest.warns(DeprecationWarning):
            config = AirlockConfig()

        assert config.unknown_args is UnknownArgsMode.BLOCK

    @pytest.mark.parametrize(
        ("value", "mode"),
        [("true", UnknownArgsMode.BLOCK), ("false", UnknownArgsMode.STRIP_AND_LOG)],
    )
    def test_alone_it_still_works(
        self, monkeypatch: pytest.MonkeyPatch, value: str, mode: UnknownArgsMode
    ) -> None:
        monkeypatch.delenv("AIRLOCK_UNKNOWN_ARGS", raising=False)
        monkeypatch.setenv("AIRLOCK_STRICT_MODE", value)

        with pytest.warns(DeprecationWarning):
            config = AirlockConfig()

        assert config.unknown_args is mode


def _records(path: Path) -> list[dict[str, Any]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line and not line.startswith("#")]


class TestTheAmbientIdentityIsRecorded:
    def test_the_audit_record_carries_it(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"

        @Airlock(config=AirlockConfig(enable_audit_log=True, audit_log_path=log))
        def export_report(name: str) -> str:
            return name

        with AirlockContext(agent_id="host-agent", session_id="sess-1"):
            export_report(name="q3")

        (record,) = _records(log)
        assert (record["agent_id"], record["session_id"]) == ("host-agent", "sess-1")

    def test_the_tool_sees_it_through_get_current_context(self) -> None:
        @Airlock()
        def whoami() -> str:
            current = get_current_context()
            return current.agent_id if current is not None and current.agent_id else "anonymous"

        with AirlockContext(agent_id="host-agent", roles=["admin"]):
            assert whoami() == "host-agent"
        assert whoami() == "anonymous"

    def test_a_policy_resolver_sees_it(self) -> None:
        seen: list[tuple[str | None, list[str], str | None]] = []

        def pick(context: AirlockContext[Any]) -> Any:
            seen.append((context.agent_id, list(context.roles), context.workspace_id))
            from agent_airlock import SecurityPolicy

            return SecurityPolicy()

        @Airlock(policy=pick)
        def tool() -> str:
            return "ok"

        with AirlockContext(agent_id="a1", roles=["admin"], workspace_id="prod"):
            tool()
        tool()

        assert seen == [("a1", ["admin"], "prod"), (None, [], None)]

    def test_the_calls_own_identity_is_not_overwritten(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"

        @Airlock(config=AirlockConfig(enable_audit_log=True, audit_log_path=log))
        def read(ctx: Any, key: str) -> str:
            return key

        own = SimpleNamespace(context=SimpleNamespace(agent_id="framework-agent"))
        with AirlockContext(agent_id="host-agent"):
            read(own, key="k")

        (record,) = _records(log)
        assert record["agent_id"] == "framework-agent"
