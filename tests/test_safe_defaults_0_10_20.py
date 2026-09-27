"""Regressions for the safer defaults in 0.10.20.

- A generator tool's body runs when it is iterated, after ``@Airlock`` has returned, so it
  ran outside the network airgap and without the call's context, and nothing it yielded
  was sanitized: under ``allow_egress=False`` it could still open a socket, and it
  streamed PII unmasked.
- The audit log recorded argument values as given (only parameter names were checked),
  in a file that lands in the working directory by default.
- An audit log that could not be created crashed ``@Airlock`` at decoration time, so the
  default config broke any import from an unwritable working directory.
- ``get_default_backend()`` fell back to running code in-process with no isolation.
- Six settings that were never applied are deprecated (their tests live with the 0.10.19
  ones in ``test_config_correctness_0_10_19.py``).
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import socket
import string
import warnings
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest

from agent_airlock import Airlock, AirlockConfig, AirlockContext, get_current_context
from agent_airlock.audit import AuditLogger
from agent_airlock.network import NetworkPolicy

_RNG = random.Random(20)
_AIRGAPPED = AirlockConfig(network_policy=NetworkPolicy(allow_egress=False))


def _connect() -> str:
    """Try a local TCP connection; name whatever stopped it."""
    s = socket.socket()
    s.settimeout(0.5)
    try:
        s.connect(("127.0.0.1", 9))
        return "connected"
    except Exception as e:  # noqa: BLE001 - the name of the exception is the result
        return type(e).__name__
    finally:
        s.close()


def _key() -> str:
    """An OpenAI-project-shaped key, assembled so no scanner files this file."""
    body = "".join(_RNG.choices(string.ascii_letters + string.digits, k=60))
    return "sk-" + "proj-" + body


def _records(path: Path) -> list[dict[str, Any]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line and not line.startswith("#")]


class TestGeneratorToolsRunUnderTheCallsGuards:
    def test_each_step_runs_inside_the_airgap(self) -> None:
        @Airlock(config=_AIRGAPPED)
        def stream() -> Generator[str, None, None]:
            yield _connect()

        assert list(stream()) == ["NetworkBlockedError"]

    def test_yielded_items_are_masked_like_returned_values(self) -> None:
        @Airlock()
        def stream() -> Generator[Any, None, None]:
            yield "mail john@example.com"
            yield {"contact": "jane@example.com"}

        text, record = list(stream())

        assert "john@example.com" not in text
        assert "jane@example.com" not in record["contact"]

    def test_masking_follows_sanitize_output(self) -> None:
        @Airlock(config=AirlockConfig(sanitize_output=False))
        def stream() -> Generator[str, None, None]:
            yield "mail john@example.com"

        assert list(stream()) == ["mail john@example.com"]

    def test_the_calls_context_is_current_inside_the_body(self) -> None:
        @Airlock()
        def stream() -> Generator[str | None, None, None]:
            current = get_current_context()
            yield current.agent_id if current is not None else None

        with AirlockContext(agent_id="host-agent"):
            gen = stream()
        # Iterated after the `with` block ended: the call's context still applies.
        assert list(gen) == ["host-agent"]

    def test_cleanup_after_an_early_close_runs_inside_the_airgap(self) -> None:
        cleanup: list[str] = []

        @Airlock(config=_AIRGAPPED)
        def stream() -> Generator[int, None, None]:
            try:
                yield 1
                yield 2
            finally:
                cleanup.append(_connect())

        gen = stream()
        assert next(gen) == 1
        gen.close()

        assert cleanup == ["NetworkBlockedError"]

    def test_send_and_the_return_value_pass_through(self) -> None:
        @Airlock()
        def echo() -> Generator[str, str, str]:
            got = yield "ready"
            yield f"got {got}"
            return "done"

        gen = echo()
        assert next(gen) == "ready"
        assert gen.send("ping") == "got ping"
        with pytest.raises(StopIteration) as stop:
            next(gen)
        assert stop.value.value == "done"

    def test_an_async_generator_tool(self) -> None:
        @Airlock(config=_AIRGAPPED)
        async def stream() -> Any:
            yield _connect()
            yield "mail john@example.com"

        async def collect() -> list[Any]:
            return [item async for item in stream()]

        blocked, text = asyncio.run(collect())

        assert blocked == "NetworkBlockedError"
        assert "john@example.com" not in text


class TestTheAuditLogMasksArgumentValues:
    def test_personal_data_and_keys_in_any_argument(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        key = _key()

        @Airlock(config=AirlockConfig(audit_log_path=log))
        def send(to: str, note: str) -> str:
            return "sent"

        send(to="john@example.com", note=f"use {key}")

        (record,) = _records(log)
        preview = json.dumps(record["args_preview"])
        assert "john@example.com" not in preview
        assert key[10:30] not in preview

    def test_a_key_that_straddles_the_preview_cut(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        key = _key()

        @Airlock(config=AirlockConfig(audit_log_path=log))
        def store(blob: str) -> str:
            return "stored"

        # The preview keeps 100 characters; the key starts at 61, so cutting before
        # masking would have written its first 39 characters.
        store(blob="x" * 60 + " " + key + " tail")

        (record,) = _records(log)
        assert key[10:30] not in record["args_preview"]["blob"]


class TestAnAuditLogThatCannotBeCreated:
    @pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root writes anywhere")
    def test_decorating_and_calling_still_work(self, tmp_path: Path) -> None:
        locked = tmp_path / "locked"
        locked.mkdir()
        locked.chmod(0o555)
        try:

            @Airlock(config=AirlockConfig(audit_log_path=locked / "audit.jsonl"))
            def tool(x: int) -> int:
                return x * 2

            assert tool(x=2) == 4
            assert AuditLogger(locked / "audit.jsonl").enabled is False
        finally:
            locked.chmod(0o755)


class TestAirlockAuditLogPath:
    def test_it_moves_the_default(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setenv("AIRLOCK_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))

        assert AirlockConfig().audit_log_path == tmp_path / "audit.jsonl"

    def test_a_path_given_in_code_wins(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("AIRLOCK_AUDIT_LOG_PATH", str(tmp_path / "env.jsonl"))

        config = AirlockConfig(audit_log_path=Path("airlock_audit.json"))

        assert config.audit_log_path == Path("airlock_audit.json")

    def test_a_path_given_in_toml_wins(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("AIRLOCK_AUDIT_LOG_PATH", str(tmp_path / "env.jsonl"))
        toml = tmp_path / "airlock.toml"
        toml.write_text('[airlock]\naudit_log_path = "from-toml.jsonl"\n', encoding="utf-8")

        assert AirlockConfig.from_toml(toml).audit_log_path == Path("from-toml.jsonl")


class TestTheDeprecationSaysWhen:
    def test_the_warning_names_the_removal(self) -> None:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            AirlockConfig(require_done_receipt=True)

        (warning,) = [w for w in caught if w.category is FutureWarning]
        assert "will be removed in v1.0.0" in str(warning.message)
        assert "DoneReceiptGuard" in str(warning.message)
