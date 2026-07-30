"""Tests for the zero-dependency logging shim (``agent_airlock._log``).

The library logs through ``from ._log import structlog``. When ``structlog`` is
installed (as it is under ``[dev]`` / CI) that name is the real module and these
tests confirm the re-export. The stdlib-``logging``-backed fallback classes are
always defined, so they are exercised directly here — that is what keeps a bare
``pip install agent-airlock`` (Pydantic only) a supported, tested path even
though the CI coverage job always has real structlog present.
"""

from __future__ import annotations

import logging

import pytest

from agent_airlock import _log
from agent_airlock._log import _noop, _ShimBoundLogger, _StructlogShim


class TestReExport:
    def test_structlog_name_is_exported(self) -> None:
        # Under [dev]/CI this is the real module; the point is that the name
        # exists and yields a logger with the structlog call surface.
        logger = _log.structlog.get_logger("agent-airlock.test")
        assert hasattr(logger, "info")
        assert hasattr(logger, "bind")

    def test_dunder_all(self) -> None:
        assert _log.__all__ == ["structlog"]


class TestShimBoundLogger:
    def test_render_without_context(self) -> None:
        assert _ShimBoundLogger._render("event_only", {}) == "event_only"

    def test_render_folds_keyword_context_into_message(self) -> None:
        rendered = _ShimBoundLogger._render("blocked", {"tool": "rm", "n": 3})
        assert rendered == "blocked tool='rm' n=3"

    @pytest.mark.parametrize(
        "method,level",
        [
            ("debug", logging.DEBUG),
            ("info", logging.INFO),
            ("warning", logging.WARNING),
            ("error", logging.ERROR),
            ("critical", logging.CRITICAL),
        ],
    )
    def test_levels_emit_with_folded_context(
        self, method: str, level: int, caplog: pytest.LogCaptureFixture
    ) -> None:
        logger = _ShimBoundLogger("agent-airlock.shim.levels")
        with caplog.at_level(logging.DEBUG, logger="agent-airlock.shim.levels"):
            getattr(logger, method)("did_thing", reason="because")
        assert caplog.records, f"{method} produced no log record"
        record = caplog.records[-1]
        assert record.levelno == level
        assert record.getMessage() == "did_thing reason='because'"

    def test_exception_logs_at_error_with_exc_info(self, caplog: pytest.LogCaptureFixture) -> None:
        logger = _ShimBoundLogger("agent-airlock.shim.exc")
        with caplog.at_level(logging.ERROR, logger="agent-airlock.shim.exc"):
            try:
                raise ValueError("boom")
            except ValueError:
                logger.exception("handling_failed", where="unit-test")
        record = caplog.records[-1]
        assert record.levelno == logging.ERROR
        assert record.exc_info is not None
        assert record.getMessage() == "handling_failed where='unit-test'"

    def test_bind_returns_self(self) -> None:
        logger = _ShimBoundLogger("agent-airlock.shim.bind")
        assert logger.bind(request_id="abc", tenant="t1") is logger


class TestStructlogShim:
    def test_get_logger_returns_bound_logger(self) -> None:
        assert isinstance(_StructlogShim.get_logger("x"), _ShimBoundLogger)

    def test_get_logger_default_name(self) -> None:
        assert isinstance(_StructlogShim.get_logger(), _ShimBoundLogger)

    def test_configure_is_a_noop(self) -> None:
        assert _StructlogShim.configure(processors=[], logger_factory=None) is None

    def test_make_filtering_bound_logger_returns_the_logger_type(self) -> None:
        assert _StructlogShim.make_filtering_bound_logger(logging.INFO) is _ShimBoundLogger

    def test_print_logger_factory_is_a_noop(self) -> None:
        assert _StructlogShim.PrintLoggerFactory(file=None) is None

    def test_processor_and_renderer_names_exist_and_are_callable(self) -> None:
        # Mirrors what the four CLI benches build: a processors list plus a
        # console renderer, all handed to the no-op configure().
        assert _StructlogShim.processors.add_log_level("x", "info", {}) is None
        assert _StructlogShim.processors.TimeStamper(fmt="iso") is None
        assert _StructlogShim.dev.ConsoleRenderer(colors=False) is None

    def test_cli_configure_pattern_runs_through_the_shim(self) -> None:
        # Exactly the shape of cli/corpus_bench.py's setup, proving a bare
        # install can run the benches without structlog installed.
        shim = _StructlogShim()
        shim.configure(
            processors=[
                shim.processors.add_log_level,
                shim.processors.TimeStamper(fmt="iso"),
                shim.dev.ConsoleRenderer(colors=False),
            ],
            logger_factory=shim.PrintLoggerFactory(file=None),
            wrapper_class=shim.make_filtering_bound_logger(20),
        )


class TestNoop:
    def test_noop_swallows_everything(self) -> None:
        assert _noop() is None
        assert _noop(1, 2, key="v") is None
