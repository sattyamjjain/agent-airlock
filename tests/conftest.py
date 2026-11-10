"""Suite-wide test configuration."""

from __future__ import annotations

import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from agent_airlock._log import structlog
from agent_airlock.audit import AuditLogger

# A tool decorated with the default config writes its audit log to airlock_audit.json in
# the working directory, which for a test run is the checkout: it had grown past 75MB there.
# AuditLogger keeps one instance per resolved path, so registering the default path with a
# logger that writes elsewhere sends those records to a temporary file instead. Tests that
# pass their own audit_log_path are unaffected.
_DEFAULT_AUDIT_PATH = Path("airlock_audit.json").resolve()
_REDIRECTED = AuditLogger(Path(tempfile.mkdtemp(prefix="airlock-audit-")) / "airlock_audit.json")


def _redirect_default_audit_log() -> None:
    AuditLogger._instances.setdefault(_DEFAULT_AUDIT_PATH, _REDIRECTED)


def pytest_configure(config: pytest.Config) -> None:
    # Before collection, so tools decorated at import time get the redirected logger too.
    _redirect_default_audit_log()


@pytest.fixture(autouse=True)
def _default_audit_log_outside_the_checkout() -> Iterator[None]:
    # Some tests clear AuditLogger._instances; register the redirect again for each test.
    _redirect_default_audit_log()
    yield


@pytest.fixture(autouse=True)
def _structlog_config_does_not_leak() -> Iterator[None]:
    # The scan-tools, trace, corpus-bench and negotiation-bench CLIs call structlog.configure
    # with PrintLoggerFactory(file=sys.stderr), which binds whatever sys.stderr is at that
    # moment: under capsys, a capture stream that is closed when the test ends. structlog's
    # configuration is global, so the next test that logged at ERROR wrote to the closed
    # stream and failed with "I/O operation on closed file" (seen running
    # tests/test_scan_tools.py before tests/test_tooling_honesty_0_10_24.py). Put back
    # whatever configuration the test started with.
    get_config = getattr(structlog, "get_config", None)
    if get_config is None:  # the stdlib shim of a bare install has no global configuration
        yield
        return
    saved = get_config()
    yield
    structlog.configure(**saved)
