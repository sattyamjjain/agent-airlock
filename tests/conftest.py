"""Suite-wide test configuration."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from agent_airlock._log import structlog
from agent_airlock.audit import AuditLogger
from agent_airlock.runtime import startup_hooks

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
    _hide_host_startup_hooks()


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


# Since 0.10.36 every guarded call checks the interpreter's startup hooks: startup_hook_check
# defaults to "warn", which logs each unknown hook and issues one RuntimeWarning per walk.
# The interpreter running the suite has hooks of its own (coverage's a1_coverage.pth in CI,
# whatever a developer's environment carries), and a test's outcome must not depend on them.
# So the walk sees what a test plants (a temporary or fixture directory it puts on sys.path)
# and never the directories this interpreter started with.
def _resolved(path: str) -> str:
    return os.path.normcase(os.path.realpath(path))


_HOST_DIRECTORIES = frozenset(_resolved(path) for path in startup_hooks._directories())
_real_directories = startup_hooks._directories
_real_customize_hook = startup_hooks._customize_hook


def _planted_directories() -> list[str]:
    return [path for path in _real_directories() if _resolved(path) not in _HOST_DIRECTORIES]


def _planted_customize_hook(
    name: str, kind: startup_hooks.StartupHookKind
) -> startup_hooks.StartupHookFinding | None:
    hook = _real_customize_hook(name, kind)
    # A hook with no file (a finder that raised reports the bare module name) is a test's.
    if hook is None or not os.path.isabs(hook.path):
        return hook
    home = os.path.dirname(hook.path)
    if os.path.basename(hook.path).startswith("__init__."):
        home = os.path.dirname(home)  # a package's own directory is below the host's
    return None if _resolved(home) in _HOST_DIRECTORIES else hook


def _hide_host_startup_hooks() -> None:
    # For the whole run, before collection: a function-scoped fixture left a guarded call in a
    # module- or session-scoped fixture to walk the host, and keep what it found for the rest
    # of the run (`_process_walk`).
    startup_hooks._directories = _planted_directories
    startup_hooks._customize_hook = _planted_customize_hook
