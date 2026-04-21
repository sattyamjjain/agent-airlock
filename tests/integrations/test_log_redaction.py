"""Log-redaction filter regression tests (v0.5.3+).

Codifies the class of bug disclosed by Splunk on 2026-04-19 as
CVE-2026-20205: MCP connector logged full raw tool-call payloads —
including cleartext ``SPLUNK_HEC_TOKEN`` kwargs — to a world-readable
audit file. agent-airlock's response is a drop-in ``logging.Filter``
that redacts 14 documented secret shapes before they reach any
handler.

Primary sources
---------------
- Splunk SVD-2026-0419:
  https://advisory.splunk.com/advisories/SVD-2026-0419
- NVD CVE-2026-20205:
  https://nvd.nist.gov/vuln/detail/CVE-2026-20205
"""

from __future__ import annotations

import logging

import pytest

from agent_airlock.integrations.log_redaction import (
    RedactingLogFilter,
    install_airlock_log_redaction,
    uninstall_airlock_log_redaction,
)


@pytest.fixture
def captured() -> list[str]:
    """Drop-in log capture that also carries the airlock filter."""
    return []


@pytest.fixture
def logger(captured: list[str]):
    """A fresh per-test logger with a capture handler AND the airlock filter.

    We apply the filter on the HANDLER, not the logger, so the test's
    root-level caller can't bypass it even by shouting at the parent.
    """
    lg = logging.getLogger("airlock-test-" + str(id(captured)))
    lg.handlers.clear()
    lg.setLevel(logging.DEBUG)

    class CaptureHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(self.format(record))

    h = CaptureHandler()
    h.setFormatter(logging.Formatter("%(message)s"))
    h.addFilter(RedactingLogFilter())
    lg.addHandler(h)
    yield lg
    lg.handlers.clear()


class TestRedactingLogFilter:
    def test_01_clean_log_unchanged(self, logger, captured) -> None:
        """A log record with no secrets must pass through verbatim."""
        logger.info("tool=read_file path=%s", "/tmp/safe.txt")
        assert captured == ["tool=read_file path=/tmp/safe.txt"]

    def test_02_splunk_hec_token_redacted(self, logger, captured) -> None:
        logger.info("splunk_hec_token=11111111-2222-3333-4444-555555555555")
        assert "[REDACTED]" in captured[0]
        assert "11111111-2222-3333-4444-555555555555" not in captured[0]

    def test_03_aws_access_key_redacted(self, logger, captured) -> None:
        logger.info("uploading to aws with AKIAIOSFODNN7EXAMPLE")
        assert "AKIAIOSFODNN7EXAMPLE" not in captured[0]
        assert "[REDACTED]" in captured[0]

    def test_04_anthropic_key_redacted(self, logger, captured) -> None:
        fake = "sk-ant-" + "a" * 40
        logger.info("api_key=%s", fake)
        assert fake not in captured[0]
        assert "[REDACTED]" in captured[0]

    def test_05_multiple_secrets_single_record_all_redacted(self, logger, captured) -> None:
        """A record carrying both an AWS key AND a bearer token has both redacted."""
        logger.info(
            "aws=AKIAIOSFODNN7EXAMPLE bearer=Bearer %s",
            "eyJhbGciOiJIUzI1NiJ9.payload.sig",
        )
        rec = captured[0]
        assert "AKIAIOSFODNN7EXAMPLE" not in rec
        assert "eyJhbGciOiJIUzI1NiJ9.payload.sig" not in rec
        assert rec.count("[REDACTED]") >= 2


class TestInstallUninstallRoundTrip:
    def test_install_is_idempotent(self) -> None:
        """Two installs yield the same filter instance (no double-stacking)."""
        lg = logging.getLogger("airlock-install-idempotent")
        lg.filters.clear()
        try:
            f1 = install_airlock_log_redaction(lg)
            f2 = install_airlock_log_redaction(lg)
            assert f1 is f2
            assert lg.filters.count(f1) == 1
        finally:
            uninstall_airlock_log_redaction(lg)

    def test_uninstall_removes_filter(self) -> None:
        lg = logging.getLogger("airlock-uninstall")
        lg.filters.clear()
        install_airlock_log_redaction(lg)
        assert uninstall_airlock_log_redaction(lg) is True
        # second uninstall is a no-op
        assert uninstall_airlock_log_redaction(lg) is False

    def test_extra_patterns_applied(self, caplog) -> None:
        """Caller-supplied extra patterns augment the default set."""
        lg = logging.getLogger("airlock-extra-patterns")
        lg.filters.clear()
        lg.setLevel(logging.DEBUG)
        install_airlock_log_redaction(
            lg,
            extra_patterns=[r"TENANT-[A-Z0-9]{8}"],
        )
        try:
            with caplog.at_level(logging.DEBUG, logger=lg.name):
                lg.info("visit from TENANT-ABCDEF01")
            assert any("[REDACTED]" in r.getMessage() for r in caplog.records)
            assert not any("TENANT-ABCDEF01" in r.getMessage() for r in caplog.records)
        finally:
            uninstall_airlock_log_redaction(lg)
