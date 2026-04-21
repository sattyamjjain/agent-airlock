"""Log-redaction filter for Python ``logging`` pipelines (v0.5.3+).

Motivation
----------
On 2026-04-19 Splunk disclosed **CVE-2026-20205** (CVSS 7.5) in its
official MCP connector: the connector logged full raw tool-call
payloads — including cleartext ``SPLUNK_HEC_TOKEN`` kwargs — to a
world-readable audit file under ``$SPLUNK_HOME/var/log/splunkd.log``.
Exploited in the wild against two SOC teams. Fixed in splunk-mcp
0.7.3.

agent-airlock ships redaction primitives elsewhere (the sanitizer
surface used by the session-snapshot guard and Auto Memory write
path). What was missing was an out-of-the-box ``logging.Filter`` that
applies the same redaction discipline to every LogRecord flowing
through a user's logging pipeline. This module is that filter.

Usage::

    import logging
    from agent_airlock.integrations.log_redaction import (
        install_airlock_log_redaction,
    )

    install_airlock_log_redaction()  # installs on root logger
    logging.info("token=ghp_%s", secret)
    # → "token=[REDACTED]"

Pattern sources
---------------
The default pattern set lives in
``src/agent_airlock/fixtures/redaction_patterns_2026_04.txt``. Each
pattern carries a primary-source citation above it. Callers can
extend with additional patterns via the ``extra_patterns`` parameter
without forking the fixture.

References
----------
- Splunk SVD-2026-0419:
  https://advisory.splunk.com/advisories/SVD-2026-0419
- NVD CVE-2026-20205:
  https://nvd.nist.gov/vuln/detail/CVE-2026-20205
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from pathlib import Path

_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "redaction_patterns_2026_04.txt"
_REDACTED = "[REDACTED]"
_FILTER_ATTR = "_airlock_redaction_filter"


def _load_default_patterns() -> list[re.Pattern[str]]:
    """Parse the shipped fixture into compiled regexes.

    Blank lines and ``#``-comment lines are ignored. Syntactically
    invalid patterns raise ``re.error`` at module load — we want a
    noisy failure rather than a silently-unfilled filter.
    """
    patterns: list[re.Pattern[str]] = []
    for line in _FIXTURE.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        patterns.append(re.compile(stripped))
    return patterns


def _redact_text(text: str, patterns: list[re.Pattern[str]]) -> str:
    out = text
    for pat in patterns:
        out = pat.sub(_REDACTED, out)
    return out


class RedactingLogFilter(logging.Filter):
    """Logging filter that replaces every pattern-matched span with ``[REDACTED]``.

    Applies to both ``record.msg`` and every element of ``record.args``
    (strings only — non-string args are left untouched so ``%d`` format
    specifiers keep working). Idempotent: applying the filter twice is
    safe because ``[REDACTED]`` itself does not match any shipped
    pattern.

    Instances are safe to share across loggers.
    """

    def __init__(self, *, patterns: list[re.Pattern[str]] | None = None) -> None:
        super().__init__()
        self._patterns: list[re.Pattern[str]] = (
            patterns if patterns is not None else _load_default_patterns()
        )

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003 — Filter API
        # Redact ``record.msg`` when it is a string template.
        if isinstance(record.msg, str):
            record.msg = _redact_text(record.msg, self._patterns)

        # Redact every string in ``record.args``. Leave non-strings
        # (ints, dicts, etc.) alone so %-formatting keeps working.
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: _redact_text(v, self._patterns) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
            else:
                record.args = tuple(
                    _redact_text(a, self._patterns) if isinstance(a, str) else a
                    for a in record.args
                )
        return True


def install_airlock_log_redaction(
    logger: logging.Logger | None = None,
    *,
    extra_patterns: Iterable[str] = (),
) -> RedactingLogFilter:
    """Install :class:`RedactingLogFilter` on ``logger`` (root if None).

    Idempotent. Re-installing on a logger that already carries the
    airlock filter returns the existing instance rather than stacking a
    second copy — this prevents double-redaction round-trips and makes
    the call safe inside application-startup code that may run twice
    under testing.

    Args:
        logger: Target logger. ``None`` means the root logger.
        extra_patterns: Additional regex strings appended to the
            default set. Use for tenant-specific secret shapes.

    Returns:
        The installed filter instance, so callers can pass it back to
        :func:`uninstall_airlock_log_redaction` later.
    """
    target = logger if logger is not None else logging.getLogger()

    # Short-circuit on idempotent re-installation.
    existing = getattr(target, _FILTER_ATTR, None)
    if isinstance(existing, RedactingLogFilter):
        return existing

    patterns = _load_default_patterns()
    for extra in extra_patterns:
        patterns.append(re.compile(extra))

    flt = RedactingLogFilter(patterns=patterns)
    target.addFilter(flt)
    setattr(target, _FILTER_ATTR, flt)
    return flt


def uninstall_airlock_log_redaction(logger: logging.Logger | None = None) -> bool:
    """Remove a previously-installed filter. Returns True if one was removed."""
    target = logger if logger is not None else logging.getLogger()
    existing = getattr(target, _FILTER_ATTR, None)
    if isinstance(existing, RedactingLogFilter):
        target.removeFilter(existing)
        delattr(target, _FILTER_ATTR)
        return True
    return False


__all__ = [
    "RedactingLogFilter",
    "install_airlock_log_redaction",
    "uninstall_airlock_log_redaction",
]
