"""Command-line interface for Agent-Airlock (V0.4.0).

Provides tools for:
- airlock doctor: Scan codebase for security issues
- airlock verify: Verify Airlock protection status
- airlock audit: Analyze audit logs
"""

from .doctor import doctor
from .egress_bench import egress_bench
from .verify import verify

# NOTE: cli.scan_tools is intentionally NOT imported here — it is invoked as a
# console script (``airlock-scan-tools``) or via ``python -m
# agent_airlock.cli.scan_tools``; eager import would trigger a runpy
# double-import RuntimeWarning under ``-m``.

__all__ = ["doctor", "egress_bench", "verify"]
