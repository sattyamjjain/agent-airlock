"""Command-line interface for Agent-Airlock (V0.4.0).

Provides tools for:
- airlock doctor: Scan codebase for security issues
- airlock verify: Verify Airlock protection status
- airlock audit: Analyze audit logs
"""

from .doctor import doctor
from .verify import verify

__all__ = ["doctor", "verify"]
