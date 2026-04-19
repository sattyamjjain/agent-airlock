"""Canonical exception root for agent-airlock (v0.5.1+).

Historically each module declared its own exception subclass of the built-in
``Exception``. New exceptions introduced from v0.5.1 onward should subclass
``AirlockError`` so users can ``except AirlockError:`` once and catch every
airlock-owned failure. Existing module-local exceptions (e.g.
``PathValidationError``, ``MCPSecurityError``) are intentionally left alone
to avoid breaking ``except`` sites in downstream code; they can be migrated
individually over time.
"""

from __future__ import annotations


class AirlockError(Exception):
    """Canonical base class for errors raised by agent-airlock primitives."""
