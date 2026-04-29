"""``airlock studio`` — hosted policy-rehearsal sandbox (Feature C, v0.6.0+).

Stdlib HTTP server (``http.server``) renders a paste-an-agent-
transcript form, evaluates each line against the loaded policy
bundle, and emits inline verdicts with a diff against a previous
run. FastAPI is gated behind the ``airlock[studio]`` extra so the
base install stays lean — the stdlib path is the always-available
default.

Reference
---------
* Microsoft Agent Governance Toolkit (positioning anchor):
  https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/
"""

from __future__ import annotations

from .app import (
    StudioApp,
    StudioState,
    rehearse_transcript,
)

__all__ = [
    "StudioApp",
    "StudioState",
    "rehearse_transcript",
]
