"""AgentDojo adaptive-attacker robustness bench for agent-airlock.

Registers airlock as an AgentDojo defense and measures its effect on the
``tool_knowledge`` attack over a pinned workspace + banking subset. Deterministic
(no model) by default; a real model-in-the-loop pass is available via ``--model``.

``agentdojo`` is an optional ``bench`` extra — the airlock core stays zero-dep.

Public API lives in :mod:`benchmarks.agentdojo.run` (imported directly rather than
re-exported here, so ``python -m benchmarks.agentdojo.run`` does not double-import).

Run::

    python -m benchmarks.agentdojo.run
"""

from __future__ import annotations
