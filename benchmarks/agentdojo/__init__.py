"""AgentDojo indirect-prompt-injection bench for agent-airlock.

Registers airlock as an AgentDojo defense and measures its effect under AgentDojo's
fixed-template ``tool_knowledge`` attack (not an adaptive attacker) over the pinned
workspace, banking, travel and slack suites. Deterministic (no model) by default; a real
model-in-the-loop pass is available via ``--model ... --run``, and
``replay_published`` scores AgentDojo's own published Claude runs against the same policy.

``agentdojo`` is an optional ``bench`` extra — the airlock core stays zero-dep.

Public API lives in :mod:`benchmarks.agentdojo.run` (imported directly rather than
re-exported here, so ``python -m benchmarks.agentdojo.run`` does not double-import).

Run::

    python -m benchmarks.agentdojo.run
    python -m benchmarks.agentdojo.replay_published --fetch
"""

from __future__ import annotations
