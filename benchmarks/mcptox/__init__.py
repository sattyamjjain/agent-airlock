"""MCPTox: replay recorded tool calls through ``@Airlock``, and run Claude 5.5 on it fresh.

MCPTox (Wang et al., arXiv:2508.14925) poisons one tool description on each of 45 live MCP
servers and records what 27 models did. Its released ``response_all.json`` (1,348 cases)
is fetched at run time from a pinned commit and verified by sha256; it is never vendored,
because the source repository carries no license. Only aggregates are committed.

Subcommands (``python -m benchmarks.mcptox <cmd> --help``):

* ``clean-view`` prints only the clean side of each server (tool blocks and clean
  queries). The least-privilege labels in :mod:`.lp_labels` were written from this
  output alone, before any replay code existed.
* ``replay`` (free) scores every recorded call under three policy tiers, G0, G and LP.
* ``fresh`` (paid, dry run by default) runs the poisoned and clean arms on Claude 5.5
  through the Message Batches API and scores them without an LLM judge.

Nothing here imports ``anthropic`` at module level, and no command spends money without
``--run`` and ``--budget-usd``.
"""

from __future__ import annotations
