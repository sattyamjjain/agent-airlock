"""fix_hints recovery: does airlock's refusal help a model repair its own tool call?

500 synthetic scenarios (:mod:`.scenarios`), each a task, a malformed call to a tool in
:mod:`.catalogue` and the ``@Airlock`` refusal that call draws, self-checked at
generation. A model is shown the task, its own malformed ``tool_use`` and the refusal as
an ``is_error`` ``tool_result`` in one of four arms (:mod:`.payloads`):

* **H** - ``json.dumps(AirlockResponse.to_dict())``, the full payload;
* **N** - the same dict with every fix hint removed (top-level and per-error);
* **S** - the text the Claude Agent SDK adapter sends (``_sdk_error_result``);
* **G** - a constant generic error (optional).

Its next tool call is run through a fresh stub of the same tool and scored
(:mod:`.score`): recovered (and whether the corrected call matches the task), the same
error again, a different error, no call, another tool, an API refusal or a truncation.
:mod:`.report` turns scored runs into the round blocks of ``RESULTS.md``.

Nothing here calls the API on import or in a dry run; paid runs go through
:mod:`benchmarks._claude` (``python -m benchmarks.fix_hints --run --budget-usd N``).
"""

from __future__ import annotations
