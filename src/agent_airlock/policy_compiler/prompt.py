"""Hash-pinned compile prompt.

The prompt is defined once, hashed at module load, and exposed via
:data:`PROMPT_HASH`. A change to the prompt body changes the hash;
the cache key includes the hash so a prompt edit invalidates the
cache deterministically.
"""

from __future__ import annotations

import hashlib

COMPILE_PROMPT: str = """\
You are airlock-policy-compiler. Convert the user's English policy
statement into airlock policy YAML. Output ONLY YAML, no commentary,
no markdown fences.

Required top-level keys:
  policy_id: <snake_case>
  description: <one short line>
  rules:
    - rule_id: <snake_case>
      condition: <one of: bind_address_public, missing_auth_header,
                          shell_metachar_in_argv, parallel_tool_calls_above,
                          model_id_prefix, egress_per_call_above>
      threshold: <number, when applicable>
      action: <one of: block, warn, allow>

Constraints:
  * Only emit conditions from the list above; refuse to invent new ones.
  * The output must be parseable by airlock's restricted YAML loader.
  * Use action=block by default unless the user explicitly says warn.
  * No additional keys beyond the four listed.
"""


def _hash() -> str:
    return hashlib.sha256(COMPILE_PROMPT.encode("utf-8")).hexdigest()


PROMPT_HASH: str = _hash()


def compile_prompt_template() -> str:
    """Return the canonical prompt body."""
    return COMPILE_PROMPT


__all__ = ["COMPILE_PROMPT", "PROMPT_HASH", "compile_prompt_template"]
