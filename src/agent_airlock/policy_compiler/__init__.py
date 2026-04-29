"""Natural-language policy authoring (v0.5.9+).

The compiler turns plain English ("block any MCP server bound to
0.0.0.0 without auth") into a typed :class:`PolicyChain` and the
matching YAML. The explainer reverses it.

The compiler is **deterministic**:

* The prompt template is hash-pinned (:data:`PROMPT_HASH`) so silent
  upstream LLM drift surfaces as a CI diff, not a behaviour change.
* Compiled outputs are cached by ``(prompt_hash, request_hash)`` so
  re-running the same English text never burns LLM tokens twice.
* The LLM backend is a ``Protocol`` — tests inject a deterministic
  stub. Real backends (OpenAI / Anthropic / DeepSeek / local) are
  optional. None ship with the runtime; users wire them via
  ``register_llm_backend()``.
"""

from __future__ import annotations

from .cache import CompileCache
from .compiler import (
    CompiledPolicy,
    PolicyChain,
    PolicyCompiler,
    PolicyRule,
    register_llm_backend,
)
from .explainer import explain_preset
from .prompt import PROMPT_HASH, compile_prompt_template

__all__ = [
    "CompileCache",
    "CompiledPolicy",
    "PROMPT_HASH",
    "PolicyChain",
    "PolicyCompiler",
    "PolicyRule",
    "compile_prompt_template",
    "explain_preset",
    "register_llm_backend",
]
