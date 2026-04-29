"""Deterministic English -> airlock-policy compiler."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

import structlog

from ..exceptions import AirlockError
from .cache import CompileCache
from .prompt import COMPILE_PROMPT, PROMPT_HASH

logger = structlog.get_logger("agent-airlock.policy_compiler.compiler")

LLMBackend = Callable[[str, str], str]
"""Backend signature: ``(system_prompt, user_text) -> yaml_string``.

Real backends call OpenAI / Anthropic / DeepSeek / a local model.
Tests inject a deterministic stub. None ship with the runtime to
keep the dep baseline at three.
"""

_REGISTRY: dict[str, LLMBackend] = {}


def register_llm_backend(name: str, backend: LLMBackend) -> None:
    """Register an LLM backend by name."""
    _REGISTRY[name] = backend


def _get_backend(name: str) -> LLMBackend:
    if name not in _REGISTRY:
        raise PolicyCompileError(
            f"unknown LLM backend: {name!r}. Registered: {sorted(_REGISTRY)}"
        )
    return _REGISTRY[name]


class PolicyCompileError(AirlockError):
    """Raised when the compiler can't produce a valid policy chain."""


Action = Literal["allow", "warn", "block"]
Condition = Literal[
    "bind_address_public",
    "missing_auth_header",
    "shell_metachar_in_argv",
    "parallel_tool_calls_above",
    "model_id_prefix",
    "egress_per_call_above",
]


@dataclass(frozen=True)
class PolicyRule:
    """One rule in a compiled policy chain."""

    rule_id: str
    condition: Condition
    action: Action
    threshold: float | None = None


@dataclass(frozen=True)
class PolicyChain:
    """A compiled policy."""

    policy_id: str
    description: str
    rules: tuple[PolicyRule, ...] = field(default_factory=tuple)

    def to_yaml(self) -> str:
        """Render back to the canonical YAML shape."""
        out = [f"policy_id: {self.policy_id}", f"description: {self.description}", "rules:"]
        for r in self.rules:
            out.append(f"  - rule_id: {r.rule_id}")
            out.append(f"    condition: {r.condition}")
            if r.threshold is not None:
                # int when whole, otherwise float
                if r.threshold == int(r.threshold):
                    out.append(f"    threshold: {int(r.threshold)}")
                else:
                    out.append(f"    threshold: {r.threshold}")
            out.append(f"    action: {r.action}")
        return "\n".join(out) + "\n"


@dataclass(frozen=True)
class CompiledPolicy:
    """The compiler's output: typed chain + raw YAML."""

    chain: PolicyChain
    yaml: str


class PolicyCompiler:
    """Deterministic compiler with a hash-pinned prompt + cache."""

    def __init__(
        self,
        backend: str = "stub",
        cache: CompileCache | None = None,
    ) -> None:
        self._backend_name = backend
        # ``cache or CompileCache()`` would swap in a fresh cache because
        # an empty cache is falsy via ``__len__``. Use ``is None`` instead.
        self._cache = cache if cache is not None else CompileCache()

    def compile(self, user_text: str) -> CompiledPolicy:
        """Compile English to :class:`CompiledPolicy`."""
        cached = self._cache.get(PROMPT_HASH, user_text, self._backend_name)
        if cached is not None:
            yaml_text = cached
        else:
            backend = _get_backend(self._backend_name)
            yaml_text = backend(COMPILE_PROMPT, user_text)
            self._cache.put(PROMPT_HASH, user_text, self._backend_name, yaml_text)
        chain = _parse_yaml_to_chain(yaml_text)
        return CompiledPolicy(chain=chain, yaml=yaml_text)


# ---------------------------------------------------------------------------
# Restricted-grammar YAML loader (matches the corpus / OWASP loader pattern)
# ---------------------------------------------------------------------------


def _parse_yaml_to_chain(yaml_text: str) -> PolicyChain:
    lines = yaml_text.splitlines()
    fields: dict[str, str] = {}
    rules: list[dict[str, str]] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        if line == "rules:":
            i += 1
            current: dict[str, str] | None = None
            while i < len(lines):
                sub = lines[i]
                ss = sub.strip()
                if not ss or ss.startswith("#"):
                    i += 1
                    continue
                if not sub.startswith("  "):
                    break
                if ss.startswith("- "):
                    if current is not None:
                        rules.append(current)
                    current = {}
                    inner = ss[2:]
                    if ":" in inner:
                        k, _, v = inner.partition(":")
                        current[k.strip()] = v.strip()
                else:
                    if current is None:
                        raise PolicyCompileError(
                            f"line {i + 1}: rule body without leading '- '"
                        )
                    if ":" not in ss:
                        raise PolicyCompileError(
                            f"line {i + 1}: missing ':' in rule body"
                        )
                    k, _, v = ss.partition(":")
                    current[k.strip()] = v.strip()
                i += 1
            if current is not None:
                rules.append(current)
            continue
        if ":" not in line:
            raise PolicyCompileError(f"line {i + 1}: missing ':' separator")
        key, _, rest = line.partition(":")
        fields[key.strip()] = rest.strip()
        i += 1

    if "policy_id" not in fields:
        raise PolicyCompileError("missing required key 'policy_id'")
    if "description" not in fields:
        raise PolicyCompileError("missing required key 'description'")

    parsed_rules: list[PolicyRule] = []
    for r in rules:
        for required in ("rule_id", "condition", "action"):
            if required not in r:
                raise PolicyCompileError(f"rule missing required key {required!r}")
        threshold_raw = r.get("threshold")
        threshold: float | None = None
        if threshold_raw not in (None, ""):
            try:
                threshold = float(threshold_raw)  # type: ignore[arg-type]
            except (TypeError, ValueError) as exc:
                raise PolicyCompileError(
                    f"rule {r['rule_id']!r}: bad threshold {threshold_raw!r}"
                ) from exc
        parsed_rules.append(
            PolicyRule(
                rule_id=r["rule_id"],
                condition=r["condition"],  # type: ignore[arg-type]
                action=r["action"],  # type: ignore[arg-type]
                threshold=threshold,
            )
        )
    return PolicyChain(
        policy_id=fields["policy_id"],
        description=fields["description"],
        rules=tuple(parsed_rules),
    )


__all__ = [
    "Action",
    "CompiledPolicy",
    "Condition",
    "LLMBackend",
    "PolicyChain",
    "PolicyCompileError",
    "PolicyCompiler",
    "PolicyRule",
    "register_llm_backend",
]
