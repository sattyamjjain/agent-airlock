"""Register current model ids against AgentDojo's static model registry.

Why this exists
---------------
AgentDojo's model-in-the-loop harness keys every model off three tables in
``agentdojo.models``:

* ``ModelsEnum``      — the pipeline validates ``--model`` against it
  (``AgentPipeline.from_config`` does ``ModelsEnum(config.llm)``);
* ``MODEL_PROVIDERS`` — model id -> provider, used to pick the SDK client
  (``get_llm(MODEL_PROVIDERS[ModelsEnum(llm)], llm, ...)``);
* ``MODEL_NAMES``     — model id -> the prose self-name (``"Claude"``, ``"GPT-4"``)
  that the ``tool_knowledge`` / ``important_instructions`` attack addresses the model
  by (``get_model_name_from_pipeline`` matches ``full_name in pipeline.name``).

``agentdojo`` ``0.1.35`` is the latest release and is unmaintained. Its ``ModelsEnum``
lists only retired ``claude-3-x`` ids, while the Anthropic API now serves ``claude-4/5``.
So the cross-provider (Anthropic) axis of the AgentDojo benchmark could not be run:
``ModelsEnum("claude-...")`` raised, and forcing a current id in through only the enum
would leave ``MODEL_NAMES`` without an entry, so the attack's model-name lookup would fail
(or fall through to a wrong name) and the number would be meaningless.

This shim patches **all three** tables together — enum membership, provider, *and* the
self-name the attack reads — which is exactly what keeps the attack meaningful. It turns
"wait for upstream" into a one-file, opt-in patch and lets the AgentDojo run widen past the
60-pair single-model subset. It does not touch anything unless called.

Usage
-----
From the harness (``benchmarks/agentdojo/run.py``)::

    python -m benchmarks.agentdojo.run --model claude-opus-5 --register-model claude-opus-5

or programmatically::

    from benchmarks.agentdojo.model_registry_shim import register_model
    register_model("claude-opus-5")            # provider/self-name inferred
    # ModelsEnum("claude-opus-5") now resolves; the pipeline can be built with a key.

The paid run itself still needs an API key and real spend; this only unblocks the
interface. The registered ids below are Anthropic ids current as of 2026-08 (the Claude 5
family plus Haiku 4.5) and the GA ``claude-3-5-haiku-20241022`` that agentdojo's enum
lacks; edit or extend via ``--register-model`` to match exactly what your key serves.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

# Anthropic ids current as of 2026-08 that agentdojo 0.1.35's ModelsEnum does not know.
# These are the default set registered by register_current_models(); the operator sets
# --model to whichever their key serves and can add others with --register-model.
DEFAULT_CURRENT_CLAUDE: tuple[str, ...] = (
    "claude-opus-5",
    "claude-sonnet-5",
    "claude-haiku-4-5-20251001",
    "claude-3-5-haiku-20241022",
)


def _derive_member_name(model_id: str) -> str:
    """``"claude-opus-5"`` -> ``"CLAUDE_OPUS_5"`` (a valid enum member name)."""
    name = re.sub(r"[^0-9A-Za-z]+", "_", model_id).strip("_").upper()
    return name or "MODEL"


def _infer(model_id: str) -> tuple[str, str]:
    """Infer ``(provider, self_name)`` from a model id.

    Defaults to Anthropic/Claude because that is this shim's reason for existing; the other
    prefixes are handled so an operator can register a mixed set through one entry point.
    """
    mid = model_id.lower()
    if mid.startswith("claude"):
        return "anthropic", "Claude"
    if mid.startswith(("gpt", "o1", "o3", "o4", "chatgpt")):
        return "openai", "GPT-4"
    if mid.startswith("gemini"):
        return "google", "AI model developed by Google"
    if mid.startswith("command"):
        return "cohere", "Command R"
    return "anthropic", "Claude"


def _extend_str_enum(enum_cls: type, member_name: str, value: str):  # type: ignore[no-untyped-def]
    """Add a member to an existing StrEnum at runtime (idempotent).

    StrEnum members are ``str`` instances, so a new one is a ``str.__new__`` of the enum
    class registered in the enum's internal name/value maps. This is the standard
    runtime-extension technique; it is scoped to the benchmark process and never persisted.
    """
    existing = enum_cls._value2member_map_.get(value)  # type: ignore[attr-defined]
    if existing is not None:
        return existing
    member = str.__new__(enum_cls, value)
    member._name_ = member_name
    member._value_ = value
    enum_cls._member_map_[member_name] = member  # type: ignore[attr-defined]
    enum_cls._value2member_map_[value] = member  # type: ignore[attr-defined]
    member_names = enum_cls._member_names_  # type: ignore[attr-defined]
    if member_name not in member_names:
        # _member_names_ is a list on <3.11 and a mapping-view-backed list on 3.11+; both
        # support append here because it is the concrete list the metaclass built.
        member_names.append(member_name)
    return member


def register_model(model_id: str, provider: str | None = None, self_name: str | None = None):  # type: ignore[no-untyped-def]
    """Register one model id across all three agentdojo registry tables. Idempotent.

    Args:
        model_id: the id passed to ``--model`` / the API (e.g. ``"claude-opus-5"``).
        provider: agentdojo provider key (``"anthropic"``, ``"openai"``, ...). Inferred
            from the id when omitted.
        self_name: the prose self-name the attack addresses the model by (``"Claude"``).
            Inferred from the id when omitted.

    Returns:
        The ``ModelsEnum`` member for ``model_id``.
    """
    from agentdojo import models as adm

    inferred_provider, inferred_self_name = _infer(model_id)
    provider = provider or inferred_provider
    self_name = self_name or inferred_self_name

    member = _extend_str_enum(adm.ModelsEnum, _derive_member_name(model_id), model_id)
    adm.MODEL_PROVIDERS[member] = provider
    adm.MODEL_NAMES[model_id] = self_name
    return member


def _known_ids() -> set[str]:
    from agentdojo.models import ModelsEnum

    return {member.value for member in ModelsEnum}


def register_current_models(extra: Iterable[str] = ()) -> list[str]:
    """Register the default current-Claude set plus any ``extra`` ids. Returns ids added.

    An id already known to agentdojo is skipped (not re-registered), so the return list is
    exactly what this call introduced.
    """
    before = _known_ids()
    added: list[str] = []
    for model_id in (*DEFAULT_CURRENT_CLAUDE, *extra):
        if model_id in before or model_id in added:
            continue
        register_model(model_id)
        added.append(model_id)
    return added


def ensure_registered(models: Iterable[str], extra: Iterable[str] = ()) -> list[str]:
    """Register what a run needs: every ``extra`` id, and any ``--model`` id agentdojo does
    not already know that looks like a Claude id (so ``--model claude-opus-5`` just works).

    Returns the ids newly registered (for the harness to log). Does not register the whole
    default set — only what the requested run actually references.
    """
    known = _known_ids()
    added: list[str] = []

    def _add(model_id: str) -> None:
        if model_id in known or model_id in added:
            return
        register_model(model_id)
        added.append(model_id)
        known.add(model_id)

    for model_id in extra:
        _add(model_id)
    for model_id in models:
        if model_id not in known and model_id.lower().startswith("claude"):
            _add(model_id)
    return added
