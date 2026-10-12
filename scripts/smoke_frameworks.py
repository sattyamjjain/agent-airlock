#!/usr/bin/env python3
"""Framework smoke matrix: one allowed and one denied tool call through each agent framework.

Every framework runs in its own throwaway virtualenv under ``.smoke-frameworks-venv/<key>/``
(their dependency sets conflict), with the agent-airlock wheel built from this checkout and
the framework's newest release, or the version range agent-airlock's own extra declares
where one exists. A child script inside each venv builds two tools, ``get_order_status``
(allowed) and ``delete_order`` (denied by ``SecurityPolicy(allowed_tools=["get_order_status"])``),
wraps them the way that framework's airlock integration does, and asks the model to call
both. Each tool body appends to a canary list, so "the denied tool never ran" is observed,
not inferred, and airlock's refusal is read back from its own audit log.

Modes:

  (default)          $0. Build the wheel, create the venvs, install, import, construct the
                     agent with airlock wrapping, then drive it against a scripted stand-in
                     for the Messages API on a loopback server inside the child. Nothing
                     reaches Anthropic: Python clients reach the stand-in over real HTTP
                     (observed by the same code that observes Anthropic in a paid run), the
                     Claude Agent SDK's CLI through ANTHROPIC_BASE_URL, and a request aimed
                     anywhere else is answered in-process. The stand-in replies the way
                     Claude Haiku 5.5 does by default (a thinking block before each tool
                     call), so what a framework sends on the wire, and what it does with
                     thinking blocks and refusals, is recorded before any credit is spent.
  --construct-only   Stop after construction: "ready" or the environment problem.
  --run --budget-usd N
                     Paid run on claude-haiku-5-5 (max_tokens=4096, no sampling parameters
                     set by the child, at most --max-calls model calls per framework). The
                     key is read from ANTHROPIC_API_KEY by benchmarks._claude.client and
                     reaches a child only through its environment, never argv or a log.
                     Every response is priced by exact model id into the shared ledger
                     (benchmarks._claude); each framework's worst case is reserved before it
                     starts, and the child refuses any request that would exceed that share.
  --write            With --run: rewrite the block between the SMOKE-MATRIX markers in
                     docs/COMPATIBILITY.md with a dated (UTC) table of this run.

Verdicts per framework, for the scripted exchange and the paid run alike:

  PASS           the allowed tool ran, the denied tool did not, and airlock's refusal of it
                 was observed (its audit log, or the smolagents guard raising AirlockError)
  INCONCLUSIVE   the model never attempted the denied call
  FAIL           anything else: the denied tool ran, the allowed one was refused, ...
  ERROR          the exchange broke before the denied call was attempted
  ENV            the venv, the install or an import failed
  READY          --construct-only: installed, imported and constructed

Exit codes: 0 no FAIL, ENV, ERROR or budget refusal; 1 a FAIL; 2 an environment problem
(ENV or ERROR); 3 the budget refused the run. The venvs are deleted after a clean run and
kept after any other (or with --keep-venvs); while they exist, ``make check-links`` reads
their site-packages markdown and fails.

Run from the repo root: ``python scripts/smoke_frameworks.py [--only anthropic,crewai]``
(the script puts ``src/`` and the repo root on ``sys.path`` itself). ``--no-workarounds``
runs every framework exactly as configured by default, ``--dump-requests`` keeps each
request body for triage, and ``--reuse-venvs`` skips reinstalling unchanged venvs.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import subprocess  # noqa: S404 - smoke driver: builds venvs and runs child interpreters
import sys
import textwrap
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
DIST_DIR = REPO_ROOT / "dist"
VENV_ROOT = REPO_ROOT / ".smoke-frameworks-venv"
COMPAT_DOC = REPO_ROOT / "docs" / "COMPATIBILITY.md"
PYPROJECT = REPO_ROOT / "pyproject.toml"
SCRIPT_URL = "https://github.com/sattyamjjain/agent-airlock/blob/main/scripts/smoke_frameworks.py"

MODEL = "claude-haiku-5-5"
MAX_TOKENS = 4096
DEFAULT_MAX_CALLS = 4
DEFAULT_PYTHON = "3.12"
PROMPT = (
    "Call get_order_status for order A-1001, then call delete_order for order A-1001, "
    "then reply DONE."
)
SYSTEM = (
    "You are an order-desk agent in an automated integration test. Use the tools exactly "
    "as the user asks and keep replies short."
)
RESULT_MARKER = "AIRLOCK_SMOKE_RESULT "
MOCK_KEY = "airlock-smoke-offline-mock-not-a-key"
"""Placeholder credential for the $0 modes: answered in-process or on loopback, never sent."""
BLOCK_BEGIN = "<!-- SMOKE-MATRIX:BEGIN -->"
BLOCK_END = "<!-- SMOKE-MATRIX:END -->"

PASS, FAIL, INCONCLUSIVE, ERROR, ENV, READY, SKIPPED = (
    "PASS",
    "FAIL",
    "INCONCLUSIVE",
    "ERROR",
    "ENV",
    "READY",
    "SKIPPED",
)

INSTALL_TIMEOUT_S = 1200.0
CHILD_TIMEOUT_S = {"construct": 240.0, "mock": 300.0, "run": 600.0}


@dataclass(frozen=True)
class Framework:
    """One row of the matrix.

    Attributes:
        key: Venv directory name and ``--only`` value.
        title: Row label in the docs table.
        packages: Requirements installed beside the wheel.
        versions: Distributions whose installed versions the child records.
        airlock_path: The airlock surface the child exercises, for the docs table.
        est_input_tokens: Per-request input estimate behind the paid-run worst case.
        extra: ``(extra, distribution, install_as)``: install ``install_as`` with the
            version range agent-airlock's ``extra`` declares for ``distribution``.
        workaround_packages: Extra pins applied unless ``--no-workarounds``, for a framework
            whose default resolution is known not to work; the child notes why.
    """

    key: str
    title: str
    packages: tuple[str, ...]
    versions: tuple[str, ...]
    airlock_path: str
    est_input_tokens: int = 8000
    extra: tuple[str, str, str] | None = None
    workaround_packages: tuple[str, ...] = ()


FRAMEWORKS: dict[str, Framework] = {
    fw.key: fw
    for fw in (
        Framework(
            "anthropic",
            "Anthropic Messages",
            ("anthropic",),
            ("anthropic",),
            "`integrations.anthropic` `ToolRegistry` + `process_message_tools`",
        ),
        Framework(
            "langchain",
            "LangChain",
            ("langchain", "langchain-anthropic"),
            ("langchain", "langchain-core", "langchain-anthropic", "anthropic"),
            "`integrations.langchain.create_secure_tool` in a `create_agent` loop",
        ),
        Framework(
            "langgraph",
            "LangGraph",
            ("langgraph", "langchain-anthropic"),
            ("langgraph", "langgraph-prebuilt", "langchain-core", "langchain-anthropic"),
            "`@tool` over `@Airlock`, `ToolNode` + `langgraph_toolnode_compat`",
        ),
        Framework(
            "pydantic_ai",
            "PydanticAI",
            (),
            ("pydantic-ai-slim", "anthropic"),
            "`PydanticAIAdapter.wrap_agent` on an `AnthropicModel` agent",
            extra=("pydantic-ai", "pydantic-ai", "pydantic-ai-slim[anthropic]"),
        ),
        Framework(
            "openai_agents",
            "OpenAI Agents SDK",
            ("openai-agents[litellm]",),
            ("openai-agents", "litellm"),
            "`@function_tool` over `@Airlock`, `LitellmModel`",
        ),
        Framework(
            "crewai",
            "CrewAI",
            (),
            ("crewai", "litellm", "anthropic"),
            "`CrewAIAdapter.wrap_crew`, `LLM(..., is_litellm=True)`",
            est_input_tokens=10000,
            # [anthropic] too: LLM(is_litellm=True) still imports the native Anthropic
            # provider for an anthropic/claude-* id, and raises ImportError without it.
            extra=("crewai", "crewai", "crewai[litellm,anthropic]"),
        ),
        Framework(
            "smolagents",
            "smolagents",
            ("smolagents[litellm]",),
            ("smolagents", "litellm"),
            "`smolagents_wrapper.wrap_agent` with a `PolicyBundle` guard raising `AirlockError`",
            est_input_tokens=10000,
        ),
        Framework(
            "google_adk",
            "Google ADK",
            ("litellm",),
            ("google-adk", "litellm"),
            "`google_adk.wrap_agent`, `LiteLlm`",
            extra=("google-adk", "google-adk", "google-adk"),
        ),
        Framework(
            "llamaindex",
            "LlamaIndex",
            ("llama-index-core", "llama-index-llms-anthropic"),
            ("llama-index-core", "llama-index-llms-anthropic", "anthropic"),
            "`FunctionTool.from_defaults` over `@Airlock` (example-level)",
        ),
        Framework(
            "autogen",
            "AutoGen",
            # tiktoken: autogen-ext's anthropic client imports it, and [anthropic] omits it.
            ("autogen-agentchat", "autogen-ext[anthropic]", "tiktoken"),
            ("autogen-agentchat", "autogen-ext", "anthropic"),
            "`AssistantAgent` tools over `@Airlock` (example-level)",
            # The client always passes temperature, which anthropic 1.x's messages.create
            # no longer takes (TypeError); 0.x forwards it, and 1.0 is the value Haiku 5.5 allows.
            workaround_packages=("anthropic<1",),
        ),
        Framework(
            "claude_agent_sdk",
            "Claude Agent SDK",
            (),
            ("claude-agent-sdk",),
            "`wrap_tools` then `create_sdk_mcp_server`",
            est_input_tokens=12000,
            extra=("claude-agent", "claude-agent-sdk", "claude-agent-sdk"),
        ),
    )
}

EXCLUDED: dict[str, str] = {
    "Claude Managed Agents": (
        "a hosted runtime with no local tool callable to wrap; its approval gate needs a live "
        "session test, not a framework smoke"
    ),
    "GPT-5.5 and Gemini 3 tool-shape adapters": (
        "they normalise vendor payloads, wrap no tool and call no model"
    ),
    "Google Model Armor": "a classifier the caller invokes; it wraps no tool call",
    "FastMCP": "needs no model; its integration runs in CI's test job",
}


class EnvironmentProblem(RuntimeError):
    """The wheel, a venv or an install could not be prepared (exit code 2)."""


# --------------------------------------------------------------------------------------
# Pure helpers (unit-tested in tests/test_smoke_frameworks.py; no network, no SDKs)
# --------------------------------------------------------------------------------------

_REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*?)\s*$")
_KEY_RE = re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}")


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def extra_requirement(pyproject_text: str, extra: str, dist: str, install_as: str) -> str:
    """Return ``install_as`` pinned to the range agent-airlock's ``extra`` declares for ``dist``.

    Raises:
        KeyError: The extra is missing, or declares no ``dist``.
    """
    if sys.version_info >= (3, 11):
        import tomllib
    else:  # pragma: no cover - the core's own tomli dependency on 3.10
        import tomli as tomllib

    requirements = tomllib.loads(pyproject_text)["project"]["optional-dependencies"][extra]
    for requirement in requirements:
        match = _REQ_RE.match(requirement)
        if match and _canonical(match.group(1)) == _canonical(dist):
            return f"{install_as}{match.group(3)}"
    raise KeyError(f"extra {extra!r} declares no {dist!r}")


def requirements_for(fw: Framework, pyproject_text: str, *, workarounds: bool = True) -> list[str]:
    """The requirements to install beside the wheel for ``fw``."""
    reqs = list(fw.packages)
    if fw.extra is not None:
        reqs.insert(0, extra_requirement(pyproject_text, *fw.extra))
    if workarounds:
        reqs.extend(fw.workaround_packages)
    return reqs


_ENV_ALLOWLIST = frozenset(
    {
        "PATH",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TERM",
        "TZ",
        "TMPDIR",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "all_proxy",
        "SYSTEMROOT",
    }
)
"""The only parent variables a child inherits. ANTHROPIC_*, CLAUDE*, other providers' keys,
PYTHONPATH and the Claude Code session variables never pass: an allowlist fails closed."""

_QUIET_ENV: dict[str, str] = {
    "PYTHONUNBUFFERED": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
    "DO_NOT_TRACK": "1",
    "ANONYMIZED_TELEMETRY": "false",
    "CREWAI_DISABLE_TELEMETRY": "true",
    "CREWAI_DISABLE_TRACKING": "true",
    "CREWAI_TRACING_ENABLED": "false",
    "OTEL_SDK_DISABLED": "true",
    "OPENAI_AGENTS_DISABLE_TRACING": "1",
    "LITELLM_TELEMETRY": "False",
    "LITELLM_LOG": "ERROR",
    "HF_HUB_DISABLE_TELEMETRY": "1",
    "LANGCHAIN_TRACING_V2": "false",
    "LANGSMITH_TRACING": "false",
    "TOKENIZERS_PARALLELISM": "false",
    "DISABLE_TELEMETRY": "1",
    "DISABLE_ERROR_REPORTING": "1",
    "DISABLE_AUTOUPDATER": "1",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
}


def build_child_env(
    parent_env: Mapping[str, str],
    *,
    mode: str,
    framework: str,
    workdir: Path,
    api_key: str | None = None,
    extra: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """The environment a child runs with: an allowlist of the parent's, plus the smoke config.

    ``HOME`` and the XDG directories point inside ``workdir`` so no framework reads the
    operator's own configuration or credential profiles. The API key is set only in run
    mode; the $0 modes get :data:`MOCK_KEY`, which never leaves the machine.

    Raises:
        ValueError: A key outside run mode, or run mode without one.
    """
    if (mode == "run") != bool(api_key):
        raise ValueError("the API key is passed to a child in run mode, and only then")
    home = workdir / "home"
    env = {k: v for k, v in parent_env.items() if k in _ENV_ALLOWLIST}
    env.update(_QUIET_ENV)
    env.update(
        {
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "XDG_DATA_HOME": str(home / ".local" / "share"),
            "AIRLOCK_AUDIT_LOG_PATH": str(workdir / "airlock_audit.jsonl"),
            "SMOKE_MODE": mode,
            "SMOKE_FRAMEWORK": framework,
            "SMOKE_WORKDIR": str(workdir),
            "SMOKE_MODEL": MODEL,
            "SMOKE_MAX_TOKENS": str(MAX_TOKENS),
            "SMOKE_PROMPT": PROMPT,
            "SMOKE_SYSTEM": SYSTEM,
            "ANTHROPIC_API_KEY": api_key if mode == "run" and api_key else MOCK_KEY,
        }
    )
    env.update(extra or {})
    return env


def redact(text: str, secrets: Iterable[str] = ()) -> str:
    """Replace each secret (8+ characters) and anything shaped like an Anthropic key."""
    for secret in secrets:
        if secret and len(secret) >= 8:
            text = text.replace(secret, "[REDACTED]")
    return _KEY_RE.sub("sk-ant-[REDACTED]", text)


def parse_child_output(stdout: str) -> dict[str, Any] | None:
    """The child's result: the last ``RESULT_MARKER`` line's JSON object, or ``None``."""
    for line in reversed(stdout.splitlines()):
        if line.startswith(RESULT_MARKER):
            try:
                payload = json.loads(line[len(RESULT_MARKER) :])
            except json.JSONDecodeError:
                return None
            return payload if isinstance(payload, dict) else None
    return None


def classify(
    *,
    allowed_ran: bool,
    denied_ran: bool,
    denied_attempted: bool,
    denied_refused: bool,
    allowed_refused: bool,
    run_error: bool,
) -> str:
    """The verdict for one exchange (see the module docstring).

    A refused allowed call is a FAIL even when the model then never tried the denied one:
    a false refusal is evidence about the wiring, not about the model.
    """
    if denied_ran or allowed_refused:
        return FAIL
    if allowed_ran and denied_refused:
        return PASS
    if not denied_attempted:
        return ERROR if run_error else INCONCLUSIVE
    return FAIL


def status_for(payload: Mapping[str, Any] | None, mode: str) -> str:
    """The verdict for a child's payload (``None``: it produced no result)."""
    if payload is None:
        return ERROR
    if not payload.get("constructed"):
        return ENV if payload.get("error_import") else ERROR
    if mode == "construct":
        return READY
    return classify(
        allowed_ran=bool(payload.get("allowed_ran")),
        denied_ran=bool(payload.get("denied_ran")),
        denied_attempted=bool(payload.get("denied_attempted")),
        denied_refused=bool(payload.get("denied_refused")),
        allowed_refused=bool(payload.get("allowed_refused")),
        run_error=bool(payload.get("error")),
    )


def sampling_notes(params: Mapping[str, Any]) -> list[str]:
    """What Haiku 5.5 makes of the sampling parameters a framework sent.

    Per the Claude API reference: ``temperature`` must be 1 and ``top_p`` 0.99 (its
    default); any other value, any ``top_k``, or both together is a 400.
    """
    notes = []
    for name, value in sorted(params.items()):
        accepted = (name == "temperature" and value == 1) or (name == "top_p" and value == 0.99)
        verdict = "the one value Haiku 5.5 accepts" if accepted else "Haiku 5.5 returns 400"
        notes.append(f"sends {name}={value} ({verdict})")
    if "temperature" in params and "top_p" in params:
        notes.append("sends temperature and top_p together (Haiku 5.5 returns 400)")
    return notes


def wire_notes(wire: Mapping[str, Any]) -> list[str]:
    """What a framework put on the wire that matters to Haiku 5.5."""
    notes = sampling_notes(wire.get("sampling") or {})
    max_tokens = wire.get("max_tokens") or []
    if max_tokens and list(max_tokens) != [MAX_TOKENS]:
        notes.append(f"max_tokens on the wire: {', '.join(str(v) for v in max_tokens)}")
    if any('"any"' in c or '"tool"' in c for c in wire.get("tool_choice") or []):
        notes.append("forces tool_choice (Haiku 5.5 accepts it; the forced call skips thinking)")
    if wire.get("prefill"):
        notes.append("ends a request on an assistant turn (a prefill; Haiku 5.5 returns 400)")
    return notes


def findings(payload: Mapping[str, Any] | None) -> list[str]:
    """Plain-language notes on what the framework sent and did, from a child's payload."""
    if payload is None:
        return []
    notes = wire_notes(payload.get("wire") or {})
    if payload.get("thinking") in {"dropped", "partial"}:
        notes.append(f"thinking blocks {payload['thinking']} on the next request")
    if payload.get("delivery") == "result":
        notes.append("the refusal reaches the model as a normal tool result, not is_error")
    stops = set(payload.get("stop_reasons") or []) & {"max_tokens", "refusal", "pause_turn"}
    notes.extend(f"a response stopped with stop_reason {stop}" for stop in sorted(stops))
    served = set(payload.get("response_models") or []) - {MODEL}
    if served:
        notes.append(f"served by {', '.join(sorted(served))}, not {MODEL}")
    errors = payload.get("http_errors") or []
    if errors:
        notes.append(f"API error: {errors[0]}")
    if payload.get("budget_abort"):
        notes.append("a request was refused by the smoke's call cap or dollar share")
    if payload.get("error"):
        notes.append(f"{payload.get('error_stage', 'run')} error: {payload['error']}")
    notes.extend(str(n) for n in payload.get("notes") or [])
    notes.extend(str(w) for w in payload.get("warnings") or [])
    return notes


def exit_code(statuses: Iterable[str]) -> int:
    """0 clean; 1 any FAIL; 3 the budget refused a framework; 2 any ENV or ERROR."""
    seen = set(statuses)
    if FAIL in seen:
        return 1
    if SKIPPED in seen:
        return 3
    if seen & {ENV, ERROR}:
        return 2
    return 0


def _yes_no(value: Any) -> str:
    if value is None:
        return "—"
    return "yes" if value else "no"


def _cell(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ").strip() or "—"


def _versions_cell(payload: Mapping[str, Any] | None) -> str:
    versions = (payload or {}).get("versions") or {}
    shown = [f"{name} {ver}" for name, ver in versions.items() if name != "agent-airlock"]
    return ", ".join(shown) or "—"


def _row(fw: Framework, result: Mapping[str, Any] | None) -> str:
    if result is None:
        cells = [fw.title, "—", fw.airlock_path, "Not yet run", "—", "—", "—", "—", "—", "—"]
    else:
        payload = result.get("payload") or {}
        notes = "; ".join(result.get("notes") or []) or "—"
        cells = [
            fw.title,
            _versions_cell(payload),
            fw.airlock_path,
            str(result.get("status")),
            _yes_no(payload.get("allowed_ran")),
            _yes_no(payload.get("denied_attempted")),
            _yes_no(payload.get("denied_refused")),
            str(payload.get("delivery") or "—"),
            str(payload.get("model_calls", "—")),
            notes if len(notes) <= 400 else notes[:397] + "...",
        ]
    return "| " + " | ".join(_cell(c) for c in cells) + " |"


def render_block(
    results: Mapping[str, Mapping[str, Any]] | None, meta: Mapping[str, str] | None = None
) -> str:
    """The generated docs block, markers included. ``results=None`` renders "not yet run"."""
    intro = (
        f"Generated by [`scripts/smoke_frameworks.py`]({SCRIPT_URL}); do not edit by hand. "
        "Each framework runs in its own virtualenv with the agent-airlock wheel, and the model "
        "is asked to call `get_order_status`, which the policy allows, and then `delete_order`, "
        'which `SecurityPolicy(allowed_tools=["get_order_status"])` denies. Each tool body '
        "appends to a canary list, so a denied tool that never ran is observed, not inferred, "
        "and the refusal is read back from airlock's audit log (for smolagents, from the "
        "guard raising `AirlockError`)."
    )
    legend = (
        "**PASS**: the allowed tool ran, the denied tool did not, and the refusal was "
        "observed. **INCONCLUSIVE**: the model never attempted the denied call. **ERROR**: "
        "the exchange broke before that. **ENV**: the install or an import failed."
    )
    if results is None or meta is None:
        last = (
            "**Last run:** not yet run. The table fills in from a paid run on "
            f"`{MODEL}` (`--run --budget-usd N --write`)."
        )
    else:
        last = (
            f"**Last run:** {meta['date']} (UTC) on `{meta['model']}`, max_tokens "
            f"{meta['max_tokens']}, at most {meta['max_calls']} model calls per framework; "
            f"agent-airlock {meta['airlock']} (`{meta['commit']}`); ledger-priced spend "
            f"${meta['spend']}."
        )
    lines = [BLOCK_BEGIN, intro, "", legend, "", last, ""]
    lines.append(
        "| Framework | Versions | Airlock path | Result | Allowed ran | Denied attempted "
        "| Denied refused | Refusal reached the model as | Model calls | Notes |"
    )
    lines.append("|---|---|---|---|---|---|---|---|---|---|")
    for fw in FRAMEWORKS.values():
        lines.append(_row(fw, results.get(fw.key) if results else None))
    lines += ["", "Not in the matrix:", ""]
    lines += [f"- **{name}**: {reason}." for name, reason in EXCLUDED.items()]
    lines.append(BLOCK_END)
    return "\n".join(lines)


def replace_block(text: str, block: str) -> str:
    """``text`` with the region between the SMOKE-MATRIX markers replaced by ``block``.

    Raises:
        ValueError: The markers are missing, repeated or out of order.
    """
    if text.count(BLOCK_BEGIN) != 1 or text.count(BLOCK_END) != 1:
        raise ValueError("expected exactly one SMOKE-MATRIX:BEGIN and one SMOKE-MATRIX:END")
    start = text.index(BLOCK_BEGIN)
    end = text.index(BLOCK_END)
    if end < start:
        raise ValueError("SMOKE-MATRIX:END comes before SMOKE-MATRIX:BEGIN")
    return text[:start] + block + text[end + len(BLOCK_END) :]


# --------------------------------------------------------------------------------------
# Spend: worst-case reservation, ledger pricing (benchmarks._claude, imported lazily)
# --------------------------------------------------------------------------------------


def worst_case_usd(fw: Framework, max_calls: int) -> float:
    """The most ``fw``'s paid run can cost: every call at its input estimate and full output."""
    from benchmarks._claude.pricing import worst_case_usd as one_call

    return round(max_calls * one_call(MODEL, fw.est_input_tokens, MAX_TOKENS, batch=False), 6)


def budget_plan(
    frameworks: Sequence[Framework], budget_usd: float, max_calls: int
) -> dict[str, float]:
    """Each framework's worst case, which is also the dollar share its child may spend.

    Raises:
        ValueError: The worst cases together exceed ``budget_usd``.
    """
    plan = {fw.key: worst_case_usd(fw, max_calls) for fw in frameworks}
    total = round(sum(plan.values()), 6)
    if total > budget_usd:
        raise ValueError(
            f"the worst case for {len(plan)} framework(s) at {max_calls} calls each is "
            f"${total:.4f}, above --budget-usd {budget_usd:.4f}"
        )
    return plan


def child_rates() -> dict[str, Any]:
    """Haiku 5.5 per-MTok rates the child's in-process dollar guard estimates with."""
    from benchmarks._claude.pricing import _LONG_PROMPT, rates_for

    rates = rates_for(MODEL)
    return {
        "input": rates.input,
        "output": rates.output,
        "cache_read": rates.cache_read,
        "cache_write_1h": rates.cache_write_1h,
        "long_prompt": list(_LONG_PROMPT.get(MODEL, (10**12, 1.0))),
    }


def ledger_entries(
    fw: Framework, payload: Mapping[str, Any] | None, max_calls: int
) -> list[tuple[str, dict[str, Any], float, str]]:
    """``(model, usage, usd, how)`` for each response to record in the ledger.

    Observed usage is priced by exact model id; a model the snapshot does not list is
    priced at its dearest row. A call whose usage was not observed, or every call of a
    child that produced no result, is recorded at the worst case, so the ledger can only
    overstate spend.
    """
    from benchmarks._claude.models import MODELS
    from benchmarks._claude.pricing import UnpricedModelError, price_usage

    worst = {"input_tokens": fw.est_input_tokens, "output_tokens": MAX_TOKENS}
    if payload is None:
        usd = price_usage(MODEL, worst, batch=False)
        return [(MODEL, dict(worst), usd, "no result: worst case")] * max_calls
    entries: list[tuple[str, dict[str, Any], float, str]] = []
    for item in payload.get("usage") or []:
        model = str(item.get("model") or MODEL)
        usage = dict(item.get("usage") or {})
        try:
            entries.append((model, usage, price_usage(model, usage, batch=False), "observed"))
        except UnpricedModelError:
            dearest = max(price_usage(m, usage, batch=False) for m in MODELS.values())
            entries.append((model, usage, dearest, "unlisted model: dearest row"))
    for _ in range(int(payload.get("unobserved_calls") or 0)):
        entries.append((MODEL, dict(worst), price_usage(MODEL, worst, batch=False), "unobserved"))
    return entries


# --------------------------------------------------------------------------------------
# Orchestration: wheel, venvs, children
# --------------------------------------------------------------------------------------


def _run(cmd: Sequence[str], *, log: Path | None = None, cwd: Path | None = None) -> None:
    print(f"$ {' '.join(cmd)}", flush=True)
    if log is None:
        subprocess.run(cmd, check=True, cwd=cwd, timeout=INSTALL_TIMEOUT_S)  # noqa: S603
        return
    with log.open("a", encoding="utf-8") as handle:
        subprocess.run(  # noqa: S603 - argv built by this script
            cmd,
            check=True,
            cwd=cwd,
            stdout=handle,
            stderr=subprocess.STDOUT,
            timeout=INSTALL_TIMEOUT_S,
        )


def find_uv() -> str | None:
    """``uv`` from PATH, else ``~/.local/bin/uv``; ``None`` falls back to venv + pip."""
    found = shutil.which("uv")
    if found:
        return found
    candidate = Path.home() / ".local" / "bin" / "uv"
    return str(candidate) if candidate.exists() else None


def build_wheel(uv: str | None) -> Path:
    """Build the agent-airlock wheel from this checkout into ``dist/``."""
    DIST_DIR.mkdir(exist_ok=True)
    for old in DIST_DIR.glob("agent_airlock-*.whl"):
        old.unlink()
    if uv:
        _run([uv, "build", "--wheel", "--out-dir", str(DIST_DIR)], cwd=REPO_ROOT)
    else:
        _run([sys.executable, "-m", "build", "--wheel", "--outdir", str(DIST_DIR)], cwd=REPO_ROOT)
    wheels = sorted(DIST_DIR.glob("agent_airlock-*.whl"))
    if not wheels:
        raise EnvironmentProblem("no wheel produced under dist/")
    return wheels[-1]


def venv_python(venv: Path) -> Path:
    if sys.platform == "win32":
        return venv / "Scripts" / "python.exe"
    return venv / "bin" / "python"


def _tail(path: Path, lines: int = 12) -> str:
    try:
        return "\n".join(path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:])
    except OSError:
        return ""


def prepare_venv(
    fw: Framework, wheel: Path, reqs: Sequence[str], *, uv: str | None, python: str, reuse: bool
) -> Path:
    """Create ``fw``'s venv and install its packages plus the wheel; return its python.

    With ``reuse`` and an existing venv only the wheel is reinstalled, so the checkout's
    current code is what runs.

    Raises:
        EnvironmentProblem: The venv or the install failed; the message ends with the log tail.
    """
    venv = VENV_ROOT / fw.key
    log = VENV_ROOT / f"{fw.key}.install.log"
    stamp = venv / "smoke-requirements.txt"
    py = venv_python(venv)
    VENV_ROOT.mkdir(exist_ok=True)
    wanted = "\n".join(reqs) + "\n"
    try:
        if reuse and py.exists() and stamp.exists() and stamp.read_text("utf-8") == wanted:
            _run(_pip(uv, py, "--no-deps", *_reinstall(uv), str(wheel)), log=log)
            return py
        if venv.exists():
            shutil.rmtree(venv)
        log.write_text("", encoding="utf-8")
        if uv:
            _run([uv, "venv", "--quiet", "--python", python, str(venv)], log=log)
        else:
            _run([sys.executable, "-m", "venv", str(venv)], log=log)
        _run(_pip(uv, py, *reqs, str(wheel)), log=log)
        stamp.write_text(wanted, encoding="utf-8")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        raise EnvironmentProblem(f"{type(exc).__name__}: {exc}\n{_tail(log)}") from exc
    return py


def _pip(uv: str | None, py: Path, *args: str) -> list[str]:
    """An install into ``py``'s venv, through uv when it is available."""
    if uv:
        return [uv, "pip", "install", "--python", str(py), *args]
    return [str(py), "-m", "pip", "install", "--quiet", *args]


def _reinstall(uv: str | None) -> list[str]:
    return ["--reinstall-package", "agent-airlock"] if uv else ["--force-reinstall"]


def child_source(key: str) -> str:
    """The child script for framework ``key``: the shared harness plus that framework's body."""
    fw = FRAMEWORKS[key]
    return "\n".join(
        [
            CHILD_COMMON.strip("\n"),
            "",
            f"VERSIONS = {fw.versions!r}",
            "",
            textwrap.dedent(CHILD_BODIES[key]).strip("\n"),
            "",
            'if __name__ == "__main__":',
            "    raise SystemExit(main())",
            "",
        ]
    )


def run_child(
    fw: Framework, py: Path, env: Mapping[str, str], *, timeout: float, secrets: Sequence[str]
) -> tuple[dict[str, Any] | None, str]:
    """Run ``fw``'s child; return its payload (or ``None``) and a problem description."""
    workdir = Path(env["SMOKE_WORKDIR"])
    script = workdir / "smoke_child.py"
    script.write_text(child_source(fw.key), encoding="utf-8")
    proc = subprocess.Popen(  # noqa: S603 - argv built by this script
        [str(py), "-I", str(script)],
        cwd=workdir,
        env=dict(env),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    problem = ""
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        stdout, stderr = proc.communicate()
        problem = f"child timed out after {timeout:.0f}s"
    log = workdir / "child.log"
    log.write_text(redact(f"{stdout}\n--- stderr ---\n{stderr}", secrets), encoding="utf-8")
    payload = parse_child_output(stdout)
    if payload is None and not problem:
        problem = f"child exited {proc.returncode} without a result line; see {log}"
    return payload, problem


def _kill_group(proc: subprocess.Popen[str]) -> None:
    """Kill the child and whatever it spawned (the Claude Agent SDK starts a CLI)."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, AttributeError):
        proc.kill()


def fresh_workdir(fw: Framework) -> Path:
    workdir = VENV_ROOT / fw.key / "work"
    if workdir.exists():
        shutil.rmtree(workdir)
    (workdir / "home").mkdir(parents=True)
    return workdir


@dataclass
class PaidRun:
    """What run mode needs beyond the $0 modes. The key is never printed or stored."""

    key: str
    plan: dict[str, float]
    rates: dict[str, Any]
    ledger: Any
    guard: Any
    store: Any
    run_id: str


@dataclass
class Outcome:
    status: str
    payload: dict[str, Any] | None
    notes: list[str] = field(default_factory=list)
    usd: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "payload": self.payload,
            "notes": self.notes,
            "usd": self.usd,
        }


def smoke_one(
    fw: Framework,
    *,
    mode: str,
    wheel: Path,
    reqs: Sequence[str],
    args: argparse.Namespace,
    uv: str | None,
    paid: PaidRun | None,
) -> Outcome:
    """Install, run and judge one framework (spend is recorded by the caller)."""
    try:
        py = prepare_venv(fw, wheel, reqs, uv=uv, python=args.python, reuse=args.reuse_venvs)
    except EnvironmentProblem as exc:
        return Outcome(ENV, None, [f"install failed: {exc}".splitlines()[0]])
    workdir = fresh_workdir(fw)
    extra = {
        "SMOKE_MAX_CALLS": "0" if mode == "construct" else str(args.max_calls),
        "SMOKE_TURNS": str(args.max_calls),
        "SMOKE_WORKAROUNDS": "0" if args.no_workarounds else "1",
        "SMOKE_DUMP_REQUESTS": "1" if args.dump_requests else "0",
    }
    if paid is not None:
        extra["SMOKE_BUDGET_USD"] = repr(paid.plan[fw.key])
        extra["SMOKE_RATES"] = json.dumps(paid.rates)
    env = build_child_env(
        os.environ,
        mode=mode,
        framework=fw.key,
        workdir=workdir,
        api_key=paid.key if paid else None,
        extra=extra,
    )
    secrets = [paid.key] if paid else []
    payload, problem = run_child(fw, py, env, timeout=CHILD_TIMEOUT_S[mode], secrets=secrets)
    status = status_for(payload, mode)
    notes = findings(payload)
    if problem:
        notes.insert(0, problem)
    if payload is not None and payload.get("status") not in (None, status):
        notes.insert(0, f"the child judged {payload['status']}; the driver's verdict stands")
    return Outcome(status, payload, notes)


def record_spend(paid: PaidRun, fw: Framework, outcome: Outcome, max_calls: int) -> None:
    """Price ``outcome``'s responses into the ledger, then free the framework's reservation."""
    job = f"smoke-frameworks-{paid.run_id}-{fw.key}"
    total = 0.0
    try:
        for index, (model, usage, usd, how) in enumerate(
            ledger_entries(fw, outcome.payload, max_calls), start=1
        ):
            paid.ledger.record_usage(
                job=job,
                custom_id=f"{fw.key}-{index:02d}-{how.split(':')[0].replace(' ', '-')}",
                model=model,
                batch=False,
                usage=usage,
                usd=usd,
            )
            total += usd
    finally:
        paid.guard.settle(job)
    outcome.usd = round(total, 6)


def prepare_paid_run(args: argparse.Namespace, frameworks: Sequence[Framework]) -> PaidRun:
    """Validate the credential environment and the budget before anything is built.

    Raises:
        SystemExit: 2 on a credential problem, 3 when the budget cannot cover the run.
    """
    from benchmarks._claude.budget import BudgetGuard, hard_cap_usd
    from benchmarks._claude.client import ClientConfigError, check_environment
    from benchmarks._claude.ledger import Ledger
    from benchmarks._claude.store import RunStore, git_state, new_run_id

    try:
        key = check_environment()
    except ClientConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    try:
        plan = budget_plan(frameworks, args.budget_usd, args.max_calls)
    except ValueError as exc:
        print(f"BUDGET: {exc}", file=sys.stderr)
        raise SystemExit(3) from exc
    ledger = Ledger()
    guard = BudgetGuard(args.budget_usd, ledger)
    total = sum(plan.values())
    if guard.headroom() < total:
        print(
            f"BUDGET: worst case ${total:.4f} exceeds ledger headroom ${guard.headroom():.4f} "
            f"(hard cap ${hard_cap_usd():.2f})",
            file=sys.stderr,
        )
        raise SystemExit(3)
    run_id = new_run_id("smoke")
    store = RunStore("smoke_frameworks", run_id)
    sha, dirty = git_state(REPO_ROOT)
    store.write_manifest(
        {
            "bench": "smoke_frameworks",
            "run_id": run_id,
            "git_sha": sha,
            "git_dirty": dirty,
            "model": MODEL,
            "max_tokens": MAX_TOKENS,
            "max_calls": args.max_calls,
            "budget_usd": args.budget_usd,
            "plan_usd": plan,
            "frameworks": list(plan),
            "workarounds": not args.no_workarounds,
            "command": sys.argv,
        }
    )
    return PaidRun(key, plan, child_rates(), ledger, guard, store, run_id)


def _print_summary(results: Mapping[str, Outcome], mode: str) -> None:
    print(
        "\n== framework smoke matrix "
        f"({'paid run on ' + MODEL if mode == 'run' else mode + ' mode, $0'}) =="
    )
    for key, outcome in results.items():
        payload = outcome.payload or {}
        label = outcome.status
        if mode == "mock" and outcome.status == PASS:
            label = "ready (scripted exchange PASS)"
        elif mode == "construct" and outcome.status == READY:
            label = "ready"
        spend = f" ${outcome.usd:.4f}" if outcome.usd is not None else ""
        print(f"- {FRAMEWORKS[key].title}: {label}{spend}")
        print(f"    versions: {_versions_cell(payload)}")
        if mode != "construct" and payload:
            print(
                f"    calls={payload.get('model_calls')} routes={payload.get('routes')} "
                f"delivery={payload.get('delivery')} thinking={payload.get('thinking')} "
                f"max_request_bytes={payload.get('max_request_bytes')}"
            )
        for note in outcome.notes:
            print(f"    note: {note}")


def doc_meta(
    results: Mapping[str, Outcome], *, max_calls: int, commit: str, now: datetime | None = None
) -> dict[str, str]:
    """The "Last run" facts for the docs block; the date is UTC."""
    airlock = next(
        (
            str(o.payload["versions"].get("agent-airlock"))
            for o in results.values()
            if o.payload and o.payload.get("versions")
        ),
        "unknown",
    )
    return {
        "date": (now or datetime.now(timezone.utc)).astimezone(timezone.utc).date().isoformat(),
        "model": MODEL,
        "max_tokens": str(MAX_TOKENS),
        "max_calls": str(max_calls),
        "airlock": airlock,
        "commit": commit,
        "spend": f"{sum(o.usd or 0.0 for o in results.values()):.4f}",
    }


def write_doc(
    results: Mapping[str, Outcome], meta: Mapping[str, str], path: Path = COMPAT_DOC
) -> None:
    """Rewrite the SMOKE-MATRIX block in ``path`` with ``results``."""
    block = render_block({k: o.as_dict() for k, o in results.items()}, meta)
    path.write_text(replace_block(path.read_text(encoding="utf-8"), block), encoding="utf-8")
    print(f"wrote the smoke matrix block to {path}")


def run_matrix(args: argparse.Namespace) -> int:
    frameworks = [FRAMEWORKS[k] for k in args.only] if args.only else list(FRAMEWORKS.values())
    mode = "run" if args.run else ("construct" if args.construct_only else "mock")
    paid = prepare_paid_run(args, frameworks) if mode == "run" else None
    uv = find_uv()
    try:
        wheel = build_wheel(uv)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, EnvironmentProblem) as exc:
        print(f"ERROR: wheel build failed: {exc}", file=sys.stderr)
        return 2
    pyproject_text = PYPROJECT.read_text(encoding="utf-8")
    results: dict[str, Outcome] = {}
    for fw in frameworks:
        print(f"\n### {fw.title} ({fw.key})", flush=True)
        if paid is not None:
            outcome = _paid_one(fw, paid, args, uv, wheel, pyproject_text)
        else:
            outcome = smoke_one(
                fw,
                mode=mode,
                wheel=wheel,
                reqs=requirements_for(fw, pyproject_text, workarounds=not args.no_workarounds),
                args=args,
                uv=uv,
                paid=None,
            )
        results[fw.key] = outcome
        print(f"{fw.key}: {outcome.status}", flush=True)
    _print_summary(results, mode)
    _save_results(results, args, paid)
    if args.write and paid is not None and any(o.status != SKIPPED for o in results.values()):
        from benchmarks._claude.store import git_state

        sha, dirty = git_state(REPO_ROOT)
        commit = sha[:10] + ("+dirty" if dirty else "")
        write_doc(results, doc_meta(results, max_calls=args.max_calls, commit=commit))
    code = exit_code(o.status for o in results.values())
    if code == 0 and not args.keep_venvs:
        for fw in frameworks:
            shutil.rmtree(VENV_ROOT / fw.key, ignore_errors=True)
            (VENV_ROOT / f"{fw.key}.install.log").unlink(missing_ok=True)
        if VENV_ROOT.exists() and not any(VENV_ROOT.iterdir()):
            VENV_ROOT.rmdir()
    elif code != 0:
        print(
            f"\nVenvs and child logs left under {VENV_ROOT} for triage. Remove the directory "
            "before `make check-links`, which reads every markdown file in the checkout, "
            "site-packages included.",
            file=sys.stderr,
        )
    return code


def _paid_one(
    fw: Framework,
    paid: PaidRun,
    args: argparse.Namespace,
    uv: str | None,
    wheel: Path,
    pyproject_text: str,
) -> Outcome:
    from benchmarks._claude.budget import BudgetExceededError

    job = f"smoke-frameworks-{paid.run_id}-{fw.key}"
    try:
        paid.guard.admit(job, paid.plan[fw.key])
    except BudgetExceededError as exc:
        return Outcome(SKIPPED, None, [f"budget: {exc}"])
    outcome = Outcome(ERROR, None, ["driver error before the child ran"])
    try:
        outcome = smoke_one(
            fw,
            mode="run",
            wheel=wheel,
            reqs=requirements_for(fw, pyproject_text, workarounds=not args.no_workarounds),
            args=args,
            uv=uv,
            paid=paid,
        )
    finally:
        if outcome.status == ENV and outcome.payload is None:
            paid.guard.ledger.release(job, reason="install failed; no model call made")
            outcome.usd = 0.0
        else:
            record_spend(paid, fw, outcome, args.max_calls)
    return outcome


def _save_results(
    results: Mapping[str, Outcome], args: argparse.Namespace, paid: PaidRun | None
) -> None:
    document = {k: o.as_dict() for k, o in results.items()}
    text = json.dumps(document, indent=2, sort_keys=True, default=str)
    if paid is not None:
        text = redact(text, [paid.key])
        paid.store.dir.mkdir(parents=True, exist_ok=True)
        (paid.store.dir / "results.json").write_text(text, encoding="utf-8")
        print(f"raw results: {paid.store.dir / 'results.json'}")
    if args.json_out:
        Path(args.json_out).write_text(text, encoding="utf-8")


def _parse_only(raw: str) -> list[str]:
    keys = [k.strip() for k in raw.split(",") if k.strip()]
    unknown = [k for k in keys if k not in FRAMEWORKS]
    if unknown:
        raise argparse.ArgumentTypeError(
            f"unknown framework(s) {unknown}; known: {', '.join(FRAMEWORKS)}"
        )
    return keys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="smoke_frameworks.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--only", type=_parse_only, help="comma-separated framework keys")
    parser.add_argument("--list", action="store_true", help="print the matrix and exit")
    parser.add_argument(
        "--construct-only", action="store_true", help="stop after install, import and construction"
    )
    parser.add_argument("--run", action="store_true", help="paid run on claude-haiku-5-5")
    parser.add_argument("--budget-usd", type=float, help="required with --run")
    parser.add_argument(
        "--max-calls",
        type=int,
        default=DEFAULT_MAX_CALLS,
        help="model calls allowed per framework (default 4)",
    )
    parser.add_argument(
        "--write", action="store_true", help="with --run: rewrite the docs/COMPATIBILITY.md block"
    )
    parser.add_argument(
        "--no-workarounds",
        action="store_true",
        help="run every framework as configured by default, even where it is "
        "known to send what Haiku 5.5 rejects",
    )
    parser.add_argument("--python", default=DEFAULT_PYTHON, help="venv Python (uv only)")
    parser.add_argument(
        "--reuse-venvs", action="store_true", help="keep existing venvs; reinstall only the wheel"
    )
    parser.add_argument("--keep-venvs", action="store_true", help="keep venvs on success")
    parser.add_argument("--json-out", help="also write the results JSON here")
    parser.add_argument(
        "--dump-requests",
        action="store_true",
        help="write each /v1/messages request body to <venv>/work/requests/ "
        "for triage (bodies hold prompts and tool traffic, never the key)",
    )
    return parser


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Reject flag combinations that would spend without a cap or write a $0 result."""
    if args.run and (args.budget_usd is None or args.budget_usd <= 0):
        parser.error("--run requires a positive --budget-usd")
    if args.budget_usd is not None and not args.run:
        parser.error("--budget-usd applies only with --run")
    if args.write and not args.run:
        parser.error("--write requires --run: the docs table records paid runs only")
    if args.write and args.only:
        parser.error("--write records the whole matrix; drop --only")
    if args.run and args.construct_only:
        parser.error("--run and --construct-only are exclusive")
    if not 1 <= args.max_calls <= 8:
        parser.error("--max-calls must be between 1 and 8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_args(parser, args)
    if args.list:
        for fw in FRAMEWORKS.values():
            print(f"{fw.key:18} {fw.title:20} {fw.airlock_path}")
        for name, reason in EXCLUDED.items():
            print(f"{'(excluded)':18} {name}: {reason}")
        return 0
    for path in (REPO_ROOT, REPO_ROOT / "src"):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    try:
        return run_matrix(args)
    except SystemExit as exc:
        return int(exc.code or 0)


# --------------------------------------------------------------------------------------
# The child: one script per framework, run with that framework's venv python (-I)
# --------------------------------------------------------------------------------------

CHILD_COMMON = r'''
"""agent-airlock framework smoke child. Generated by scripts/smoke_frameworks.py; do not edit.

Runs inside one framework's throwaway virtualenv. Builds two tools whose bodies append to a
canary list, wraps them with that framework's agent-airlock integration, drives the agent,
and prints one line, RESULT_MARKER + JSON, with what it observed. Every /v1/messages request
passes through Recorder: hooks on httpx and httpx2 see the Python clients, and in mock mode
a loopback server answers anything that ignores them (the Claude Agent SDK's CLI).
"""

import asyncio
import base64
import importlib
import importlib.metadata
import itertools
import json
import os
import re
import sys
import threading
import warnings
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

MODE = os.environ.get("SMOKE_MODE", "construct")
FRAMEWORK = os.environ.get("SMOKE_FRAMEWORK", "unknown")
MODEL = os.environ.get("SMOKE_MODEL", "claude-haiku-5-5")
MAX_TOKENS = int(os.environ.get("SMOKE_MAX_TOKENS", "4096"))
MAX_CALLS = int(os.environ.get("SMOKE_MAX_CALLS", "0"))  # hard cap; 0 in construct mode
TURNS = max(1, int(os.environ.get("SMOKE_TURNS", "4")))  # the framework's own turn limit
BUDGET_USD = float(os.environ.get("SMOKE_BUDGET_USD") or 0)
RATES = json.loads(os.environ.get("SMOKE_RATES") or "{}")
PROMPT = os.environ.get("SMOKE_PROMPT", "")
SYSTEM = os.environ.get("SMOKE_SYSTEM", "")
WORKDIR = os.environ.get("SMOKE_WORKDIR", ".")
WORKAROUNDS = os.environ.get("SMOKE_WORKAROUNDS", "1") == "1"
DUMP_REQUESTS = os.environ.get("SMOKE_DUMP_REQUESTS") == "1"
AUDIT_PATH = os.environ.get("AIRLOCK_AUDIT_LOG_PATH", "airlock_audit.json")
RESULT_MARKER = "AIRLOCK_SMOKE_RESULT "
ALLOWED, DENIED, FINAL_TOOL, ORDER_ID = "get_order_status", "delete_order", "final_answer", "A-1001"
MOCK_USAGE = {
    "input_tokens": 11,
    "output_tokens": 7,
    "cache_creation_input_tokens": 0,
    "cache_read_input_tokens": 0,
}
MOCK_URL = None

CANARY = {ALLOWED: [], DENIED: []}
GUARD_REFUSALS = []
NOTES = []


class SmokeBudgetAbort(RuntimeError):
    """The child refused to send a model request: its call cap or dollar share is spent."""


def order_status_body(order_id):
    CANARY[ALLOWED].append(order_id)
    return f"Order {order_id} has shipped."


def delete_order_body(order_id):
    CANARY[DENIED].append(order_id)
    return f"Order {order_id} was deleted."


def make_policy(*extra_allowed):
    from agent_airlock import SecurityPolicy

    return SecurityPolicy(allowed_tools=[ALLOWED, *extra_allowed])


def note(text):
    if text not in NOTES:
        NOTES.append(text)


def base_tool_name(name):
    name = str(name or "")
    if name.startswith("mcp__"):
        name = name.split("__")[-1]
    return name.strip().lower().replace(" ", "_").replace("-", "_")


def redact(text):
    text = str(text)
    key = os.environ.get("ANTHROPIC_API_KEY") or ""
    if MODE == "run" and len(key) >= 8:
        text = text.replace(key, "[REDACTED]")
    return re.sub(r"sk-ant-[A-Za-z0-9_\-]{8,}", "sk-ant-[REDACTED]", text)


def describe(exc):
    return redact(f"{type(exc).__name__}: {exc}")[:400]


def where(exc, depth=4):
    """The innermost frames of ``exc``'s traceback, as short ``package/file.py:line`` entries."""
    import traceback

    frames = traceback.extract_tb(exc.__traceback__)[-depth:]
    return [f"{f.filename.split('site-packages/')[-1]}:{f.lineno} {f.name}" for f in frames]


# ---- the scripted model (mock mode) ----------------------------------------------------

_MESSAGE_IDS = itertools.count(1)


def _text_of(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            str(b.get("text") or "") for b in content if isinstance(b, dict) and b.get("type") == "text"
        )
    return ""


def react_actions(text):
    return [base_tool_name(m) for m in re.findall(r"Action:\s*([A-Za-z_][\w\-]*)", text or "")]


_NAMED_CALL = re.compile(r"""["']name["']\s*:\s*["']([A-Za-z_][\w\-]*)["']""")


def text_calls(text):
    """Calls a framework replays as text: ReAct ``Action: x`` lines and ``'name': 'x'`` blobs.

    smolagents, for one, sends earlier tool calls back as "Calling tools: [...]" text rather
    than as tool_use blocks.
    """
    return react_actions(text) + [base_tool_name(m) for m in _NAMED_CALL.findall(text or "")]


_ERRORED_CALL = re.compile(r"Error executing tool '([A-Za-z_][\w\-]*)'")


def called_tools(messages):
    """Tool names already called in a request's history: tool_use blocks and text replays.

    A call that failed may appear only as error text in a user turn (smolagents drops a
    refused call from the assistant history and reports "Error executing tool 'x'").
    """
    called = set()
    for message in messages:
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if message.get("role") == "user":
            called.update(base_tool_name(m) for m in _ERRORED_CALL.findall(_text_of(content)))
            continue
        if message.get("role") != "assistant":
            continue
        called.update(text_calls(_text_of(content)))
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    called.add(base_tool_name(block.get("name")))
    return called


def _pick(tools, wanted):
    return next((t for t in tools if base_tool_name(t.get("name")) == wanted), None)


def _tool_input(tool, value):
    schema = tool.get("input_schema") or {}
    properties = schema.get("properties") or {}
    if "order_id" in properties:
        return {"order_id": value}
    required = schema.get("required") or list(properties)
    return {required[0]: value} if required else {"order_id": value}


def _react_prompt(body):
    system = body.get("system")
    text = system if isinstance(system, str) else _text_of(system)
    for message in body.get("messages") or []:
        if isinstance(message, dict):
            text += "\n" + _text_of(message.get("content"))
    return "Action Input:" in text


def scripted_blocks(body):
    """The next turn for a request: get_order_status, then delete_order, then DONE."""
    tools = [t for t in body.get("tools") or [] if isinstance(t, dict) and t.get("name")]
    called = called_tools(body.get("messages") or [])
    if tools:
        for wanted in (ALLOWED, DENIED):
            tool = _pick(tools, wanted)
            if tool is not None and wanted not in called:
                return [_tool_use(tool, _tool_input(tool, ORDER_ID))], "tool_use"
        final = _pick(tools, FINAL_TOOL)
        if final is not None and FINAL_TOOL not in called:
            return [_tool_use(final, _tool_input(final, "DONE"))], "tool_use"
        return [{"type": "text", "text": "DONE"}], "end_turn"
    if _react_prompt(body):
        for wanted in (ALLOWED, DENIED):
            if wanted not in called:
                action = json.dumps({"order_id": ORDER_ID})
                text = f"Thought: I will call {wanted}.\nAction: {wanted}\nAction Input: {action}"
                return [{"type": "text", "text": text}], "end_turn"
        final_text = "Thought: I now know the final answer\nFinal Answer: DONE"
        return [{"type": "text", "text": final_text}], "end_turn"
    return [{"type": "text", "text": "DONE"}], "end_turn"


def _tool_use(tool, arguments):
    return {"type": "tool_use", "id": f"toolu_airlock_smoke_{next(_MESSAGE_IDS):04d}",
            "name": tool["name"], "input": arguments}


def scripted_message(body):
    """A Messages API response shaped like Haiku 5.5's default: a thinking block first."""
    n = next(_MESSAGE_IDS)
    blocks, stop = scripted_blocks(body)
    signature = base64.b64encode(f"airlock-smoke-mock-signature-{n}".encode()).decode()
    return {
        "id": f"msg_airlock_smoke_{n:04d}",
        "type": "message",
        "role": "assistant",
        "model": body.get("model") or MODEL,
        "content": [{"type": "thinking", "thinking": "", "signature": signature}, *blocks],
        "stop_reason": stop,
        "stop_sequence": None,
        "usage": dict(MOCK_USAGE),
    }


def sse_bytes(message):
    """``message`` as the Messages API streams it."""
    start = dict(message, content=[], stop_reason=None, stop_sequence=None,
                 usage=dict(message["usage"], output_tokens=1))
    events = [("message_start", {"type": "message_start", "message": start})]
    for index, block in enumerate(message["content"]):
        events.extend(_block_events(index, block))
    events.append(("message_delta", {"type": "message_delta",
                                     "delta": {"stop_reason": message["stop_reason"], "stop_sequence": None},
                                     "usage": {"output_tokens": message["usage"]["output_tokens"]}}))
    events.append(("message_stop", {"type": "message_stop"}))
    return "".join(f"event: {name}\ndata: {json.dumps(data)}\n\n" for name, data in events).encode()


def _block_events(index, block):
    kind = block["type"]
    if kind == "thinking":
        start, delta = {"type": "thinking", "thinking": "", "signature": ""}, {
            "type": "signature_delta", "signature": block["signature"]}
    elif kind == "tool_use":
        start = {"type": "tool_use", "id": block["id"], "name": block["name"], "input": {}}
        delta = {"type": "input_json_delta", "partial_json": json.dumps(block["input"])}
    else:
        start, delta = {"type": "text", "text": ""}, {"type": "text_delta", "text": block["text"]}
    return [
        ("content_block_start", {"type": "content_block_start", "index": index, "content_block": start}),
        ("content_block_delta", {"type": "content_block_delta", "index": index, "delta": delta}),
        ("content_block_stop", {"type": "content_block_stop", "index": index}),
    ]


def mock_reply(body):
    message = scripted_message(body)
    if body.get("stream"):
        return sse_bytes(message), "text/event-stream"
    return json.dumps(message).encode(), "application/json"


def canned_reply(method, path):
    """Answers for the non-messages endpoints a client may touch in mock mode."""
    if path.endswith("/v1/messages/count_tokens"):
        return 200, {"input_tokens": MOCK_USAGE["input_tokens"]}
    if method == "GET" and "/v1/models" in path:
        model = {"type": "model", "id": MODEL, "display_name": "Claude Haiku 5.5",
                 "created_at": "2026-01-01T00:00:00Z"}
        if path.rstrip("/").endswith("/v1/models"):
            return 200, {"data": [model], "has_more": False, "first_id": MODEL, "last_id": MODEL}
        return 200, model
    return 404, {"type": "error", "error": {"type": "not_found_error",
                                            "message": "airlock smoke mock: no such endpoint"}}


# ---- parsing what goes over the wire ---------------------------------------------------


def parse_sse(raw):
    model, usage, blocks, stop = None, {}, {}, None
    for line in raw.decode("utf-8", "replace").splitlines():
        if not line.startswith("data:"):
            continue
        try:
            event = json.loads(line[5:].strip())
        except ValueError:
            continue
        kind = event.get("type") if isinstance(event, dict) else None
        if kind == "message_start":
            message = event.get("message") or {}
            model = message.get("model") or model
            usage.update(message.get("usage") or {})
        elif kind == "content_block_start":
            blocks[event.get("index")] = dict(event.get("content_block") or {})
        elif kind == "content_block_delta":
            delta = event.get("delta") or {}
            block = blocks.setdefault(event.get("index"), {})
            if delta.get("type") == "signature_delta":
                block["signature"] = (block.get("signature") or "") + str(delta.get("signature") or "")
        elif kind == "message_delta":
            usage.update({k: v for k, v in (event.get("usage") or {}).items() if v is not None})
            stop = (event.get("delta") or {}).get("stop_reason") or stop
    if model is None and not blocks:
        return None
    ordered = [blocks[i] for i in sorted(k for k in blocks if isinstance(k, int))]
    return {"model": model, "usage": usage, "content": ordered, "stop_reason": stop}


def parse_message_payload(raw, content_type):
    head = raw.lstrip()[:6]
    if "event-stream" in (content_type or "") or head.startswith((b"event:", b"data:")):
        return parse_sse(raw)
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(data, dict) or data.get("type") != "message":
        return None
    return {"model": data.get("model"), "usage": data.get("usage") or {},
            "content": data.get("content") or [], "stop_reason": data.get("stop_reason")}


def error_text(raw, status):
    try:
        error = json.loads(raw).get("error") or {}
        return redact(f"HTTP {status} {error.get('type')}: {error.get('message')}")[:300]
    except (ValueError, AttributeError):
        return f"HTTP {status}"


def clean_usage(usage):
    out = {k: v for k, v in usage.items() if isinstance(v, (int, float)) and not isinstance(v, bool)}
    cache_creation = usage.get("cache_creation")
    if isinstance(cache_creation, dict):
        out["cache_creation"] = {k: v for k, v in cache_creation.items() if isinstance(v, (int, float))}
    return out


def price(usage):
    """Rough USD for the in-process guard; the parent re-prices exactly into the ledger."""
    if not RATES or not usage:
        return 0.0
    prompt = sum(int(usage.get(k) or 0) for k in
                 ("input_tokens", "cache_read_input_tokens", "cache_creation_input_tokens"))
    threshold, multiplier = RATES.get("long_prompt") or (10**12, 1.0)
    scale = multiplier if prompt > threshold else 1.0
    return scale * (
        int(usage.get("input_tokens") or 0) * RATES["input"]
        + int(usage.get("output_tokens") or 0) * RATES["output"]
        + int(usage.get("cache_read_input_tokens") or 0) * RATES["cache_read"]
        + int(usage.get("cache_creation_input_tokens") or 0) * RATES["cache_write_1h"]
    ) / 1_000_000


def request_worst_case(body, nbytes):
    if not RATES:
        raise SmokeBudgetAbort("no rates for the dollar guard; refusing to send")
    est_input = nbytes // 3 + 1
    output = int(body.get("max_tokens") or MAX_TOKENS)
    threshold, multiplier = RATES.get("long_prompt") or (10**12, 1.0)
    scale = multiplier if est_input > threshold else 1.0
    return scale * (est_input * RATES["input"] + output * RATES["output"]) / 1_000_000


def wire_summary(body):
    messages = body.get("messages") if isinstance(body.get("messages"), list) else []
    last = messages[-1] if messages and isinstance(messages[-1], dict) else {}
    return {
        "model": body.get("model"),
        "max_tokens": body.get("max_tokens"),
        "sampling": {k: body[k] for k in ("temperature", "top_p", "top_k") if k in body},
        "thinking": body.get("thinking"),
        "output_config": body.get("output_config"),
        "tool_choice": body.get("tool_choice"),
        "stream": bool(body.get("stream")),
        "tools": [str(t.get("name")) for t in body.get("tools") or [] if isinstance(t, dict)],
        "last_role": last.get("role"),
        "keys": sorted(body),
    }


def merge_wire(wires):
    if not wires:
        return {}
    sampling = {}
    for wire in wires:
        for name, value in wire["sampling"].items():
            sampling.setdefault(name, value)
    return {
        "models": sorted({str(w["model"]) for w in wires}),
        "max_tokens": sorted({w["max_tokens"] for w in wires if isinstance(w["max_tokens"], int)}),
        "sampling": sampling,
        "thinking": next((w["thinking"] for w in wires if w["thinking"] is not None), None),
        "output_config": next((w["output_config"] for w in wires if w["output_config"] is not None), None),
        "tool_choice": sorted({json.dumps(w["tool_choice"], sort_keys=True) for w in wires
                               if w["tool_choice"] is not None}),
        "stream": sorted({w["stream"] for w in wires}),
        "prefill": any(w["last_role"] == "assistant" for w in wires),
        "keys": sorted(set().union(*(w["keys"] for w in wires))),
        "tools": wires[0]["tools"],
    }


def _tool_result_text(block):
    content = block.get("content")
    return content if isinstance(content, str) else _text_of(content) if content else ""


class Recorder:
    """Every /v1/messages request the child sees, whichever route it took."""

    def __init__(self):
        self.lock = threading.RLock()
        self.calls = []
        self.other = {}
        self.spent = 0.0
        self.signatures = []
        self.echoed = set()
        self.tool_uses = []
        self.deliveries = {}
        self.text_delivery = False
        self.aborts = []
        self.auth_kinds = set()
        self.sdk_usage = []

    def begin(self, route, raw):
        try:
            body = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, ValueError):
            body = {}
        body = body if isinstance(body, dict) else {}
        with self.lock:
            try:
                self._admit(body, len(raw))
            except SmokeBudgetAbort as exc:
                self.aborts.append(str(exc))
                raise
            call = {"route": route, "status": None, "model": body.get("model"), "usage": None,
                    "bytes": len(raw), "wire": wire_summary(body), "body": body}
            self.calls.append(call)
            self._observe_request(body)
            if DUMP_REQUESTS:
                path = os.path.join(WORKDIR, "requests", f"{len(self.calls):02d}.json")
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump(body, handle, indent=2, default=str)
        return call

    def _admit(self, body, nbytes):
        if len(self.calls) >= MAX_CALLS:
            raise SmokeBudgetAbort(f"the cap of {MAX_CALLS} model calls is reached; not sent")
        if MODE != "run":
            return
        worst = request_worst_case(body, nbytes)
        if self.spent + worst > BUDGET_USD:
            raise SmokeBudgetAbort(
                f"worst case ${worst:.5f} exceeds the ${BUDGET_USD - self.spent:.5f} left of "
                "this framework's share; not sent")

    def _observe_request(self, body):
        names = {}
        denied_called = False
        for message in body.get("messages") or []:
            if not isinstance(message, dict):
                continue
            content = message.get("content")
            role = message.get("role")
            text = _text_of(content)
            if role == "assistant" and DENIED in text_calls(text):
                denied_called = True
            if role == "user" and (denied_called or DENIED in text) and "AIRLOCK" in text.upper():
                self.text_delivery = True
            if not isinstance(content, list):
                continue
            for block in content:
                if not isinstance(block, dict):
                    continue
                kind = block.get("type")
                if role == "assistant" and kind == "thinking" and block.get("signature"):
                    self.echoed.add(block["signature"])
                elif role == "assistant" and kind == "tool_use":
                    names[block.get("id")] = base_tool_name(block.get("name"))
                    denied_called = denied_called or names[block.get("id")] == DENIED
                elif kind == "tool_result" and names.get(block.get("tool_use_id")) == DENIED:
                    self.deliveries[block.get("tool_use_id")] = {
                        "is_error": bool(block.get("is_error")),
                        "airlock_text": "AIRLOCK" in _tool_result_text(block).upper(),
                    }

    def finish(self, call, status, raw, content_type):
        with self.lock:
            if call.get("finished"):
                return
            call["finished"] = True
            call["status"] = status
            if status != 200:
                call["error"] = error_text(raw, status)
                return
            parsed = parse_message_payload(raw, content_type)
            if parsed is None:
                call["usage_unparsed"] = True
                return
            index = next(i for i, c in enumerate(self.calls) if c is call)
            call["model"] = parsed.get("model") or call["model"]
            call["usage"] = clean_usage(parsed.get("usage") or {})
            call["stop_reason"] = parsed.get("stop_reason")
            for block in parsed.get("content") or []:
                kind = block.get("type")
                if kind == "tool_use":
                    self.tool_uses.append(base_tool_name(block.get("name")))
                elif kind == "thinking" and block.get("signature") and call["stop_reason"] == "tool_use":
                    self.signatures.append((index, block["signature"]))
                elif kind == "text":
                    self.tool_uses.extend(react_actions(block.get("text") or ""))
            self.spent += price(call["usage"])

    def add_external(self, model, usage, route, represents=1):
        """Usage of calls made outside this process (the Claude Agent SDK's CLI), as it reports.

        ``represents`` is how many API calls one aggregate entry stands for.
        """
        with self.lock:
            usage = clean_usage(usage or {})
            self.calls.append({"route": route, "status": 200, "model": model, "usage": usage,
                               "bytes": 0, "wire": wire_summary({"model": model}), "body": {},
                               "finished": True, "represents": represents})
            self.spent += price(usage)

    def add_unobserved(self, route, count):
        with self.lock:
            for _ in range(count):
                self.calls.append({"route": route, "status": None, "model": MODEL, "usage": None,
                                   "bytes": 0, "wire": wire_summary({"model": MODEL}), "body": {}})

    def note_other(self, method, url):
        parts = urlsplit(str(url))
        label = f"{method} {parts.hostname}{parts.path}"
        with self.lock:
            self.other[label] = self.other.get(label, 0) + 1

    def summary(self):
        with self.lock:
            calls = list(self.calls)
            last = len(calls) - 1
            eligible = [sig for index, sig in self.signatures if index < last]
            if not eligible:
                thinking = "n/a"
            else:
                kept = [sig for sig in eligible if sig in self.echoed]
                thinking = "kept" if len(kept) == len(eligible) else "dropped" if not kept else "partial"
            delivered = list(self.deliveries.values())
            if delivered:
                delivery = "error" if delivered[-1]["is_error"] else "result"
                airlock_text = delivered[-1]["airlock_text"]
            elif self.text_delivery:
                delivery, airlock_text = "text", True
            else:
                delivery, airlock_text = "not seen", None
            return {
                "model_calls": sum(int(c.get("represents", 1)) for c in calls),
                "usage": [{"model": c["model"], "usage": c["usage"]} for c in calls
                          if c.get("status") == 200 and c.get("usage") is not None],
                "unobserved_calls": sum(
                    1 for c in calls if c.get("status") is None or c.get("usage_unparsed")),
                "http_errors": [c["error"] for c in calls if c.get("error")][:3],
                "routes": sorted({c["route"] for c in calls}),
                "wire": merge_wire([c["wire"] for c in calls if c.get("bytes")]),
                "response_models": sorted({str(c["model"]) for c in calls if c.get("status") == 200}),
                "stop_reasons": sorted({str(c["stop_reason"]) for c in calls if c.get("stop_reason")}),
                "max_request_bytes": max((c["bytes"] for c in calls), default=0),
                "thinking": thinking,
                "delivery": delivery,
                "delivery_airlock_text": airlock_text,
                "tool_uses": list(self.tool_uses),
                "other_requests": dict(sorted(self.other.items())),
                "auth_kinds": sorted(self.auth_kinds),
                "aborts": list(self.aborts),
                "sdk_usage": list(self.sdk_usage),
            }


RECORDER = Recorder()


# ---- interception: httpx / httpx2 hooks and the loopback server -------------------------


def is_messages_call(method, url):
    return method.upper() == "POST" and urlsplit(str(url)).path.rstrip("/").endswith("/v1/messages")


def _is_anthropic_host(host):
    return bool(host) and (host == "anthropic.com" or host.endswith(".anthropic.com"))


def _request_bytes(request):
    try:
        return bytes(request.content)
    except Exception:
        try:
            return bytes(request.read())
        except Exception:
            return b""


OBSERVED_HEADER = "x-airlock-smoke-observed"


def _to_loopback(url):
    if not MOCK_URL:
        return False
    mock = urlsplit(MOCK_URL)
    return url.host == mock.hostname and url.port == mock.port


def _plan(lib, request):
    """("mock", call) | ("canned", (status, body)) | ("pass", call or None).

    In mock mode a request bound for the loopback server is sent for real and observed the
    way run mode observes Anthropic's responses (streams included); one bound anywhere else
    is answered in-process, and nothing is forwarded to Anthropic.
    """
    method, url = request.method, request.url
    if is_messages_call(method, url):
        call = RECORDER.begin(f"hook:{lib}", _request_bytes(request))
        if MODE == "run":
            return "pass", call
        if _to_loopback(url):
            request.headers[OBSERVED_HEADER] = "1"
            call["route"] = f"hook:{lib}+loopback"
            return "pass", call
        return "mock", call
    RECORDER.note_other(method, url)
    if MODE != "run" and _is_anthropic_host(url.host):
        return "canned", canned_reply(method, url.path)
    return "pass", None


def _mock_response(module, request, plan):
    kind, value = plan
    if kind == "mock":
        raw, ctype = mock_reply(value["body"])
        RECORDER.finish(value, 200, raw, ctype)
        status = 200
    else:
        status, payload = value
        raw, ctype = json.dumps(payload).encode(), "application/json"
    headers = {"content-type": ctype, "request-id": "req_airlock_smoke_mock"}
    return module.Response(status, headers=headers, content=raw, request=request)


def _observe(call, response, streamed, is_async):
    if call is None:
        return
    ctype = response.headers.get("content-type", "")
    if not streamed:
        try:
            raw = response.content
        except Exception:
            raw = b""
        RECORDER.finish(call, response.status_code, raw, ctype)
        return
    status = response.status_code
    if is_async:
        original = response.aiter_bytes

        async def aiter_bytes(*args, **kwargs):
            buffer = bytearray()
            try:
                async for chunk in original(*args, **kwargs):
                    buffer.extend(chunk)
                    yield chunk
            finally:
                RECORDER.finish(call, status, bytes(buffer), ctype)

        response.aiter_bytes = aiter_bytes
    else:
        original = response.iter_bytes

        def iter_bytes(*args, **kwargs):
            buffer = bytearray()
            try:
                for chunk in original(*args, **kwargs):
                    buffer.extend(chunk)
                    yield chunk
            finally:
                RECORDER.finish(call, status, bytes(buffer), ctype)

        response.iter_bytes = iter_bytes


def install_hooks():
    hooked = []
    for lib in ("httpx", "httpx2"):
        try:
            module = importlib.import_module(lib)
        except ImportError:
            continue
        _patch(module, lib)
        hooked.append(lib)
    return hooked


def _patch(module, lib):
    sync_send, async_send = module.Client.send, module.AsyncClient.send

    def send(self, request, *args, **kwargs):
        plan = _plan(lib, request)
        if plan[0] != "pass":
            return _mock_response(module, request, plan)
        response = sync_send(self, request, *args, **kwargs)
        _observe(plan[1], response, bool(kwargs.get("stream")), False)
        return response

    async def asend(self, request, *args, **kwargs):
        plan = _plan(lib, request)
        if plan[0] != "pass":
            return _mock_response(module, request, plan)
        response = await async_send(self, request, *args, **kwargs)
        _observe(plan[1], response, bool(kwargs.get("stream")), True)
        return response

    module.Client.send = send
    module.AsyncClient.send = asend


class _MockHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _read_body(self):
        if "chunked" in (self.headers.get("transfer-encoding") or "").lower():
            chunks = []
            while True:
                size = int(self.rfile.readline().strip().split(b";")[0] or b"0", 16)
                if size == 0:
                    self.rfile.readline()
                    return b"".join(chunks)
                chunks.append(self.rfile.read(size))
                self.rfile.readline()
        length = int(self.headers.get("content-length") or 0)
        return self.rfile.read(length) if length else b""

    def _send(self, status, ctype, raw):
        self.send_response(status)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(raw)))
        self.send_header("request-id", "req_airlock_smoke_mock")
        self.end_headers()
        self.wfile.write(raw)

    def _auth_kind(self):
        if self.headers.get("x-api-key"):
            RECORDER.auth_kinds.add("x-api-key")
        if (self.headers.get("authorization") or "").lower().startswith("bearer"):
            RECORDER.auth_kinds.add("bearer")

    def do_POST(self):
        raw = self._read_body()
        url = f"http://{self.headers.get('host', '127.0.0.1')}{self.path}"
        self._auth_kind()
        if not is_messages_call("POST", url):
            RECORDER.note_other("POST", url)
            status, payload = canned_reply("POST", urlsplit(url).path)
            return self._send(status, "application/json", json.dumps(payload).encode())
        if self.headers.get(OBSERVED_HEADER):
            try:
                body = json.loads(raw.decode("utf-8")) if raw else {}
            except (UnicodeDecodeError, ValueError):
                body = {}
            out, ctype = mock_reply(body if isinstance(body, dict) else {})
            return self._send(200, ctype, out)
        try:
            call = RECORDER.begin("server", raw)
        except SmokeBudgetAbort as exc:
            payload = {"type": "error", "error": {"type": "invalid_request_error", "message": str(exc)}}
            return self._send(400, "application/json", json.dumps(payload).encode())
        out, ctype = mock_reply(call["body"])
        RECORDER.finish(call, 200, out, ctype)
        self._send(200, ctype, out)

    def do_GET(self):
        url = f"http://{self.headers.get('host', '127.0.0.1')}{self.path}"
        RECORDER.note_other("GET", url)
        status, payload = canned_reply("GET", urlsplit(url).path)
        self._send(status, "application/json", json.dumps(payload).encode())


class MockServer:
    def __init__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _MockHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self):
        self.thread.start()
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


# ---- observations and the result line --------------------------------------------------


def read_audit():
    records = []
    try:
        with open(AUDIT_PATH, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line.startswith("{"):
                    try:
                        records.append(json.loads(line))
                    except ValueError:
                        continue
    except OSError:
        pass
    return records


def observations():
    audit = read_audit()
    blocked = {base_tool_name(r.get("tool_name")) for r in audit if r.get("blocked")}
    seen = {base_tool_name(r.get("tool_name")) for r in audit}
    guarded = {base_tool_name(n) for n in GUARD_REFUSALS}
    summary = RECORDER.summary()
    if MODE == "run" and summary["model_calls"] == 0 and (CANARY[ALLOWED] or CANARY[DENIED]):
        note("tools ran but no model call crossed the hooks; spend is booked at the worst case")
        RECORDER.add_unobserved("unhooked", TURNS)
        summary = RECORDER.summary()
    denied_refused = DENIED in blocked or DENIED in guarded
    admitted = sum(1 for r in audit if base_tool_name(r.get("tool_name")) == ALLOWED
                   and not r.get("blocked"))
    if CANARY[ALLOWED] and admitted > len(CANARY[ALLOWED]):
        note(f"{admitted} audit records for {len(CANARY[ALLOWED])} allowed call(s): the tool "
             "is wrapped by Airlock more than once")
    return {
        "allowed_ran": bool(CANARY[ALLOWED]),
        "denied_ran": bool(CANARY[DENIED]),
        "allowed_refused": ALLOWED in blocked or ALLOWED in guarded,
        "denied_refused": denied_refused,
        "denied_attempted": bool(CANARY[DENIED]) or denied_refused or DENIED in seen
        or DENIED in summary["tool_uses"],
        "audit_records": len(audit),
        "budget_abort": bool(summary["aborts"]),
        **summary,
    }


def child_status(result):
    """The child's own verdict; the parent recomputes it with ``classify`` and keeps its own."""
    if not result.get("constructed"):
        return "ENV" if result.get("error_import") else "ERROR"
    if MODE == "construct":
        return "READY"
    if result.get("denied_ran") or result.get("allowed_refused"):
        return "FAIL"
    if result.get("allowed_ran") and result.get("denied_refused"):
        return "PASS"
    if not result.get("denied_attempted"):
        return "ERROR" if result.get("error") else "INCONCLUSIVE"
    return "FAIL"


def versions():
    found = {}
    for dist in (*VERSIONS, "agent-airlock"):
        try:
            found[dist] = importlib.metadata.version(dist)
        except importlib.metadata.PackageNotFoundError:
            found[dist] = "not installed"
    return found


def airlock_warnings(caught):
    keep = []
    for item in caught:
        text = str(item.message)
        if "agent-airlock" in text or "SUPPORTED_" in text:
            keep.append(redact(text.split(". ")[0])[:300])
    return sorted(set(keep))


def litellm_model_note():
    """Whether LiteLLM knows the model id, from the map it loaded and from its bundled copy.

    LiteLLM fetches its model map from GitHub at import; the copy in the wheel is what it
    falls back to offline or under LITELLM_LOCAL_MODEL_COST_MAP=True.
    """
    try:
        import litellm

        litellm.get_model_info(f"anthropic/{MODEL}")
    except Exception as exc:
        note(f"LiteLLM has no model info for anthropic/{MODEL} ({type(exc).__name__})")
    try:
        import importlib.resources

        bundled = json.loads(
            (importlib.resources.files("litellm") / "model_prices_and_context_window_backup.json")
            .read_text(encoding="utf-8"))
    except Exception:
        return
    if MODEL not in bundled and f"anthropic/{MODEL}" not in bundled:
        version = importlib.metadata.version("litellm")
        note(f"litellm {version}'s bundled model map lacks {MODEL}: it is known only from the "
             "map litellm fetches from GitHub at import (not offline, not with "
             "LITELLM_LOCAL_MODEL_COST_MAP=True)")


def emit(result):
    line = redact(json.dumps(result, default=str, sort_keys=True))
    sys.stdout.write("\n" + RESULT_MARKER + line + "\n")
    sys.stdout.flush()


def main():
    global MOCK_URL
    result = {"framework": FRAMEWORK, "mode": MODE, "constructed": False}
    server = None
    try:
        result["hooked"] = install_hooks()
        if MODE == "mock":
            server = MockServer()
            MOCK_URL = server.start()
            os.environ["ANTHROPIC_BASE_URL"] = MOCK_URL
            os.environ["ANTHROPIC_API_BASE"] = MOCK_URL
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            handle = construct()
        result["constructed"] = True
        result["warnings"] = airlock_warnings(caught)
        if MODE != "construct":
            final = run_agent(handle)
            result["final_text"] = None if final is None else redact(final)[:200]
    except BaseException as exc:  # a framework may raise SystemExit; everything is reported
        if isinstance(exc, KeyboardInterrupt):
            raise
        result["error_stage"] = "run" if result["constructed"] else "construct"
        result["error"] = describe(exc)
        result["error_where"] = where(exc)
        result["error_import"] = isinstance(exc, ImportError)
    finally:
        try:
            result.update(observations())
        except Exception as exc:
            result["observe_error"] = describe(exc)
        result["versions"] = versions()
        result["notes"] = list(NOTES)
        result["status"] = child_status(result)
        if server is not None:
            server.stop()
        emit(result)
    return 0
'''


CHILD_BODIES: dict[str, str] = {
    "anthropic": r'''
        def construct():
            import anthropic
            from agent_airlock.integrations.anthropic import ToolRegistry

            registry = ToolRegistry(policy=make_policy())

            @registry.tool()
            def get_order_status(order_id: str) -> str:
                """Look up the shipping status of an order."""
                return order_status_body(order_id)

            @registry.tool()
            def delete_order(order_id: str) -> str:
                """Delete an order permanently."""
                return delete_order_body(order_id)

            return anthropic.Anthropic(), registry


        def run_agent(handle):
            from agent_airlock.integrations.anthropic import process_message_tools

            client, registry = handle
            messages = [{"role": "user", "content": PROMPT}]
            for _ in range(TURNS):
                message = client.messages.create(
                    model=MODEL, max_tokens=MAX_TOKENS, system=SYSTEM,
                    tools=registry.get_tool_definitions(), messages=messages,
                )
                if message.stop_reason != "tool_use":
                    return "".join(b.text for b in message.content if b.type == "text")
                messages.append({"role": "assistant", "content": message.content})
                messages.append({"role": "user", "content": process_message_tools(message, registry)})
            return None
    ''',
    "langchain": r'''
        def construct():
            from langchain.agents import create_agent
            from langchain_anthropic import ChatAnthropic
            from agent_airlock.integrations.langchain import create_secure_tool

            def get_order_status(order_id: str) -> str:
                """Look up the shipping status of an order."""
                return order_status_body(order_id)

            def delete_order(order_id: str) -> str:
                """Delete an order permanently."""
                return delete_order_body(order_id)

            policy = make_policy()
            tools = [create_secure_tool(get_order_status, policy=policy),
                     create_secure_tool(delete_order, policy=policy)]
            model = ChatAnthropic(model=MODEL, max_tokens=MAX_TOKENS)
            return create_agent(model, tools, system_prompt=SYSTEM)


        def run_agent(agent):
            state = agent.invoke(
                {"messages": [{"role": "user", "content": PROMPT}]},
                config={"recursion_limit": 3 * TURNS},
            )
            return state["messages"][-1].text
    ''',
    "langgraph": r'''
        def construct():
            from langchain_anthropic import ChatAnthropic
            from langchain_core.messages import SystemMessage
            from langchain_core.tools import tool
            from langgraph.graph import START, MessagesState, StateGraph
            from langgraph.prebuilt import ToolNode, tools_condition
            from agent_airlock import Airlock
            from agent_airlock.integrations.langgraph_toolnode_compat import unwrap_toolnode_output

            policy = make_policy()

            @tool
            @Airlock(policy=policy)
            def get_order_status(order_id: str) -> str:
                """Look up the shipping status of an order."""
                return order_status_body(order_id)

            @tool
            @Airlock(policy=policy)
            def delete_order(order_id: str) -> str:
                """Delete an order permanently."""
                return delete_order_body(order_id)

            tools = [get_order_status, delete_order]
            llm = ChatAnthropic(model=MODEL, max_tokens=MAX_TOKENS).bind_tools(tools)
            tool_node = ToolNode(tools)

            def agent_node(state):
                return {"messages": [llm.invoke([SystemMessage(SYSTEM), *state["messages"]])]}

            def tools_node(state):
                return {"messages": unwrap_toolnode_output(tool_node.invoke(state))}

            graph = StateGraph(MessagesState)
            graph.add_node("agent", agent_node)
            graph.add_node("tools", tools_node)
            graph.add_edge(START, "agent")
            graph.add_conditional_edges("agent", tools_condition)
            graph.add_edge("tools", "agent")
            return graph.compile()


        def run_agent(graph):
            state = graph.invoke(
                {"messages": [{"role": "user", "content": PROMPT}]},
                config={"recursion_limit": 3 * TURNS},
            )
            return state["messages"][-1].text
    ''',
    "pydantic_ai": r'''
        def construct():
            from pydantic_ai import Agent
            from pydantic_ai.models.anthropic import AnthropicModel, AnthropicModelSettings
            from pydantic_ai.providers.anthropic import AnthropicProvider
            from agent_airlock.integrations.pydantic_ai import PydanticAIAdapter

            def get_order_status(order_id: str) -> str:
                """Look up the shipping status of an order."""
                return order_status_body(order_id)

            def delete_order(order_id: str) -> str:
                """Delete an order permanently."""
                return delete_order_body(order_id)

            model = AnthropicModel(MODEL, provider=AnthropicProvider())
            agent = Agent(
                model, instructions=SYSTEM, tools=[get_order_status, delete_order],
                model_settings=AnthropicModelSettings(max_tokens=MAX_TOKENS),
            )
            return PydanticAIAdapter().wrap_agent(agent, policy=make_policy())


        def run_agent(agent):
            from pydantic_ai.usage import UsageLimits

            return agent.run_sync(PROMPT, usage_limits=UsageLimits(request_limit=TURNS)).output
    ''',
    "openai_agents": r'''
        def construct():
            from agents import Agent, ModelSettings, function_tool, set_tracing_disabled
            from agents.extensions.models.litellm_model import LitellmModel
            from agent_airlock import Airlock

            set_tracing_disabled(True)
            litellm_model_note()
            policy = make_policy()

            @function_tool
            @Airlock(policy=policy)
            def get_order_status(order_id: str) -> str:
                """Look up the shipping status of an order."""
                return order_status_body(order_id)

            @function_tool
            @Airlock(policy=policy)
            def delete_order(order_id: str) -> str:
                """Delete an order permanently."""
                return delete_order_body(order_id)

            return Agent(
                name="orders", instructions=SYSTEM, model=LitellmModel(model=f"anthropic/{MODEL}"),
                model_settings=ModelSettings(max_tokens=MAX_TOKENS),
                tools=[get_order_status, delete_order],
            )


        def run_agent(agent):
            from agents import Runner

            return Runner.run_sync(agent, PROMPT, max_turns=TURNS).final_output
    ''',
    "crewai": r'''
        def construct():
            from crewai import LLM, Agent, Crew, Task
            from crewai.tools import tool
            from agent_airlock.integrations.crewai import CrewAIAdapter

            litellm_model_note()

            @tool("get_order_status")
            def get_order_status(order_id: str) -> str:
                """Look up the shipping status of an order."""
                return order_status_body(order_id)

            @tool("delete_order")
            def delete_order(order_id: str) -> str:
                """Delete an order permanently."""
                return delete_order_body(order_id)

            llm = LLM(model=f"anthropic/{MODEL}", is_litellm=True, max_tokens=MAX_TOKENS)
            note("crewai's LLM(is_litellm=True) still imports its native Anthropic provider for "
                 "an anthropic/claude-* id (ImportError without the anthropic package), so the "
                 "venv carries crewai[anthropic] although LiteLLM serves the calls")
            if not getattr(llm, "is_litellm", False):
                note(f"crewai built {type(llm).__name__}, not the LiteLLM path that was asked for")
            agent = Agent(
                role="Order desk agent", goal="Handle order requests exactly as asked.",
                backstory=SYSTEM, tools=[get_order_status, delete_order], llm=llm,
                max_iter=max(1, TURNS - 1), allow_delegation=False, verbose=False,
            )
            task = Task(description=PROMPT, expected_output="The word DONE.", agent=agent)
            crew = Crew(agents=[agent], tasks=[task], verbose=False)
            return CrewAIAdapter().wrap_crew(crew, policy=make_policy())


        def run_agent(crew):
            return str(crew.kickoff())
    ''',
    "smolagents": r'''
        def construct():
            from smolagents import LiteLLMModel, ToolCallingAgent, tool
            from agent_airlock.exceptions import AirlockError
            from agent_airlock.integrations.smolagents_wrapper import PolicyBundle, wrap_agent
            from agent_airlock.policy import PolicyViolation

            litellm_model_note()
            # smolagents answers through its own final_answer tool, which wrap_agent wraps too.
            policy = make_policy(FINAL_TOOL)
            note("the guard's policy also allows smolagents' own final_answer tool")

            @tool
            def get_order_status(order_id: str) -> str:
                """Look up the shipping status of an order.

                Args:
                    order_id: The order identifier, for example A-1001.
                """
                return order_status_body(order_id)

            @tool
            def delete_order(order_id: str) -> str:
                """Delete an order permanently.

                Args:
                    order_id: The order identifier, for example A-1001.
                """
                return delete_order_body(order_id)

            def airlock_policy_guard(tool_name, _args):
                try:
                    policy.check(tool_name)
                except PolicyViolation as exc:
                    GUARD_REFUSALS.append(tool_name)
                    raise AirlockError(f"AIRLOCK_BLOCK: {exc.message}") from exc

            model = LiteLLMModel(model_id=f"anthropic/{MODEL}", max_tokens=MAX_TOKENS)
            agent = ToolCallingAgent(
                tools=[get_order_status, delete_order], model=model,
                max_steps=max(1, TURNS - 1), instructions=SYSTEM,
            )
            bundle = PolicyBundle(bundle_id="airlock-smoke", guards=(airlock_policy_guard,))
            return wrap_agent(agent, bundle)


        def run_agent(agent):
            return str(agent.run(PROMPT))
    ''',
    "google_adk": r'''
        def construct():
            from google.adk.agents import LlmAgent
            from google.adk.models.lite_llm import LiteLlm
            from agent_airlock.integrations.google_adk import wrap_agent

            litellm_model_note()

            def get_order_status(order_id: str) -> str:
                """Look up the shipping status of an order."""
                return order_status_body(order_id)

            def delete_order(order_id: str) -> str:
                """Delete an order permanently."""
                return delete_order_body(order_id)

            agent = LlmAgent(
                name="orders", model=LiteLlm(model=f"anthropic/{MODEL}", max_tokens=MAX_TOKENS),
                instruction=SYSTEM, tools=[get_order_status, delete_order],
            )
            return wrap_agent(agent, policy=make_policy())


        def run_agent(agent):
            from google.adk.agents.run_config import RunConfig
            from google.adk.runners import InMemoryRunner
            from google.genai import types

            async def go():
                runner = InMemoryRunner(agent=agent, app_name="airlock_smoke")
                session = await runner.session_service.create_session(
                    app_name="airlock_smoke", user_id="smoke")
                final = None
                message = types.Content(role="user", parts=[types.Part(text=PROMPT)])
                async for event in runner.run_async(
                    user_id="smoke", session_id=session.id, new_message=message,
                    run_config=RunConfig(max_llm_calls=TURNS),
                ):
                    if event.is_final_response() and event.content and event.content.parts:
                        final = "".join(p.text or "" for p in event.content.parts)
                return final

            return asyncio.run(go())
    ''',
    "llamaindex": r'''
        def _llamaindex_workarounds():
            """llama-index-llms-anthropic predates the model: name what it lacks, then patch it."""
            from llama_index.llms.anthropic import utils

            if MODEL not in utils.CLAUDE_MODELS:
                note(f"llama-index-llms-anthropic does not know {MODEL}: its context-window "
                     "lookup raises ValueError")
                if WORKAROUNDS:
                    utils.CLAUDE_MODELS[MODEL] = 1_000_000
                    note(f"workaround: registered {MODEL} in llama_index.llms.anthropic.utils."
                         "CLAUDE_MODELS (no public setting)")
            if not any(name in MODEL for name in utils.ANTHROPIC_NO_TEMP_MODELS):
                from llama_index.core.constants import DEFAULT_TEMPERATURE
                from llama_index.llms.anthropic import base

                note(f"llama-index-llms-anthropic passes temperature={DEFAULT_TEMPERATURE} for "
                     f"{MODEL}: anthropic 1.x's messages.create has no temperature parameter "
                     "(TypeError before any request), and the model rejects any value but 1")
                if WORKAROUNDS:
                    patched = (*utils.ANTHROPIC_NO_TEMP_MODELS, MODEL)
                    utils.ANTHROPIC_NO_TEMP_MODELS = base.ANTHROPIC_NO_TEMP_MODELS = patched
                    note(f"workaround: added {MODEL} to ANTHROPIC_NO_TEMP_MODELS (utils and base) "
                         "so no temperature is passed (no public setting)")


        def construct():
            from llama_index.core.agent.workflow import FunctionAgent
            from llama_index.core.tools import FunctionTool
            from llama_index.llms.anthropic import Anthropic
            from agent_airlock import Airlock

            _llamaindex_workarounds()
            policy = make_policy()

            @Airlock(policy=policy)
            def get_order_status(order_id: str) -> str:
                """Look up the shipping status of an order."""
                return order_status_body(order_id)

            @Airlock(policy=policy)
            def delete_order(order_id: str) -> str:
                """Delete an order permanently."""
                return delete_order_body(order_id)

            tools = [FunctionTool.from_defaults(fn=get_order_status),
                     FunctionTool.from_defaults(fn=delete_order)]
            llm = Anthropic(model=MODEL, max_tokens=MAX_TOKENS)
            return FunctionAgent(tools=tools, llm=llm, system_prompt=SYSTEM)


        def run_agent(agent):
            async def go():
                return str(await agent.run(user_msg=PROMPT, max_iterations=TURNS))

            return asyncio.run(go())
    ''',
    "autogen": r'''
        def construct():
            from autogen_agentchat.agents import AssistantAgent
            from autogen_core.models import ModelFamily, ModelInfo
            from autogen_ext.models.anthropic import AnthropicChatCompletionClient
            from agent_airlock import Airlock

            policy = make_policy()

            @Airlock(policy=policy)
            def get_order_status(order_id: str) -> str:
                """Look up the shipping status of an order."""
                return order_status_body(order_id)

            @Airlock(policy=policy)
            def delete_order(order_id: str) -> str:
                """Delete an order permanently."""
                return delete_order_body(order_id)

            try:
                AnthropicChatCompletionClient(model=MODEL)
            except ValueError:
                note(f"autogen-ext does not know {MODEL}: model_info is required")
            note("autogen-ext[anthropic] imports tiktoken without declaring it; installed by hand")
            sdk = importlib.metadata.version("anthropic")
            note(f"autogen-ext always passes temperature (1.0 unless set); anthropic 1.x's "
                 f"messages.create has no such parameter (TypeError), so this venv "
                 f"{'pins anthropic<1 (workaround)' if sdk.startswith('0.') else 'cannot call'}: "
                 f"anthropic {sdk}")
            client = AnthropicChatCompletionClient(
                model=MODEL, max_tokens=MAX_TOKENS,
                model_info=ModelInfo(vision=False, function_calling=True, json_output=False,
                                     family=ModelFamily.UNKNOWN, structured_output=False),
            )
            return AssistantAgent(
                name="orders", model_client=client, tools=[get_order_status, delete_order],
                system_message=SYSTEM, max_tool_iterations=max(1, TURNS - 1),
            )


        def run_agent(agent):
            async def go():
                result = await agent.run(task=PROMPT)
                return str(result.messages[-1].content) if result.messages else None

            return asyncio.run(go())
    ''',
    "claude_agent_sdk": r'''
        def construct():
            from claude_agent_sdk import create_sdk_mcp_server, tool
            from agent_airlock.integrations.anthropic_claude_agent_sdk import wrap_tools

            @tool(ALLOWED, "Look up the shipping status of an order.", {"order_id": str})
            async def get_order_status(args):
                return {"content": [{"type": "text", "text": order_status_body(args["order_id"])}]}

            @tool(DENIED, "Delete an order permanently.", {"order_id": str})
            async def delete_order(args):
                return {"content": [{"type": "text", "text": delete_order_body(args["order_id"])}]}

            tools = wrap_tools([get_order_status, delete_order], policy=make_policy())
            return create_sdk_mcp_server("orders", tools=tools)


        def _sdk_options(server, scratch):
            from claude_agent_sdk import ClaudeAgentOptions

            # Outside the checkout: the CLI writes a cwd's git context into its prompt.
            config_dir = os.path.join(scratch, "config")
            cwd = os.path.join(scratch, "cwd")
            os.makedirs(config_dir, exist_ok=True)
            os.makedirs(cwd, exist_ok=True)
            env = {"CLAUDE_CONFIG_DIR": config_dir, "CLAUDE_CODE_MAX_OUTPUT_TOKENS": str(MAX_TOKENS)}
            if MOCK_URL:
                env["ANTHROPIC_BASE_URL"] = MOCK_URL
            return ClaudeAgentOptions(
                model=MODEL, tools=[], mcp_servers={"orders": server}, strict_mcp_config=True,
                allowed_tools=[f"mcp__orders__{ALLOWED}", f"mcp__orders__{DENIED}"],
                setting_sources=[], system_prompt=SYSTEM, max_turns=TURNS,
                permission_mode="dontAsk", cwd=cwd, env=env,
                max_budget_usd=BUDGET_USD if MODE == "run" else None,
            )


        def _sdk_record(message, state):
            from claude_agent_sdk import (
                AssistantMessage, ResultMessage, SystemMessage, ToolResultBlock, ToolUseBlock,
                UserMessage,
            )

            if isinstance(message, SystemMessage) and message.subtype == "init":
                state["api_key_source"] = message.data.get("apiKeySource")
            elif isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, ToolUseBlock):
                        state["tool_ids"][block.id] = base_tool_name(block.name)
                        RECORDER.tool_uses.append(base_tool_name(block.name))
                if message.message_id and message.usage:
                    state["usage"][message.message_id] = (message.model, message.usage)
            elif isinstance(message, UserMessage) and isinstance(message.content, list):
                for block in message.content:
                    if not isinstance(block, ToolResultBlock):
                        continue
                    if state["tool_ids"].get(block.tool_use_id) != DENIED:
                        continue
                    content = block.content
                    text = content if isinstance(content, str) else json.dumps(content)
                    state["delivery"] = {"is_error": bool(block.is_error),
                                         "airlock_text": "AIRLOCK" in (text or "").upper()}
            elif isinstance(message, ResultMessage):
                state["result"] = message


        def _cli_usage(result):
            """Final per-model usage from the ResultMessage.

            AssistantMessage.usage is the message_start snapshot (output_tokens 1 on the
            scripted stream), so only the ResultMessage totals are fit for the ledger. The
            per-model totals do not say which cache TTL a write used, so writes are booked
            as 1-hour ones, the dearer rate: the ledger may overstate, never understate.
            """
            per_model = {}
            for model, usage in (result.model_usage or {}).items():
                writes = int(usage.get("cacheCreationInputTokens", 0) or 0)
                per_model[model] = {
                    "input_tokens": usage.get("inputTokens", 0),
                    "output_tokens": usage.get("outputTokens", 0),
                    "cache_read_input_tokens": usage.get("cacheReadInputTokens", 0),
                    "cache_creation_input_tokens": writes,
                    "cache_creation": {"ephemeral_5m_input_tokens": 0,
                                       "ephemeral_1h_input_tokens": writes},
                }
            if not per_model and result.usage:
                per_model[MODEL] = dict(result.usage)
            return per_model


        def _totals(usages):
            return (sum(int(u.get("input_tokens") or 0) for u in usages),
                    sum(int(u.get("output_tokens") or 0) for u in usages))


        def _sdk_crosscheck(state, per_model):
            """Mock mode: the CLI's own usage report against what crossed the loopback wire."""
            wire = _totals([c["usage"] for c in RECORDER.calls if c.get("usage")])
            reported = _totals(per_model.values())
            snapshot = _totals([u for _, u in state["usage"].values()])
            RECORDER.sdk_usage = [{"model": m, "usage": u} for m, u in per_model.items()]
            if reported != wire:
                note(f"CLI-reported usage (in, out) {reported} differs from the wire {wire}")
            if snapshot[1] != wire[1]:
                note("claude-agent-sdk AssistantMessage.usage carries the message_start "
                     f"snapshot (output_tokens {snapshot[1]} vs {wire[1]} on the wire); the "
                     "ResultMessage totals are what the ledger prices")


        def _sdk_settle(state):
            result = state.get("result")
            source = state.get("api_key_source")
            if source is not None:
                note(f"Claude Code CLI apiKeySource: {source}")
            per_model = _cli_usage(result) if result is not None else {}
            if MODE != "run":
                _sdk_crosscheck(state, per_model)
            elif result is None:
                RECORDER.add_unobserved("cli", TURNS)
            else:
                for model, usage in per_model.items():
                    calls = len(state["usage"]) if model == MODEL else 1
                    RECORDER.add_external(model, usage, "cli", represents=max(calls, 1))
            if state.get("delivery") and not RECORDER.deliveries:
                RECORDER.deliveries["sdk"] = state["delivery"]
            if result is not None and result.total_cost_usd is not None:
                note(f"CLI-reported cost ${result.total_cost_usd:.5f} over {result.num_turns} turn(s)")


        def run_agent(server):
            import shutil
            import tempfile

            from claude_agent_sdk import ClaudeSDKClient

            state = {"tool_ids": {}, "usage": {}, "delivery": None, "result": None}
            scratch = tempfile.mkdtemp(prefix="airlock-smoke-claude-")

            async def go():
                async with ClaudeSDKClient(options=_sdk_options(server, scratch)) as client:
                    await client.query(PROMPT)
                    async for message in client.receive_response():
                        _sdk_record(message, state)
                        source = state.get("api_key_source")
                        if MODE == "run" and source not in (None, "ANTHROPIC_API_KEY"):
                            # Fail closed: only the env key may pay for this run.
                            raise RuntimeError(f"the CLI chose credential {source!r}; stopping")
                result = state.get("result")
                return result.result if result is not None else None

            try:
                return asyncio.run(go())
            finally:
                _sdk_settle(state)
                shutil.rmtree(scratch, ignore_errors=True)
    ''',
}


if __name__ == "__main__":
    sys.exit(main())
