"""``airlock explain`` CLI (v0.8.13+) — privilege right-sizing reporter.

Surfaces over-permissioning by diffing **granted** tool scopes (the
SecurityPolicy's allow-list) against **actually-called** tool scopes
(extracted from a run trace), per :class:`AgentIdentity`. Prints, per
agent, the granted-but-never-used set (the dead-weight scopes) and a
suggested tightened allow-list.

**This module is strictly read-only.** It never mutates a
:class:`SecurityPolicy`, never writes a policy file, and never installs
itself into the deny-by-default enforcement path. The output is
operator-facing observability, intended to be reviewed by a human
before any policy is tightened by hand.

Inputs
------
- ``--policy <file>``: a TOML or JSON file with SecurityPolicy fields
  (currently consumes ``allowed_tools`` and ``denied_tools`` — the
  scope-relevant subset).
- ``--trace <file>``: a run trace, in one of two formats:

  1. **Audit JSONL** (the native format emitted by
     :class:`agent_airlock.audit.AuditLogger`). One JSON object per
     line, each carrying ``tool_name`` + ``agent_id`` + ``blocked``.
     Lines starting with ``#`` are treated as header comments.
  2. **OTLP JSON** (a single JSON document with a top-level
     ``resourceSpans`` array — the format
     ``opentelemetry-exporter-otlp`` writes). Span ``name`` is taken
     as the tool name; ``attributes`` are searched for ``agent_id``
     and an optional ``airlock.blocked`` flag.

Auto-detected by inspecting the first non-blank bytes of the file.

Outputs
-------
``--format table`` (default) prints a human-readable per-agent report.
``--format json`` prints a machine-readable object with the same
content. ``--suggest-policy`` ADDS a proposed tightened
``SecurityPolicy`` block to stdout — never to the policy file.

Failure model
-------------
Errors return a non-zero exit code and a structured message on stderr;
no partial output to stdout. Empty traces (no admitted calls) are
*reported* (the unused set is the full allow-list) rather than treated
as an error — a fresh deployment with no recorded traffic genuinely
has zero used scopes.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:  # Python 3.11+ stdlib
    import tomllib as _tomllib
except ImportError:  # pragma: no cover - <3.11 fallback (tomli pulled via base deps)
    import tomli as _tomllib  # type: ignore[no-redef, unused-ignore]


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CallObservation:
    """One admitted tool call extracted from a trace."""

    tool_name: str
    agent_id: str


@dataclass
class AgentUsageReport:
    """Per-agent diff of granted vs used scopes."""

    agent_id: str
    granted_patterns: list[str]
    used_tools: list[str] = field(default_factory=list)
    used_patterns: list[str] = field(default_factory=list)
    unused_patterns: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "granted_patterns": list(self.granted_patterns),
            "used_tools": sorted(self.used_tools),
            "used_patterns": sorted(self.used_patterns),
            "unused_patterns": sorted(self.unused_patterns),
        }


# ---------------------------------------------------------------------------
# Trace loaders
# ---------------------------------------------------------------------------


def _peek_format(text: str) -> str:
    """Best-effort format detect: 'otlp' if the document is a JSON object
    whose first non-whitespace structure has a ``resourceSpans`` key;
    otherwise 'jsonl' (the native audit format)."""
    stripped = text.lstrip()
    if not stripped:
        return "jsonl"
    if stripped[0] == "{":
        # Try a real JSON load — cheap on small files; the alternative
        # is a regex that could misclassify a JSONL line that happens
        # to start with '{'.
        try:
            head = json.loads(stripped)
        except json.JSONDecodeError:
            return "jsonl"
        if isinstance(head, dict) and "resourceSpans" in head:
            return "otlp"
        # A single JSON object without resourceSpans is treated as
        # JSONL with a single record (one tool call). Fine.
        return "jsonl"
    return "jsonl"


def load_trace(path: Path) -> list[CallObservation]:
    """Parse a run trace, returning the list of admitted tool calls.

    Skipped:

    - Blank lines, lines starting with ``#`` (audit JSONL headers).
    - Records with ``blocked=True`` — the brief is "what was *actually
      called*"; a blocked call is by definition not a granted scope's
      exercise.
    - Records missing both ``tool_name`` and an OTLP span ``name``.
    """
    text = path.read_text(encoding="utf-8")
    fmt = _peek_format(text)
    if fmt == "otlp":
        return _load_otlp(text)
    return _load_jsonl(text)


def _load_jsonl(text: str) -> list[CallObservation]:
    out: list[CallObservation] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        if record.get("blocked") is True:
            continue
        tool_name = record.get("tool_name")
        agent_id = record.get("agent_id")
        if not isinstance(tool_name, str) or not tool_name:
            continue
        if not isinstance(agent_id, str) or not agent_id:
            agent_id = "__anonymous__"
        out.append(CallObservation(tool_name=tool_name, agent_id=agent_id))
    return out


def _load_otlp(text: str) -> list[CallObservation]:
    doc = json.loads(text)
    out: list[CallObservation] = []
    if not isinstance(doc, dict):
        return out
    for resource_span in doc.get("resourceSpans", []) or []:
        if not isinstance(resource_span, dict):
            continue
        # OTLP attribute lookup: resource-level attrs can carry agent_id
        # too — we read them as a default and let span-level override.
        res_attrs = _otlp_attrs(resource_span.get("resource", {}))
        for scope_span in resource_span.get("scopeSpans", []) or []:
            if not isinstance(scope_span, dict):
                continue
            for span in scope_span.get("spans", []) or []:
                if not isinstance(span, dict):
                    continue
                span_attrs = _otlp_attrs(span)
                # Honour an explicit blocked flag if the producer set
                # one; otherwise assume the call was admitted.
                blocked = span_attrs.get("airlock.blocked")
                if isinstance(blocked, bool) and blocked:
                    continue
                tool_name = span_attrs.get("tool.name") or span.get("name")
                if not isinstance(tool_name, str) or not tool_name:
                    continue
                agent_id = (
                    span_attrs.get("agent_id") or res_attrs.get("agent_id") or "__anonymous__"
                )
                if not isinstance(agent_id, str):
                    agent_id = "__anonymous__"
                out.append(CallObservation(tool_name=tool_name, agent_id=agent_id))
    return out


def _otlp_attrs(node: Mapping[str, Any]) -> dict[str, Any]:
    """Flatten an OTLP ``attributes`` array into a plain ``{key: value}``.

    OTLP encodes attributes as ``[{"key": "x", "value": {"stringValue": "v"}}]``;
    this helper turns that into ``{"x": "v"}``. Unsupported value
    shapes return ``None`` for that key.
    """
    out: dict[str, Any] = {}
    for entry in node.get("attributes", []) or []:
        if not isinstance(entry, dict):
            continue
        key = entry.get("key")
        if not isinstance(key, str):
            continue
        value = entry.get("value")
        if not isinstance(value, dict):
            out[key] = None
            continue
        # OTLP AnyValue union — accept the common shapes.
        if "stringValue" in value:
            out[key] = value["stringValue"]
        elif "boolValue" in value:
            out[key] = value["boolValue"]
        elif "intValue" in value:
            out[key] = int(value["intValue"])
        elif "doubleValue" in value:
            out[key] = float(value["doubleValue"])
        else:
            out[key] = None
    return out


# ---------------------------------------------------------------------------
# Policy loader
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicySnapshot:
    """The scope-relevant slice of a SecurityPolicy.

    We deliberately do NOT load the full :class:`SecurityPolicy` here —
    the CLI is read-only and only needs the allow / deny lists. Pulling
    the full policy (with capability gating, rate limits, etc.) would
    couple this command to every field that ever ships and complicate
    the file-format contract.
    """

    allowed_tools: tuple[str, ...]
    denied_tools: tuple[str, ...]


def load_policy(path: Path) -> PolicySnapshot:
    """Load a ``SecurityPolicy`` snapshot from a TOML or JSON file.

    The loader looks for ``allowed_tools`` and ``denied_tools`` either
    at the document root OR under a ``[policy]`` / ``"policy"`` section
    (for files that bundle the policy alongside other config).
    """
    raw = path.read_bytes()
    if path.suffix.lower() in {".toml"}:
        doc = _tomllib.loads(raw.decode("utf-8"))
    else:
        doc = json.loads(raw.decode("utf-8"))
    if not isinstance(doc, dict):
        raise ValueError(f"policy file {path} did not parse to an object")
    section = doc
    if "policy" in doc and isinstance(doc["policy"], dict):
        section = doc["policy"]
    allowed = section.get("allowed_tools", []) or []
    denied = section.get("denied_tools", []) or []
    if not isinstance(allowed, list) or not all(isinstance(x, str) for x in allowed):
        raise ValueError("policy.allowed_tools must be a list[str]")
    if not isinstance(denied, list) or not all(isinstance(x, str) for x in denied):
        raise ValueError("policy.denied_tools must be a list[str]")
    return PolicySnapshot(
        allowed_tools=tuple(allowed),
        denied_tools=tuple(denied),
    )


# ---------------------------------------------------------------------------
# Diff algorithm
# ---------------------------------------------------------------------------


def diff_granted_vs_used(
    policy: PolicySnapshot,
    observations: Iterable[CallObservation],
) -> list[AgentUsageReport]:
    """Compute the granted-vs-used scope diff, per agent.

    A granted pattern is "used" if at least one observed tool name
    matches it via :func:`fnmatch.fnmatch` (the same matcher
    :class:`SecurityPolicy` uses internally). A pattern with **zero**
    matches is "unused" and is reported as dead-weight.

    For agents that share a granted policy but have different observed
    sets, each agent gets its own per-agent unused set. This is the
    typical multi-agent case — one role grant, N agents using different
    subsets of it.

    Args:
        policy: The granted scopes.
        observations: All admitted tool calls in the trace.

    Returns:
        One :class:`AgentUsageReport` per ``agent_id`` observed. Agents
        that never made an admitted call still appear (with the full
        granted set as "unused") iff they show up in any observation
        record — agents absent from the trace entirely are not
        synthesised, since the CLI has no agent registry to enumerate
        them from.
    """
    by_agent: dict[str, set[str]] = {}
    for obs in observations:
        by_agent.setdefault(obs.agent_id, set()).add(obs.tool_name)

    granted_patterns = list(policy.allowed_tools)
    reports: list[AgentUsageReport] = []
    for agent_id, used_tools in sorted(by_agent.items()):
        used_patterns: list[str] = []
        unused_patterns: list[str] = []
        for pattern in granted_patterns:
            if any(fnmatch.fnmatch(tool, pattern) for tool in used_tools):
                used_patterns.append(pattern)
            else:
                unused_patterns.append(pattern)
        reports.append(
            AgentUsageReport(
                agent_id=agent_id,
                granted_patterns=list(granted_patterns),
                used_tools=sorted(used_tools),
                used_patterns=used_patterns,
                unused_patterns=unused_patterns,
            )
        )
    return reports


def suggest_tightened_policy(
    report: AgentUsageReport, denied_tools: tuple[str, ...]
) -> dict[str, list[str]]:
    """Return a *suggested* tightened policy payload for one agent.

    Heuristic: keep only the patterns that actually matched observed
    calls (``used_patterns``). The denied-list is forwarded unchanged
    — denials are policy intent, not usage data. The output is a
    plain dict so callers can serialise to TOML / JSON / whatever
    review surface they want.

    **This function never writes to disk** and never modifies the
    in-memory :class:`SecurityPolicy`.
    """
    return {
        "allowed_tools": list(report.used_patterns),
        "denied_tools": list(denied_tools),
    }


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------


def _format_table(reports: list[AgentUsageReport]) -> str:
    if not reports:
        return "(no agents observed in trace)\n"
    lines: list[str] = []
    for r in reports:
        lines.append(f"agent: {r.agent_id}")
        lines.append(f"  granted patterns ({len(r.granted_patterns)}):")
        for p in r.granted_patterns:
            mark = "✓" if p in r.used_patterns else "✗"
            lines.append(f"    {mark} {p}")
        lines.append(f"  used tools ({len(r.used_tools)}):")
        for t in r.used_tools:
            lines.append(f"      {t}")
        if r.unused_patterns:
            lines.append(f"  unused (dead-weight) patterns ({len(r.unused_patterns)}):")
            for p in r.unused_patterns:
                lines.append(f"      - {p}")
        else:
            lines.append("  unused (dead-weight) patterns: (none)")
        lines.append("")
    return "\n".join(lines)


def _format_json(reports: list[AgentUsageReport]) -> str:
    return json.dumps([r.to_dict() for r in reports], indent=2, sort_keys=True) + "\n"


def _format_suggested_policies(
    reports: list[AgentUsageReport], denied: tuple[str, ...], fmt: str
) -> str:
    """Render the per-agent suggested-tightened-policy block."""
    payload = {r.agent_id: suggest_tightened_policy(r, denied) for r in reports}
    if fmt == "json":
        return json.dumps({"suggested_policies": payload}, indent=2, sort_keys=True) + "\n"
    lines = ["", "# === Suggested tightened policies (REVIEW BEFORE ADOPTING) ===", ""]
    for agent_id, body in payload.items():
        lines.append(f"## agent: {agent_id}")
        lines.append("[policy]")
        lines.append("allowed_tools = [")
        for p in body["allowed_tools"]:
            lines.append(f"    {json.dumps(p)},")
        lines.append("]")
        lines.append("denied_tools = [")
        for p in body["denied_tools"]:
            lines.append(f"    {json.dumps(p)},")
        lines.append("]")
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="airlock-explain",
        description=(
            "Read-only privilege right-sizing reporter. Diffs granted "
            "vs actually-called tool scopes per agent and prints the "
            "dead-weight set. NEVER mutates or auto-applies any policy."
        ),
    )
    parser.add_argument(
        "--unused-scopes",
        action="store_true",
        help=(
            "Show granted scopes that were never matched by any observed "
            "tool call. Currently the only analysis mode — included as a "
            "flag so future analyses (e.g. --unused-roles) can be added "
            "without changing the entrypoint."
        ),
    )
    parser.add_argument(
        "--policy",
        type=Path,
        required=True,
        help="Path to a SecurityPolicy snapshot file (TOML or JSON).",
    )
    parser.add_argument(
        "--trace",
        type=Path,
        required=True,
        help=("Path to a run trace: audit JSONL (native) or OTLP JSON (auto-detected)."),
    )
    parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format. Default: table.",
    )
    parser.add_argument(
        "--suggest-policy",
        action="store_true",
        help=(
            "Also emit a proposed tightened SecurityPolicy to stdout. "
            "Never writes the policy file — review the suggestion by hand "
            "before adopting."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.unused_scopes:
        parser.error("at least one analysis mode required (e.g. --unused-scopes)")
        return 2  # argparse.error already exits, but keep mypy happy

    try:
        policy = load_policy(args.policy)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: cannot load policy {args.policy}: {exc}", file=sys.stderr)
        return 2

    try:
        observations = load_trace(args.trace)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot load trace {args.trace}: {exc}", file=sys.stderr)
        return 2

    reports = diff_granted_vs_used(policy, observations)

    if args.format == "json":
        print(_format_json(reports), end="")
    else:
        print(_format_table(reports), end="")

    if args.suggest_policy:
        print(_format_suggested_policies(reports, policy.denied_tools, args.format), end="")

    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
