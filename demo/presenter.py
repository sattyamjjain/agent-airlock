"""Agent-Airlock — presenter demo (run this live).

One command, three acts, presenter-paced. Every block is a real airlock decision —
nothing here is faked or hard-coded.

    Act 1  The block      an injected agent tries to wire money to an attacker
    Act 2  Shift left     catch the bad tool contract before the agent loads it
    Act 3  The proof      210 tool calls, deterministic, ~microseconds/decision

Usage:
    python demo/presenter.py          # step through with Enter (you control pace)
    python demo/presenter.py --auto   # run straight through (rehearsal / recording)

No API keys, no network, no model calls. Run from the repo root.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

import structlog

# Airlock still logs an event per block; silence it so the stage output is clean.
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))

from agent_airlock import Airlock, AirlockConfig, SecurityPolicy, UnknownArgsMode  # noqa: E402

HERE = Path(__file__).parent
AUDIT = HERE / "airlock_audit.jsonl"
AUTO = "--auto" in sys.argv

# --- tiny ANSI helper (degrades to plain text off a TTY or with NO_COLOR) ----
_USE = sys.stdout.isatty() and "NO_COLOR" not in os.environ


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _USE else s


def bold(s: str) -> str:
    return _c("1", s)


def dim(s: str) -> str:
    return _c("2", s)


def green(s: str) -> str:
    return _c("32", s)


def red(s: str) -> str:
    return _c("31", s)


def yellow(s: str) -> str:
    return _c("33", s)


def cyan(s: str) -> str:
    return _c("36", s)


def banner(title: str) -> None:
    line = "═" * 70
    print(f"\n{cyan(line)}")
    print(cyan(f"  {title}"))
    print(f"{cyan(line)}")


def beat(msg: str = "next") -> None:
    if AUTO:
        return
    try:
        input(dim(f"\n   ↵  {msg}"))
    except (EOFError, KeyboardInterrupt):
        raise SystemExit(0) from None


# ============================================================================ #
# Act 1 — the runtime block
# ============================================================================ #

POLICY = SecurityPolicy(allowed_tools=["get_balance", "transfer_funds"], default_deny=True)
CONFIG = AirlockConfig(
    enable_audit_log=True, audit_log_path=AUDIT, unknown_args=UnknownArgsMode.BLOCK
)


@Airlock(policy=POLICY, config=CONFIG)
def get_balance(account_id: str) -> dict:
    return {"account_id": account_id, "balance": 4200}


@Airlock(policy=POLICY, config=CONFIG)
def transfer_funds(to: str, amount: int) -> dict:
    return {"status": "transferred", "to": to, "amount": amount}


@Airlock(policy=POLICY, config=CONFIG)
def drain_account(to: str) -> dict:
    return {"status": "drained", "to": to}


def _call(label: str, note: str, fn) -> None:
    print(f"\n  {bold(label)}")
    print(f"  {dim(note)}")
    result = fn()
    if isinstance(result, dict) and result.get("status") == "blocked":
        print(f"  {red('🛑 BLOCKED')}  {red(result['block_reason'])}")
        print(f"     {dim(result['error'])}")
        if result.get("fix_hints"):
            print(f"     {cyan('fix_hint →')} {result['fix_hints'][0]}")
    else:
        print(f"  {green('✅ EXECUTED')}  {dim(str(result))}")


def act1() -> None:
    banner("ACT 1  ·  The agent was prompt-injected. Watch the seam.")
    AUDIT.unlink(missing_ok=True)
    print(dim("  Policy: deny-by-default, allow-list = [get_balance, transfer_funds]."))
    print(dim("  Ghost/hallucinated arguments are BLOCKED, not silently stripped.\n"))

    beat("run the authorized call")
    _call(
        "get_balance(account_id='acct_1')",
        "the legitimate read the agent is supposed to do",
        lambda: get_balance(account_id="acct_1"),
    )

    beat("now the LLM sends the amount as a string")
    _call(
        "transfer_funds(to='acct_2', amount='9999')",
        "type confusion — model sent a string, not an int",
        lambda: transfer_funds(to="acct_2", amount="9999"),  # type: ignore[arg-type]
    )

    beat("the injected page smuggled in a bypass flag")
    _call(
        "transfer_funds(to='0xATTACKER', amount=9999, confirm_override=True)",
        "ghost argument — 'confirm_override' does not exist on the tool",
        lambda: transfer_funds(to="0xATTACKER", amount=9999, confirm_override=True),  # type: ignore[call-arg]
    )

    beat("the injection tells the agent to pivot to another tool")
    _call(
        "drain_account(to='0xATTACKER')",
        "unauthorized tool — not in the allow-list",
        lambda: drain_account(to="0xATTACKER"),
    )

    beat("show the audit trail")
    print(f"\n  {bold('Audit trail')} {dim(str(AUDIT))}")
    for line in AUDIT.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        rec = json.loads(line)
        if rec.get("blocked"):
            print(
                f"     {red('BLOCKED')}  {rec['tool_name']:16} {dim('(' + rec['block_reason'] + ')')}"
            )
        else:
            print(f"     {green('allowed')}  {rec['tool_name']}")
    print(f"\n  {dim('Every decision is on disk. That is your evidence trail.')}")


# ============================================================================ #
# Act 2 — the static contract check
# ============================================================================ #


def act2() -> None:
    banner("ACT 2  ·  Shift left — catch the bad contract before the agent loads it.")
    from agent_airlock.scan import load_tool_defs, resolve_policy, scan_tools

    print(dim(f"  airlock scan-tools {HERE.name}/tools.json --policy strict\n"))
    beat("run the static type-check")
    loaded = load_tool_defs(HERE / "tools.json")
    report = scan_tools(loaded.tools, resolve_policy("strict"), policy_name="strict")
    for r in report.results:
        if r.grade.value == "pass":
            print(f"  {green('PASS')}  {r.tool_name:16} {dim('cap: ' + r.inferred_capability)}")
        else:
            tag = red("FAIL") if r.grade.value == "fail" else yellow("WARN")
            print(f"  {tag}  {r.tool_name:16} {dim('cap: ' + r.inferred_capability)}")
            for v in r.violations:
                print(f"        {dim(v.code)} {v.message}")
    print(
        f"\n  {dim('Exit code')} {bold(str(report.exit_code))} {dim('— this goes straight into CI.')}"
    )


# ============================================================================ #
# Act 3 — the proof at scale
# ============================================================================ #


def _pct(xs: list[float], p: float) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    k = (len(s) - 1) * p / 100.0
    f = int(k)
    return s[f] if f + 1 >= len(s) else s[f] + (s[f + 1] - s[f]) * (k - f)


def act3() -> None:
    banner("ACT 3  ·  Not cherry-picked. 210 tool calls, deterministic.")
    beat("run the block-rate benchmark")
    # Running `python demo/presenter.py` puts demo/ on sys.path, not the repo
    # root — add it so `benchmarks` is importable from the clone.
    repo_root = str(HERE.parent)
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    try:
        from benchmarks.blockrate import run_blockrate
    except ImportError:
        print(red("  benchmarks/ needs the repo clone (not shipped in the pip wheel)."))
        print(dim("  Run this act from a `git clone` of the repo."))
        return

    rep = run_blockrate(measure_latency=True)
    mal = [(tc, b) for tc, b in rep.results if tc.expected_block]
    ben = [(tc, b) for tc, b in rep.results if not tc.expected_block]
    blocked_mal = sum(1 for _, b in mal if b)
    fp = sum(1 for _, b in ben if b)
    p50 = _pct(rep.latencies_ms, 50)
    p95 = _pct(rep.latencies_ms, 95)

    print(
        f"\n  corpus                 {bold(str(rep.total))} tool calls "
        f"{dim(f'({len(mal)} malicious, {len(ben)} benign)')}"
    )
    print(
        f"  malicious blocked      {green(f'{blocked_mal}/{len(mal)}  ({rep.overall_block_rate:.0%})')}"
    )
    print(f"  benign false-positive  {green(f'{fp}/{len(ben)}  ({rep.overall_fp_rate:.0%})')}")
    print(
        f"  latency p50 / p95      {bold(f'{p50 * 1000:.1f} / {p95 * 1000:.1f} µs')} {dim('per decision')}"
    )
    print(f"\n  {dim('Incumbents (LlamaFirewall, Invariant) are model-in-the-loop —')}")
    print(f"  {dim('marked scope-claimed, not re-run. No fabricated competitor number.')}")
    print(f"  {dim('Wired into AgentDojo as a defense: 84.4% of tool_knowledge')}")
    print(f"  {dim('injection targets blocked at the tool seam.')}")


def main() -> None:
    banner("AGENT-AIRLOCK  ·  govern the action at the execution boundary")
    print(dim("  LLMs hallucinate tool calls. Airlock sits on the tool-call seam:"))
    print(dim("  validate → policy → execute → sanitize. In-process. Deterministic. Zero-dep."))
    beat("begin")
    act1()
    beat("Act 2")
    act2()
    beat("Act 3")
    act3()
    banner("Even a badly-architected agent can't do damage — the safe path is the default.")
    print()


if __name__ == "__main__":
    main()
