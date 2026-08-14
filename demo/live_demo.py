"""Agent-Airlock live demo — govern the action at the execution boundary.

Scenario: an AI agent read a poisoned web page (indirect prompt injection) and now
tries to wire money to an attacker. Airlock sits at the tool-call seam. Watch what it
lets through, what it blocks, and what it writes to the audit log — deterministically,
in-process, no model call, no keys.

Run:  python demo/live_demo.py
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import structlog

from agent_airlock import Airlock, AirlockConfig, SecurityPolicy, UnknownArgsMode

# Quiet structlog so the narrated output is clean. (Airlock still emits an
# `airlock_blocked` event per block; we show the structured return + audit log.)
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))

AUDIT = Path("demo/airlock_audit.jsonl")
AUDIT.unlink(missing_ok=True)

# Deny-by-default: the agent is authorized for exactly two tools, nothing else.
# Ghost/hallucinated arguments are BLOCKED, not silently stripped.
POLICY = SecurityPolicy(allowed_tools=["get_balance", "transfer_funds"], default_deny=True)
CONFIG = AirlockConfig(
    enable_audit_log=True,
    audit_log_path=AUDIT,
    unknown_args=UnknownArgsMode.BLOCK,
)


@Airlock(policy=POLICY, config=CONFIG)
def get_balance(account_id: str) -> dict:
    """Read a balance (authorized, read-only)."""
    return {"account_id": account_id, "balance": 4200}


@Airlock(policy=POLICY, config=CONFIG)
def transfer_funds(to: str, amount: int) -> dict:
    """Move money (authorized, but strictly typed + closed arg surface)."""
    return {"status": "transferred", "to": to, "amount": amount}


@Airlock(policy=POLICY, config=CONFIG)
def drain_account(to: str) -> dict:
    """A tool the injection WANTS to call. Not in the allow-list."""
    return {"status": "drained", "to": to}


def show(label: str, result: Any) -> None:
    blocked = isinstance(result, dict) and result.get("status") == "blocked"
    print(f"\n{'🛑 BLOCKED' if blocked else '✅ EXECUTED'}  {label}")
    if blocked:
        print(f"    reason   : {result['block_reason']}")
        print(f"    error    : {result['error']}")
        if result.get("fix_hints"):
            print(f"    fix_hint : {result['fix_hints'][0]}")
    else:
        print(f"    result   : {result}")


def main() -> None:
    print("=" * 68)
    print("  Agent-Airlock — the agent was prompt-injected. Watch the seam.")
    print("=" * 68)

    # 1. The legitimate call the agent is supposed to make.
    show("get_balance(account_id='acct_1')  — authorized read", get_balance(account_id="acct_1"))

    # 2. LLM type confusion: sends amount as a string "9999".
    show(
        "transfer_funds(to='acct_2', amount='9999')  — string, not int",
        transfer_funds(to="acct_2", amount="9999"),  # type: ignore[arg-type]
    )

    # 3. The injected page smuggled in a bypass flag `confirm_override=True`.
    show(
        "transfer_funds(to='0xATTACKER', amount=9999, confirm_override=True)  — ghost arg",
        transfer_funds(to="0xATTACKER", amount=9999, confirm_override=True),  # type: ignore[call-arg]
    )

    # 4. The injection tells the agent to pivot to an unauthorized tool.
    show("drain_account(to='0xATTACKER')  — tool not in allow-list", drain_account(to="0xATTACKER"))

    # 5. The audit trail — every decision is on disk.
    print("\n" + "=" * 68)
    print(f"  Audit log ({AUDIT}) — every call recorded:")
    print("=" * 68)
    for line in AUDIT.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        rec = json.loads(line)
        outcome = "BLOCKED" if rec.get("blocked") else "allowed"
        detail = f"  ({rec['block_reason']})" if rec.get("blocked") else ""
        print(f"  {outcome:8}  {rec['tool_name']}{detail}")

    print("\nGovern the action at the execution boundary. Deterministic. In-process. Zero-dep.")


if __name__ == "__main__":
    main()
