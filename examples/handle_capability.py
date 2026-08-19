"""A handle in the argument stream is a bearer capability, so check it like one.

Run it:

    python examples/handle_capability.py

Offline and deterministic — no network, no API key, no server. The handles are minted by an
in-process ledger and the clock is injected, so the output is the same on every machine.

Why this example exists
-----------------------
MCP **2026-07-28** removed the protocol-level session (SEP-2575). A server that needs
cross-call state now mints a handle from one tool and the model passes it back as an
*argument* to another (SEP-2567). That moves a value which grants continuity out of trusted
transport state and into the same channel as attacker-influenced tool inputs.

Everything below is a well-typed ``str``. A validator that only checks the type accepts all
five calls. Four of them should not happen:

1. **Never issued** — a handle the model read out of a transcript or another tenant's output
   rather than one that was issued to this run.
2. **Wrong issuer** — a real handle from this run, minted by a different tool. A
   confused-deputy hand-off, even inside the right scope.
3. **Wrong scope** — a real handle from the right tool, minted for a different workspace.
   This is the cross-tenant one.
4. **Expired** — a handle that was valid, replayed after its TTL.

The scenario is the smallest thing that shows all of them: two tools that mint (one for each
of two workspaces, plus an unrelated exporter), and one tool that consumes.

Scenario 6 is the one that matters, and it is not in the list above.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from agent_airlock import Airlock, HandleField, HandleLedger, handle_run, issue_handle

#: The tool permitted to mint session handles for the checkpoint store.
CHECKPOINT_ISSUER = "mnemo.checkpoint"

#: An unrelated tool in the same run that also hands back opaque strings.
EXPORT_ISSUER = "mnemo.export"

#: The workspace the reader below operates on. A handle for any other workspace is refused.
HOME_WORKSPACE = "workspace-acme"
OTHER_WORKSPACE = "workspace-globex"

#: A realistic session lifetime for the handles that are supposed to still be valid.
SESSION_TTL_SECONDS = 900.0

#: Scenario 5 needs a handle that genuinely expires while the example is running. Short
#: enough to be invisible, long enough not to race the minting call itself.
EXPIRING_TTL_SECONDS = 0.05


@dataclass
class Call:
    """One attempt to use a handle, and what should happen to it."""

    label: str
    handle: str
    expected: str
    """``allow`` or the ``block_reason`` the call should produce. Asserted in ``main``."""


@Airlock()
def open_session(workspace: str) -> str:
    """Mint a session handle for ``workspace`` and hand it to the model.

    This is the *only* legitimate source of a handle the reader below will accept. The
    ledger records who minted it, what for, and when.
    """
    return issue_handle(
        issuer=CHECKPOINT_ISSUER,
        scope=workspace,
        ttl_seconds=SESSION_TTL_SECONDS,
    )


@Airlock()
def start_export(workspace: str) -> str:
    """A different tool that also returns an opaque string. Same shape, different authority."""
    return issue_handle(issuer=EXPORT_ISSUER, scope=workspace)


@Airlock()
def read_checkpoint(
    session: HandleField(issuer=CHECKPOINT_ISSUER, scope=HOME_WORKSPACE),
    key: str = "latest",
) -> str:
    """Read from the checkpoint store.

    ``session`` is declared as a capability rather than a ``str``. The declaration is what
    makes it checkable at all — a handle smuggled in as an argument this tool never declared
    is stripped by ghost-argument validation before it reaches here.

    The body is reached only when the handle was issued in this run, by
    ``mnemo.checkpoint``, for ``workspace-acme``, and has not expired.
    """
    return f"CHECKPOINT[{key}] for {HOME_WORKSPACE}"


def _describe(result: object) -> tuple[str, str]:
    """Reduce an airlock result to ``(verdict, detail)`` for printing."""
    if isinstance(result, dict):
        return result.get("block_reason", "blocked"), str(result.get("fix_hints", [""])[0])
    return "allow", str(result)


def _run(call: Call) -> bool:
    """Execute one attempt, print it, and report whether it matched the expectation."""
    verdict, detail = _describe(read_checkpoint(session=call.handle, key="latest"))
    ok = verdict == call.expected

    print(f"\n{call.label}")
    print(f"  handle:   {call.handle[:9]}…")
    print(f"  verdict:  {verdict.upper()}")
    print(f"  detail:   {detail}")
    if not ok:
        print(f"  MISMATCH: expected {call.expected}")
    return ok


def build_calls(ledger: HandleLedger) -> list[Call]:
    """Mint the handles for every scenario against one run's ledger.

    Args:
        ledger: The run's issuance ledger. Most handles are minted through the tools, which
            is how a real server would do it; the expiring one is minted directly so its TTL
            can be set to something the example can outlive.

    Returns:
        The five attempts, in the order ``main`` prints them.
    """
    good = open_session(workspace=HOME_WORKSPACE)
    other_workspace = open_session(workspace=OTHER_WORKSPACE)
    other_tool = start_export(workspace=HOME_WORKSPACE)

    # Issued perfectly, with a TTL short enough to elapse inside this function. A real
    # session TTL is minutes; waiting that out would not make the demonstration any more
    # truthful, and this way the expiry is genuine rather than simulated.
    expired = ledger.issue(
        issuer=CHECKPOINT_ISSUER,
        scope=HOME_WORKSPACE,
        ttl_seconds=EXPIRING_TTL_SECONDS,
    )
    time.sleep(EXPIRING_TTL_SECONDS * 2)

    return [
        Call(
            "1. Issued here, right tool, right scope, still alive — proceeds",
            good,
            "allow",
        ),
        Call(
            "2. Never issued in this run — read out of a transcript",
            "ah_seen-in-a-log-somewhere",
            "handle_not_issued",
        ),
        Call(
            "3. Real handle, wrong issuer — the export tool's, not the checkpoint tool's",
            other_tool,
            "handle_wrong_issuer",
        ),
        Call(
            "4. Real handle, right tool, WRONG WORKSPACE — the cross-tenant one",
            other_workspace,
            "handle_wrong_scope",
        ),
        Call(
            "5. Real handle, everything right, but expired — a replay",
            expired,
            "handle_expired",
        ),
    ]


def main() -> int:
    """Run every scenario. Returns a process exit code, non-zero if any verdict was wrong."""
    print("=" * 78)
    print("Capability handles — MCP 2026-07-28 / SEP-2567")
    print(f"Reader accepts: issuer={CHECKPOINT_ISSUER!r} scope={HOME_WORKSPACE!r}")
    print("=" * 78)

    results: list[bool] = []
    with handle_run("run-demo") as ledger:
        for call in build_calls(ledger):
            results.append(_run(call))

        print(f"\n  (ledger holds {len(ledger)} issued handles for this run)")

    # Scenario 6 runs OUTSIDE the `with`, so no ledger is bound at all.
    print("\n6. No ledger bound to the run at all — blocked, deny-by-default")
    verdict, _ = _describe(read_checkpoint(session="ah_anything-at-all"))
    print(f"  verdict:  {verdict.upper()}")
    results.append(verdict == "handle_not_issued")

    print(
        "\n"
        + "-" * 78
        + "\nScenario 6 is the one that matters. Every other line here shows a check working;\n"
        "that one shows what happens when the check was never wired up. A capability layer\n"
        "that passes calls through when nobody configured it is not a capability layer — the\n"
        "absence of the mechanism has to be as closed as its rejection. There is deliberately\n"
        "no 'observe only' mode: a knob that downgrades this to a warning is the thing the\n"
        "feature exists to remove.\n"
    )

    failed = results.count(False)
    if failed:
        print(f"FAILED: {failed} scenario(s) did not produce the expected verdict")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
