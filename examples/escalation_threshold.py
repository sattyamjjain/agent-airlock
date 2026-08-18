"""Transfers under $500 proceed; over $500 ask a human.

Run it:

    python examples/escalation_threshold.py

Offline and deterministic — no network, no API key, no real approver. The approver is a
stub that returns a preset verdict, so the output is the same on every machine.

Why this example exists
-----------------------
The v0.8.74 changelog names this exact sentence as the thing airlock previously could not
express. Before that release ``SecurityPolicy`` had two outcomes and neither was a value:
:meth:`SecurityPolicy.check` returns ``None`` to allow and raises ``PolicyViolation`` to
deny. "Ask a human" had nowhere to go, even though ``agent_airlock.oversight`` had shipped
a working approval primitive since v0.8.4.

It takes two features together, which is the point of showing them in one file:

1. **Dynamic policy resolution.** ``escalate_tools`` matches on the *tool name*, but the
   rule here depends on an *argument value*. So the policy is a callable: it reads the
   pending amount off the request context and returns a different policy above and below
   the threshold. The decision is a property of the call, not of the function.
2. **The third verdict.** Over the threshold, the resolved policy raises
   ``PolicyEscalation`` — a subclass of ``PolicyViolation``, which is what makes the
   fail-closed behaviour in scenario 4 structural rather than a runtime check.

Four scenarios run below, and scenario 4 is the one that matters most.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agent_airlock import Airlock, AirlockContext, SecurityPolicy
from agent_airlock.oversight import OversightRequest, OversightResponse, OversightVerdict

#: Anything at or below this proceeds untouched. Above it needs a human.
THRESHOLD_USD = 500


@dataclass
class TransferRequest:
    """What the harness knows about the pending call.

    ``session_id`` / ``agent_id`` are the attribute names airlock's ``ContextExtractor``
    already looks for, so this object doubles as the run identity.
    """

    amount_usd: int
    session_id: str = "session-demo"
    agent_id: str = "payments-agent"


@dataclass
class RunContext:
    """A ``RunContextWrapper``-alike. airlock reads the inner object through ``.context``."""

    context: TransferRequest


@dataclass
class StubApprover:
    """Stands in for Slack, PagerDuty, or a CLI prompt.

    A real approver blocks on a human. This one answers instantly with a preset verdict so
    the example is deterministic, and records what it was asked so the output can show that
    the human actually saw the reason and the rule.
    """

    verdict: OversightVerdict
    seen: list[OversightRequest] = field(default_factory=list)

    def __call__(self, request: OversightRequest) -> OversightResponse:
        self.seen.append(request)
        return OversightResponse(
            # Echoing request_id is part of the protocol: an approver that answers a
            # different request has not answered this one, and airlock blocks on a mismatch.
            request_id=request.request_id,
            verdict=self.verdict,
            detail=f"stub approver decided {self.verdict.value}",
            approver="finance-oncall@example.com",
        )


def build_policy_resolver(approver: StubApprover | None) -> object:
    """Return a policy *callable* — the amount decides which policy applies.

    Args:
        approver: The operator-supplied approval transport, or ``None`` to demonstrate
            the deny-by-default path.

    Returns:
        A resolver suitable for ``@Airlock(policy=...)``.
    """

    def resolve(ctx: AirlockContext[RunContext]) -> SecurityPolicy:
        wrapper = ctx.user_context
        amount = wrapper.context.amount_usd if wrapper else 0

        if amount <= THRESHOLD_USD:
            # Under the line: an ordinary allow. Nothing to escalate.
            return SecurityPolicy(allowed_tools=["transfer_funds"])

        return SecurityPolicy(
            allowed_tools=["transfer_funds"],
            escalate_tools={
                "transfer_funds": (f"${amount:,} is over the ${THRESHOLD_USD:,} auto-approve limit")
            },
            approver=approver,
            escalation_channel="finance",
        )

    return resolve


def make_tool(approver: StubApprover | None):
    """Build the airlocked tool against one approver configuration."""

    @Airlock(policy=build_policy_resolver(approver))
    def transfer_funds(request: RunContext, amount_usd: int) -> str:
        # Reached only when the policy allowed the call, or a human granted it.
        return f"TRANSFERRED ${amount_usd:,}"

    return transfer_funds


def _run(label: str, amount: int, approver: StubApprover | None) -> None:
    tool = make_tool(approver)
    request = RunContext(context=TransferRequest(amount_usd=amount))
    result = tool(request, amount_usd=amount)

    print(f"\n{label}")
    print(f"  amount:   ${amount:,}")
    if isinstance(result, dict):
        # A blocked call returns the structured AirlockResponse rather than the value.
        print(f"  verdict:  BLOCKED ({result['block_reason']})")
        print(f"  why:      {result['error']}")
    else:
        print("  verdict:  ALLOWED")
        print(f"  result:   {result}")
    if approver is not None and approver.seen:
        asked = approver.seen[-1]
        print(f"  human saw: rule={asked.args['escalation_rule']!r}")
        print(f"             reason={asked.args['escalation_reason']!r}")


def main() -> None:
    print("=" * 78)
    print(f"Escalation threshold demo — auto-approve at or below ${THRESHOLD_USD:,}")
    print("=" * 78)

    _run(
        "1. Under the threshold — proceeds, no human involved",
        amount=250,
        approver=StubApprover(verdict=OversightVerdict.GRANT),
    )

    _run(
        "2. Over the threshold, human GRANTS — proceeds after approval",
        amount=5_000,
        approver=StubApprover(verdict=OversightVerdict.GRANT),
    )

    _run(
        "3. Over the threshold, human DENIES — blocked",
        amount=5_000,
        approver=StubApprover(verdict=OversightVerdict.DENY),
    )

    _run(
        "4. Over the threshold, NO approver registered — blocked, deny-by-default",
        amount=5_000,
        approver=None,
    )

    print(
        "\n"
        + "-" * 78
        + "\nScenario 4 is the one that matters. A policy that escalates with nothing to\n"
        "escalate to must block, never pass. PolicyEscalation subclasses PolicyViolation,\n"
        "so every call site that predates the third verdict already refuses it — the\n"
        "fail-closed behaviour is enforced by the type lattice, not by a runtime branch\n"
        "someone could forget to write.\n"
    )


if __name__ == "__main__":
    main()
