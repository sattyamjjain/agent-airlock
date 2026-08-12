"""Capability-union boundary — two individually-approved leases denied at GRANT time.

The danger is the *combination*: a tool that can read files and a tool that can send data are
each fine on their own, but held together they are an exfiltration path (the "lethal trifecta"
capability-combination named at Black Hat USA 2026). agent-airlock evaluates the union at the
moment a lease is issued and denies it by default — naming the prior lease that combined to
trigger it — even though neither lease was independently refused.

Run it (no arguments, no network, no keys):

    python examples/capability_union_boundary.py

References:
    - CSA lethal-trifecta capability-security note:
      https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-lethal-trifecta-capability-securi/
    - Design: docs/interop/capability-union-boundary.md
"""

from __future__ import annotations

from agent_airlock.capability_caps import (
    CapabilityCapEngine,
    CapabilityCategory,
    CapabilityRulesConfig,
    CapabilityUnionDeniedError,
    Lease,
    UnionOverride,
)

FILESYSTEM_READ = frozenset({CapabilityCategory.FILESYSTEM_READ})
NETWORK_EGRESS = frozenset({CapabilityCategory.NETWORK_EGRESS})


def main() -> int:
    engine = CapabilityCapEngine(CapabilityRulesConfig())
    agent = "support-agent-7"

    # 1. Grant a filesystem-read lease. Individually permitted — no exception.
    engine.grant_lease(
        agent, Lease("lease-read", "read_ticket_files", FILESYSTEM_READ, granted_by="ops")
    )
    print("granted  lease-read   (read_ticket_files, filesystem-read)  -> allowed on its own")

    # 2. Grant a network-egress lease. Individually it would be fine too — but the UNION with
    #    the read lease is an exfiltration path, so it is denied at grant time.
    egress = Lease("lease-egress", "post_to_webhook", NETWORK_EGRESS, granted_by="ops")
    try:
        engine.grant_lease(agent, egress)
        print("granted  lease-egress (post_to_webhook)  -> allowed  (unexpected!)")
    except CapabilityUnionDeniedError as denied:
        prior = ", ".join(lease.lease_id for lease in denied.triggering_leases)
        print(f"DENIED   lease-egress (post_to_webhook)  -> union with prior lease [{prior}]")
        print(f"         reason: {denied}")

    # 3. The escape hatch: an explicit, logged override. Allowed, but recorded loudly (a
    #    structlog warning + a decision-log record) with the granting identity.
    override = UnionOverride(identity="secops@example.com", reason="approved incident export")
    engine.grant_lease(agent, egress, override=override)
    print(f"OVERRIDE lease-egress -> allowed by {override.identity} (recorded loudly)")

    # 4. A benign combination stays allowed: egress to an ALLOWLISTED destination is not a sink.
    engine2 = CapabilityCapEngine(CapabilityRulesConfig())
    engine2.grant_lease("agent-b", Lease("l-read", "read_config", FILESYSTEM_READ))
    ok = engine2.grant_lease(
        "agent-b",
        Lease("l-egress-ok", "call_internal_api", NETWORK_EGRESS, network_allowlisted=True),
    )
    print(
        f"granted  l-egress-ok (allowlisted egress)  -> allowed={ok.allowed}  (not an exfil sink)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
