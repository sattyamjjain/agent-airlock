# CIMD trust-anchor pinning (MCP 2026-07-28)

The MCP `2026-07-28` revision replaces Dynamic Client Registration with **Client ID Metadata
Documents**. The `client_id` *is* an https URL, and the client's metadata document is served
from that URL — by the client.

That moves the trust anchor onto infrastructure you do not control.

| | Dynamic Client Registration | Client ID Metadata Document |
| --- | --- | --- |
| Who holds the record | the authorization server | the client |
| Can it change after approval | no | **yes, at any time** |
| What you approved | the record you issued | a document you fetched once |

Under DCR, "the client I approved" and "the client I am about to authorize" were the same
object. Under CIMD they are two fetches of a document someone else can rewrite in between. A
client that was benign at approval time can change its own `redirect_uris` later, and a naive
implementation re-reads the document on every grant and silently follows it.

## What the guard does

```python
from agent_airlock.mcp.cimd import CIMDGuard, SQLiteCIMDPinStore

guard = CIMDGuard(store=SQLiteCIMDPinStore("airlock.db"))

# One explicit, attributed approval creates the pin. There is no trust-on-first-use.
guard.approve("https://client.example.com/.well-known/oauth-client", approved_by="secops@example.com")

# Every later grant re-resolves and compares.
decision = guard.check("https://client.example.com/.well-known/oauth-client")
if not decision.allowed:
    print(decision.verdict)        # CIMDVerdict.DENY_DRIFT
    print(decision.reason)         # names exactly which fields changed
```

### (a) Fetch-and-pin

`approve()` is the only thing that creates or moves a pin. It records a SHA-256 of the
**canonicalised** document (sorted keys, tight separators — so reformatting is not drift, but
any semantic change is), the resolved origin, the approving identity, and every top-level
field for later diffing.

Point `SQLiteCIMDPinStore` at the same database file as `SQLiteCapabilityLedgerStore` and the
pins live alongside the lease ledger, so a restart restores both together.

### (b) Freshness check at grant time

`check()` re-resolves and compares. On mismatch it **denies by default** and names the fields:

```
client_id 'https://client.example.com/.well-known/oauth-client' metadata document changed
since it was pinned (a1b2c3d4e5f6a7b8 -> 9f8e7d6c5b4a3928): redirect_uris:
["https://client.example.com/callback"] -> ["https://attacker.example/steal"] — denied by
default; a rotation is never auto-accepted
```

A rotation is **never** auto-accepted. The only way forward is another explicit `approve()`,
which is the documented re-approval path and is logged with the approving identity.

### (c) Origin constraints

Refused before the body is trusted:

- a `client_id` whose scheme is not `https` → `DENY_SCHEME`;
- a host that is, or resolves to, a loopback / private / link-local / metadata address →
  `DENY_PRIVATE_ADDRESS` (reusing the SSRF guard's address classification, so the alternate
  IPv4 encodings it already handles are handled here too);
- any redirect hop that leaves the `client_id` origin → `DENY_CROSS_ORIGIN_REDIRECT`.

`allow_private_addresses=True` exists for a deliberate internal deployment. It is off by
default and the caller owns the consequences.

### (d) Revocation moves to *denied*, not *unknown*

A document that 404s (or 410s), or that comes back missing a required field, moves the client
to **revoked** and the state is persisted. It does not fall back to "never seen".

That distinction matters: "unknown" is the state a brand-new client is in, and a disappearing
document must not be able to launder itself back into it. A revoked client stays denied even
if the document returns, until someone explicitly re-approves it.

Required fields are `client_id`, `client_name`, `redirect_uris`, and the document's own
`client_id` must equal the URL it was served from.

## One decision point

The check is wired into the same grant path as the v0.8.70 capability-union boundary:

```python
engine = CapabilityCapEngine(config, cimd_guard=guard)

engine.grant_lease("agent-1", lease, client_id="https://client.example.com/.well-known/oauth-client")
# raises CIMDTrustAnchorError if the anchor moved — before the union is evaluated at all
```

A lease grant therefore has **one** decision point covering both "who is asking" (CIMD) and
"what would they then hold" (capability union), rather than two places to forget.

`UnionOverride` deliberately does **not** waive the CIMD check. The override is scoped to the
capability-union boundary; a client whose trust anchor moved is not a capability-shape
question, and letting a union override paper over it would defeat the pin.

## Limits

- It pins a document; it does not judge whether the document was trustworthy the first time.
  A malicious client that never rotates is not caught by this.
- Verification happens at **grant time**. A document that changes between a grant and a much
  later use is not re-checked by this guard.
- The freshness check costs one HTTP fetch per grant. Pass a caching `fetcher` if your grant
  rate makes that unacceptable — and note that caching reintroduces exactly the staleness
  window the pin exists to close.
