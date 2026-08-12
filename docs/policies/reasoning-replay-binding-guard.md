# Reasoning-block replay binding guard (v0.8.70+, arXiv:2605.27157 anchor)

`agent_airlock.mcp_spec.reasoning_replay_guard.ReasoningReplayGuard` binds a
provider-returned **opaque reasoning block** to the session that minted it and
refuses cross-context replay.

## Why

This repo's stated position is **behaviour over reasoning-trust**:
`action_contradiction_gate.py` and `sequence_guard.py` both refuse to trust a
model's *stated* reasoning, citing [arXiv:2605.27157][paper]. That position is
right and this guard does not change it.

The gap is different. An encrypted / opaque reasoning block (a redacted or
signed thinking block) arrives as an opaque string, is passed **back** on the
next turn to continue the thought, and nothing checks that the block belongs to
this session. A block minted in one session — or by a different model — that is
replayed into another is accepted today. That is a provenance failure, not a
reasoning-content failure.

The guard never parses, decodes, or interprets the block (consistent with "don't
trust reasoning" — it never reads what the block *says*). It **binds** it:

- `bind(payload, *, session_id, model, lease)` — on first sight, record a
  SHA-256 of the opaque payload against the current session / model / lease. The
  first binding wins, so a mint cannot be laundered by re-minting under a new
  context.
- `check_replay(payload, *, session_id, model, lease)` — on replay, **refuse**
  when the binding does not match (`REFUSE_SESSION_MISMATCH` /
  `REFUSE_MODEL_MISMATCH` / `REFUSE_LEASE_MISMATCH`), and treat an **absent**
  binding as *untrusted* (`REFUSE_UNBOUND`) rather than trusted. Deny-by-default.

| Verdict | Meaning |
|---|---|
| `BOUND_FIRST_SEEN` | Recorded on first sight (allowed). |
| `REPLAY_MATCH` | Replay matches its binding (allowed). |
| `REFUSE_SESSION_MISMATCH` | Bound to a different session. |
| `REFUSE_MODEL_MISMATCH` | Bound to a different model. |
| `REFUSE_LEASE_MISMATCH` | Bound to a different lease. |
| `REFUSE_UNBOUND` | Never minted in this scope — untrusted. |

## Install

Core. No optional extra. The guard imports only `hashlib` / `dataclasses` /
`enum` from the stdlib — Pydantic-only core, zero-dep.

## Usage

```python
from agent_airlock import ReasoningReplayGuard

guard = ReasoningReplayGuard()
# When the provider returns an encrypted reasoning block this turn:
guard.bind(block, session_id="sess-A", model="claude-opus-5", lease="lease-1")
# When a reasoning block is passed back next turn:
decision = guard.check_replay(block, session_id="sess-A", model="claude-opus-5", lease="lease-1")
if not decision.allowed:
    ...  # refuse; decision.verdict says why
# or fail-closed:
guard.check_replay_or_raise(block, session_id="sess-A", model="claude-opus-5", lease="lease-1")
```

## Limit

This stops **replay** — a block minted elsewhere reused here. It does **nothing**
about a payload that was malicious the first time it arrived; binding proves
provenance-within-session, not benignity. Pair it with the guards that judge
*behaviour* (`action_contradiction_gate`, `sequence_guard`) — those remain the
answer to a block whose content is the problem.

[paper]: https://arxiv.org/abs/2605.27157
