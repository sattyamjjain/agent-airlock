# High-value action deny-by-default preset (v0.5.2+)

`high_value_action_deny_by_default()` refuses any tool whose name
matches the high-value verb pattern unless the caller passes
`allow_high_value=True`.

## Motivating incident

On **2026-04-19**, the [Kelp DAO LayerZero bridge exploit](https://www.bloomberg.com/news/articles/2026-04-19/crypto-hack-worth-290-million-triggers-defi-contagion-shock)
moved **$292M** of wrapped-ether across 20 chains. The attacker used
stolen rsETH as collateral on Aave V3, leaving the protocol holding
**~$200M in bad debt**. Root cause was a cross-chain-message forgery
that reached an agent authorizing collateral moves. See also
[The Defiant — Aave price crash / KelpDAO exploit coverage](https://thedefiant.io/news/defi/aave-price-crash-kelpdao-exploit-whale-dump-rxi8o9).

Agent-airlock can't fix the bridge, but it can make it impossible for
an agent to authorize a high-value tool call silently.

## What the preset matches

```
(?i)(transfer|bridge|approve|withdraw|borrow|liquidate|swap|mint|burn)
```

Any tool whose name contains one of those verbs — `transfer_funds`,
`bridge_rsETH`, `approve_spender`, `withdraw_collateral`,
`borrow_against`, `liquidate_position`, `swap_usdc`, `mint_nft`,
`burn_token` — is classified high-value.

## Usage

```python
from agent_airlock import Airlock
from agent_airlock.policy_presets import (
    high_value_action_deny_by_default,
    HighValueActionBlocked,
)

hv = high_value_action_deny_by_default()

@Airlock()
def transfer_funds(to: str, amount: int) -> str:
    # Explicit opt-in — auditable at call site.
    hv["check"]("transfer_funds", allow_high_value=True)
    return do_transfer(to, amount)
```

Without `allow_high_value=True`, the `check` raises
`HighValueActionBlocked` (a subclass of `AirlockError`).

## What it does NOT do

- It doesn't look at arguments — a tool named `read_balance` that
  takes a `to_address` and a `value` isn't caught by name alone.
  Combine with `SecurityPolicy.rate_limits` and `CapabilityPolicy`
  for multi-layer defence.
- It doesn't verify cross-chain messages. That's the bridge
  protocol's job.
- It doesn't replace human sign-off for genuinely high-stakes
  actions. Pair with `MCPProxyGuard`'s consent hooks.

## Tests

See [`tests/test_policy_presets_high_value.py`](../../tests/test_policy_presets_high_value.py):
- Banned-prefix tool is blocked.
- Same tool passes when `allow_high_value=True`.
- Non-matching tool is unaffected.
