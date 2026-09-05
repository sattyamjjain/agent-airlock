# Commerce adapters

## Read this first: what `integrations/adapters/` is not

`src/agent_airlock/integrations/adapters/` is **not** the framework integration
surface. It is a three-file sub-package serving one engine —
`AgentCommerceCaps` — and nothing else in the codebase imports it.

The framework integration surface is the layer above it,
`src/agent_airlock/integrations/*.py`, which carries a module per framework:
Anthropic (Messages, Claude Agent SDK, Managed Agents), OpenAI Guardrails,
LangChain, LangGraph ToolNode, CrewAI, PydanticAI, smolagents, Gemini and GPT
tool-shape adapters, Google Model Armor, and more, plus `agent_airlock/mcp.py`
for FastMCP. That surface is broad; counting the three files in `adapters/` as
"the integrations" undercounts it by an order of magnitude.

So the two words are doing different jobs in this repo:

| | `integrations/*.py` | `integrations/adapters/*.py` |
|---|---|---|
| Job | Bind `@Airlock` into a framework's tool-calling path | Normalize one vendor's payment payload |
| Consumer | The framework | `AgentCommerceCaps` only |
| Contract | Per-framework; no common interface | One `Protocol`, documented below |

The rest of this page is about the second column.

## The contract

Defined as a `Protocol` in
`src/agent_airlock/integrations/agent_commerce_caps.py`:

```python
class CommerceAdapter(Protocol):
    """The minimal adapter interface."""

    name: str

    def parse_request(self, raw: dict[str, Any]) -> tuple[str, str, int]:
        """Return (agent_id, counterparty, amount_cents)."""
        ...
```

That is the whole interface. All three shipped adapters —
`GenericWebhookAdapter`, `ProjectDealAdapter`, `StripeAgenticAdapter` — satisfy
it identically, and the shape they share goes slightly beyond the `Protocol`:

- a `@dataclass`, with
- `name: str` carrying a **default** (`"generic-webhook"`, `"project-deal"`,
  `"stripe-agentic"`), so the adapter is constructible with no arguments;
- `parse_request` as the only method, pure, no I/O, no validation, no raising;
- a module-level `__all__`, and a re-export from `adapters/__init__.py`.

The canonical triple is `(agent_id, counterparty, amount_cents)`. Amounts are
**integer minor units** — cents, not dollars, never a float.

### Coercion is the contract's real content

Each adapter's substance is where it digs the triple out of a vendor's shape,
and each tolerates the canonical key names as a fallback:

| Adapter | `agent_id` from | `counterparty` from | `amount_cents` from |
|---|---|---|---|
| `GenericWebhookAdapter` | `agent_id` | `counterparty` | `amount_cents` |
| `ProjectDealAdapter` | `buyer_agent_id` → `agent_id` | `seller_id` → `counterparty` | `amount.minor_units` (or a bare `amount`) |
| `StripeAgenticAdapter` | `metadata.airlock_agent_id` → `agent_id` | `customer` → `counterparty` | `amount` |

Missing fields coerce to `""` / `0` rather than raising. That is deliberate and
consistent across all three: the adapter is a shape mapper, and the engine is
what refuses a bad value (`check_and_debit` returns
`Decision(allowed=False, reason="negative debit refused")` for a negative
amount). Do not add validation to a new adapter — it would be the only one that
raises, and callers do not expect it.

## The divergence: `parse_request` is caller-side

The three adapters agree with each other. Where the contract is only half wired
is between the adapter and the engine:

```python
def register_adapter(self, adapter: CommerceAdapter) -> None:
    self.adapter_name = adapter.name
```

`register_adapter` consumes **only** `.name`, which is then stamped on each
ledger row for attribution. Nothing under `src/` ever calls `parse_request` —
verified by grep; the only mentions outside the adapter modules are the
`Protocol` declaration itself and the tests.

The practical consequence, and the thing most likely to trip up someone writing
a fourth adapter: **you call `parse_request` yourself.** Registering an adapter
does not put it in the request path. The flow is

```text
raw vendor payload
      │
      ▼   you call this
adapter.parse_request(raw) ──► (agent_id, counterparty, amount_cents)
      │
      ▼   you pass the triple
caps.check_and_debit(agent_id, counterparty, amount_cents) ──► Decision
```

not

```text
raw payload ──► caps.<something>(raw)   # does not exist
```

Whether that is a gap worth closing is a design question, not a documentation
one. It is recorded here because the `Protocol` reads as though the engine
consumes it, and it does not.

## Import paths

Only `AgentCommerceCaps` is exported from the package root. `Cap`, `CapsConfig`,
`Decision`, `LedgerStore`, `SQLiteLedgerStore` and `CommerceAdapter` are not in
`agent_airlock.__all__` and must be imported from the module:

```python
from agent_airlock import AgentCommerceCaps          # works
from agent_airlock.integrations.agent_commerce_caps import (  # everything else
    Cap,
    CapsConfig,
    CommerceAdapter,
    SQLiteLedgerStore,
)
```

The three shipped adapters come from `agent_airlock.integrations.adapters`.

## Writing a new adapter

1. Create `src/agent_airlock/integrations/adapters/<vendor>_adapter.py`.
2. Declare a `@dataclass` with `name: str = "<vendor-slug>"`. The slug lands in
   the ledger's `adapter` column, so make it stable and greppable.
3. Implement `parse_request(self, raw: dict[str, Any]) -> tuple[str, str, int]`.
   Coerce with `str(...)` / `int(...)`, fall back to the canonical key names,
   and default to `""` / `0` rather than raising.
4. Add `__all__ = ["<Vendor>Adapter"]`, then re-export from
   `adapters/__init__.py` and add it to that module's `__all__`.
5. Add a test to `tests/integrations/test_agent_commerce_caps.py` in the
   `TestAdapters` class, asserting the triple for a realistic payload.
6. Document the vendor payload shape in the class docstring as a
   `.. code-block:: json` sample, as the three shipped adapters do.

There is no registry to update and no entry point to declare. An adapter is
discovered by being imported.

## Worked example

A minimal fourth adapter, end to end. This runs as written:

```python
from dataclasses import dataclass
from typing import Any

from agent_airlock.integrations.agent_commerce_caps import (
    AgentCommerceCaps,
    Cap,
    CapsConfig,
    SQLiteLedgerStore,
)


@dataclass
class LemonSqueezyAdapter:
    """Lemon Squeezy order webhook:

    .. code-block:: json

        {
          "data": {
            "attributes": {
              "store_id": "vendor-x",
              "total": 4200,
              "custom_data": {"airlock_agent_id": "agent-buyer"}
            }
          }
        }
    """

    name: str = "lemon-squeezy"

    def parse_request(self, raw: dict[str, Any]) -> tuple[str, str, int]:
        attrs = (raw.get("data") or {}).get("attributes") or {}
        custom = attrs.get("custom_data") or {}
        return (
            str(custom.get("airlock_agent_id", "")),
            str(attrs.get("store_id", "")),
            int(attrs.get("total", 0)),
        )


caps = AgentCommerceCaps(
    config=CapsConfig(caps=(Cap(amount_cents=5_000, window="day", scope="counterparty"),)),
    store=SQLiteLedgerStore(),
)
adapter = LemonSqueezyAdapter()
caps.register_adapter(adapter)  # attribution only — see the divergence above

webhook = {
    "data": {
        "attributes": {
            "store_id": "vendor-x",
            "total": 4_200,
            "custom_data": {"airlock_agent_id": "agent-buyer"},
        }
    }
}

agent_id, counterparty, amount_cents = adapter.parse_request(webhook)

first = caps.check_and_debit(agent_id, counterparty, amount_cents)
print(first.allowed, first.debit_id)
# True 1

second = caps.check_and_debit(agent_id, counterparty, amount_cents)
print(second.allowed, second.reason)
# False cap breach: scope=counterparty window=day spent=42.00 + debit=42.00 > cap=50.00
```

`Cap.window` is one of `"minute" | "hour" | "day" | "week"`; `Cap.scope` is one
of `"agent" | "counterparty" | "global"`. `SQLiteLedgerStore()` defaults to
`:memory:` — pass a path for a ledger that survives the process.
