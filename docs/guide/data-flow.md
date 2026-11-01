# Sources and sinks

Since 0.10.29 a tool that acts outward can be gated once untrusted content has entered the
run, whether or not anything detected an injection in it. Until then nothing tagged a tool
as a source or a sink: `reauth_on_untrusted_reinvocation` gates only the re-invocation of
the tool whose output came back, and a `SequenceGuard` forbids transitions by tool name.

```python
from agent_airlock import Airlock, AirlockContext, DataFlowPolicy, SecurityPolicy, sink, source


@Airlock()
@source(trust="untrusted", kind="web")
def fetch(url: str) -> str:
    ...


@Airlock(policy=SecurityPolicy(data_flow_policy=DataFlowPolicy()))
@sink(kind="email")
def send_email(to: str, body: str) -> str:
    ...


with AirlockContext(agent_id="assistant") as run:
    fetch(url="https://example.com")  # the run is now tainted
    send_email(to="bob@example.com", body="...")  # refused: sink_after_untrusted_source
    run.clear_taint()  # after the host has reviewed the run
    send_email(to="bob@example.com", body="...")  # runs
```

## The tags

- `@source(trust="untrusted", kind="web")` marks a tool whose output enters the run from
  outside it: a page, an inbox, a file someone else wrote. `kind` names what it is, and
  shows up in the taint and in the output's provenance tag. `trust="trusted"` records the
  provenance without tainting.
- `@sink` or `@sink(kind="email")` marks a tool that acts outward: it sends, posts, pays
  or writes.

Both are read like `@requires`: above or below `@Airlock`, through decorators that keep
`__wrapped__`. A tool can be both. As a sink it is gated by what came before, and as a
source it taints the run after it.

## The run's taint

An untrusted source call that reaches execution taints its run when it returns or raises.
An error can carry the source's content too, so a raise counts. A source refused before it
ran, by its own policy or any gate, taints nothing.

The taint is the run's, not one output's, so output a later tool derives from the
untrusted content (a summary of the page) stays tainted. Tagging only the source's own
output misses that case.

It lives on the run's `AirlockContext`: the one a run wrapper carries, or the one set
around the calls with `with AirlockContext(...)`. `with_metadata()` clones share it. A
source taints its run whatever policy guards the source, because the gate is the sink's
policy's: the tools of one run are often guarded by different `@Airlock` configurations.

`run.taint_sources` lists the source calls that tainted the run, and `run.clear_taint()`
re-admits sinks. A source still running when the taint is cleared taints the run again
when it ends.

## The gate

`SecurityPolicy(data_flow_policy=DataFlowPolicy(...))` on a sink applies the gate at
step 2.4, after the policy check:

| Setting | Default | What it does |
| --- | --- | --- |
| `on_sink_after_source` | `"deny"` | `deny` refuses the call as `policy_violation` with `violation_type` `sink_after_untrusted_source`. `escalate` asks the policy's `approver` (rule `data_flow`) and, with none registered, refuses as `escalation_required` |
| `serialize_batch` | `False` | Makes a sink wait for the run's sources still running before it checks. See below |
| `batch_wait_seconds` | `30.0` | How long a sink waits under `serialize_batch`. A source still running when the wait ends counts as having tainted the run |

A sink called outside any run is refused as `sink_outside_run`, since there is no taint to
read. Make the agent's calls inside `with AirlockContext(agent_id=...)`, or pass an
`AirlockContext` as the run wrapper's `context`.

A thread started without the caller's context is outside the run: a bare
`threading.Thread` does not carry it, while `asyncio.to_thread` and a run wrapper do. So a
sink called in such a thread is refused, and a source called in one taints nothing the
run can see.

The decision record of a refused sink names `rule_id` `sink_after_untrusted_source` and
`layer` `2.4:data_flow`.

## Calls in one response

When a model asks for a source and a sink in one response, a framework may run them at once.

- **Without `serialize_batch`**, the sink is gated only by sources that completed before
  its check. A sink that runs alongside a source, or ahead of it, is admitted.
- **With `serialize_batch`**, a sink waits, up to `batch_wait_seconds`, for the run's
  untrusted sources still running, and is then gated if they tainted the run. On the async
  path it first yields to the event loop once, so the other calls `asyncio.gather` started
  with it reach the gate before it looks. That covers a sink placed ahead of its source in
  the batch.

What `serialize_batch` does not cover:

- On threads, a sink that reaches the gate before its source does is admitted: the source
  is not running yet, and nothing says it is coming.
- A source that waits on an approver at step 2 counts as running only once it is admitted.
- A sync sink called on the event loop's own thread blocks the loop while it waits, so an
  async source on that loop cannot finish. The sink waits out `batch_wait_seconds` and is
  then refused.

A sink admitted ahead of a source in the same response was written before the model saw
that source's output, so its arguments cannot carry it. What it can miss is state the
source writes while both run, such as a file the sink then attaches.

## Provenance on the output

A call's output carries a provenance tag when something untrusted touched it. It is on the
audit record (`provenance`) and, with `return_dict=True`, on the envelope's
`metadata["provenance"]`:

| Output | Tag |
| --- | --- |
| An untrusted source's own | `{"trust": "untrusted", "source": "web", "crossed_boundary": true}` |
| Any other, made in a tainted run | `{"trust": "untrusted", "source": "derived", "crossed_boundary": false, "derived_from": ["web"]}` |
| A trusted source's, in a clean run | `{"trust": "trusted", "source": "crm", "crossed_boundary": false}` |
| Anything else | no tag, and the record and envelope are unchanged |

## Prior art

CaMeL (Debenedetti et al., arXiv:2503.18813) separates a query's control flow from the data
it retrieves and checks capabilities on each value at the tool call. This gate is coarser:
one taint per run, and tags on tools rather than values. See [PRIOR_ART.md](https://github.com/sattyamjjain/agent-airlock/blob/main/PRIOR_ART.md).
