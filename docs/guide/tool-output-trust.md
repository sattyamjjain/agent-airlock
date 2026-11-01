# Tool output trust

`ToolOutputTrustGuard` reads what a tool returns before it reaches the model, and flags text
shaped like instructions: "ignore previous instructions", "run the following", a fenced
shell command, a JSON tool call hidden in an error message. That is how a forged bug report
in an error tracker gets an agent to run an attacker's commands. Since 0.10.29 it can run on
every `@Airlock` result, and you choose what a flag does.

```python
from agent_airlock import Airlock, AirlockConfig
from agent_airlock.tool_output_trust_guard import ToolOutputTrustGuard

config = AirlockConfig(output_trust_guard=ToolOutputTrustGuard(on_flag="abort"))


@Airlock(config=config)
def fetch_issue(issue_id: str) -> str:
    ...
```

## What a flag does

| `on_flag` | A flagged output |
| --- | --- |
| `"envelope"` (the default) | is returned inside an untrusted-data envelope that tells the model to read it as data |
| `"typed_error"` | is refused as `output_untrusted`, with the guard's `fix_hints` |
| `"abort"` | is refused, and the run is halted: this call and every later one in it are refused as `run_halted` |

None of them puts a placeholder where the output was. A placeholder tells the agent
nothing, so it calls the same tool again, in a loop (google/adk-python#6966). An envelope
gives it the output to read; a refusal says what happened and that retrying returns the
same thing. `typed_error` leaves the next step to the agent; `abort` stops the run however
the agent reacts, and only the host can start a new one.

`abort` halts the run the call belongs to (see [Halting a run, and loops](run-guard.md)). A
call outside any run is still refused, but there is no run to halt.

## On the call path

The guard runs after masking (`sanitize_output`), so it reads, and envelopes, the masked
text. Every result is checked, a string, a mapping or list by its values, and any other
object, a pydantic model or a dataclass, as the text it would reach the model as. A
streamed result is checked value by value as it is produced, and a flagged value under
`typed_error` or `abort` raises `ToolOutputTrustError` into the stream. A container that
holds a stream keeps its shape: its other values are checked, and each value the stream
produces gets the envelope itself. `None` has nothing to check.

In envelope mode the guard's own settings decide what is enveloped. By default every result
is, flagged or not, and comes back as text. With `envelope_only_when_flagged=True` an
output with no flag is returned as it was, and with `envelope=False` nothing is enveloped.

## Outside `@Airlock`

`guard.process(output)` returns `(safe_output, decision)` and raises
`ToolOutputTrustError` when `on_flag` says to refuse; the error's `aborted` says whether the
run was halted too. `process(output, raise_on_flag=True)` makes an envelope guard raise as
`typed_error` would, as it did before 0.10.29. Pass `context=` to choose the run `abort`
halts; the context set around the call is used otherwise.
