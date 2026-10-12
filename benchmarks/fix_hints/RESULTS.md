# fix_hints recovery: does a refusal help the model repair its own tool call?

When `@Airlock` refuses a tool call it does not raise. It returns
`AirlockResponse.to_dict()`: `block_reason`, an `error` line and `fix_hints` for the model
to retry against. This benchmark measures whether Claude models turn that refusal into a
corrected call, compared with the same refusal stripped of its hints, with the text the
Claude Agent SDK adapter sends, and (optionally) with a generic error.

Harness: [`benchmarks/fix_hints/`](https://github.com/sattyamjjain/agent-airlock/tree/main/benchmarks/fix_hints)
([how to run it](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/fix_hints/README.md)).

## Method

**Scenarios.** 500 synthetic tasks on fictional tools
([`catalogue.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/fix_hints/catalogue.py),
[`scenarios.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/fix_hints/scenarios.py)).
Each pairs a task with a malformed call to a tool whose parameters are typed with
`Annotated`, `Field` constraints and `Literal`. Every malformed call is self-checked at
generation: sent through a fresh `@Airlock` stub, it must draw the intended
`block_reason` and detail, its refusal must not carry a local path, and the call the task
actually asks for must pass the same stub. Candidates that fail are rejected and counted;
the count is in each round's block.

| Category | n | Malformed call | Intended refusal |
|---|---|---|---|
| Type mismatch: int, str, bool, float, list, dict | 6 x 15 | one argument of the wrong JSON type | `validation_error` |
| Missing argument | 60 | one required argument omitted | `validation_error` (`missing_argument`) |
| Ghost argument | 60 | one invented argument; stubs run `UnknownArgsMode.BLOCK` | `ghost_arguments` |
| Constraint: numeric bound, `max_length`, `Literal` | 3 x 30 | the value breaks the constraint | `validation_error` |
| Path outside the allowed root: root stated / not stated in the task | 2 x 30 | an absolute path elsewhere under `/airlock-bench/` | `path_violation` |
| Endpoint off the allowlist: host stated / not stated in the task | 2 x 30 | a look-alike host on the reserved `.example` names | `endpoint_blocked` |
| Multiple errors | 20 | one argument missing, another of the wrong type | `validation_error` (2 errors) |
| Control: tool not permitted | 40 | a `SecurityPolicy` allowlist or deny glob refuses the tool; half the scenarios also offer a permitted alternative | `policy_violation` |
| Control: capability denied | 20 | the tool's `@requires` capability is denied or not granted | `capability_denied` |

**Protocol.** One batchable turn per request: the task as the user turn, the malformed
call as a synthetic assistant `tool_use`, and the refusal as a `tool_result` with
`is_error: true`. The tools are offered with JSON schemas built from their signatures
(no `strict`). `max_tokens` 4,096, `thinking: {type: adaptive}`, `output_config.effort`
pinned to each model's API default (Haiku 5.5 and Opus 5.5 medium, Sonnet 5.5 high), no
temperature, no `tool_choice`, no fallbacks. If a model rejected a synthetic `tool_use`
turn that carries no thinking block, the harness describes the failed call as text in
the user turn instead (`--protocol text`); each block names the protocol that ran.

**Arms.** Every payload is generated at run time from the refusal the checked-out code
returns.

- **H**: `json.dumps(to_dict())`, the full payload.
- **N**: the same dict with `fix_hints` and every `metadata.errors[].fix_hint` removed.
  The error line and the rest of `metadata` stay.
- **S**: what the Claude Agent SDK adapter sends: the error line and the `Fix hints:`
  lines as a text block, no metadata.
- **G** (optional): a constant `Error: the tool call was rejected.`

**Scoring.** The response's first `tool_use` runs through a fresh stub of the same tool.
Every stub runs `UnknownArgsMode.BLOCK` (the default strips unknown arguments), so a
corrected call that invents an argument is refused, not silently cleaned up.
*Recovered* means the stub ran the tool body; *semantic recovery* (SR) additionally
requires the corrected arguments to match the task (the oracle in
[`score.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/fix_hints/score.py)).
Other outcomes: the same error again (with identical retries counted separately), a
different error, no tool call, another tool, an API refusal (`stop_reason: refusal`) and
a truncation (`max_tokens`). A control succeeds when the refused tool is not called
again: the model stops, switches to the permitted alternative, or calls another tool.
Failed batch requests and harness errors are excluded from every denominator and counted
beside it.

**Statistics.** Recovery rate (RR) and SR per arm, category, model and round, each with
a 95% Wilson interval. McNemar exact tests, paired by scenario, for H vs N and S vs H,
and for R2 vs R1 per arm. H vs N leaves out scenarios whose two payloads are
byte-identical. The p-values are descriptive: there is no multiplicity correction.

**Rounds.** R1 measures the hint code at the commit it ran on. R2 runs after the hint
fixes, on every scenario whose payload changed plus a seeded 25% of the unchanged ones as
a test-retest control. Each block records its commit, the sha256 of `validator.py`,
`self_heal.py`, `core.py` and `_claude_sdk_tools.py`, the batch ids, the SDK version and
the pricing snapshot.

**What this does not measure.** One refusal and one chance to recover: a real agent may
retry several times or read more context. The tools, names and hosts are fictional and
every task fixes the values the oracle checks. The category mix is a design choice, not a
sample of production traffic, so an "all repair categories" rate is an average over the
categories as weighted here. Every arm shows the tool's schema, so many type and
constraint errors are recoverable with no hint at all; H vs N is what the hints add on
top of that. Model runs are not exactly reproducible, which is why R2 carries a retest
control.

## Results (append-only)

Each round appends a dated block below, newest first. A block is never edited after it is
written; a repeated or corrected run gets its own block beside the earlier one.

<!-- FIX-HINTS-ROUNDS: append newest below; never edit dated blocks -->

_Not yet measured._ No round has run yet, so this file reports no rate. The first R1
block replaces this paragraph.
