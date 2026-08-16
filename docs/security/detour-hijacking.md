# Convergent Detour Hijacking: when the task succeeds and the cost is the payload

**Paper:** [Convergent Detour Hijacking: Task-Preserving Resource Amplification in
Skill-Based LLM Agents](https://arxiv.org/abs/2608.12273) (arXiv:2608.12273, 2026-08-12)
**Regression fixture:** [`tests/test_detour_hijacking.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/test_detour_hijacking.py)
**Open gap:** [#142](https://github.com/sattyamjjain/agent-airlock/issues/142)

## The attack

Convergent Detour Hijacking (CDH) is text-only and runtime-independent. It needs no exploit,
no malformed argument, and no dangerous tool. It works like this:

1. A malicious skill's **description** wins tool selection under shared semantic cover. It
   looks relevant because it was written to look relevant.
2. That skill's **body** reuses the same rationale to fabricate plausible dependencies.
3. The fabricated dependencies **recruit unnecessary but genuinely benign skills** into a
   bounded detour.
4. The trajectory **re-enters the original route**, so the task still completes correctly.

Reported on DeepSeek-V4-Pro across 491 held-out tasks: the matched attacker coordinator is
selected in **80.02%** of tasks. Among coordinator-hit runs that complete, token consumption
rises **66.91%** and end-to-end execution time **92.45%**, while aggregate task completion
stays comparable.

## Why this is hard to see

Every layer that evaluates an agent by its **output** is blind here, because the output is
correct. There is no failed assertion, no wrong answer, no exception, and no refused call.
The damage is entirely in the trajectory: work that was done and did not need to be.

Content inspection does not help either. The recruited skills are real skills doing real
things. There is nothing to find inside `detect_document_encoding`. The attack lives in the
*fact of the call*, not in its payload.

## What agent-airlock sees

A deny-by-default contract layer runs on every tool call, so the recruited calls pass
through a seam an outcome checker never touches. That makes airlock one of the few places
this is observable at all. The fixture pins down exactly how far that goes.

### Visible today

Every recruited call lands in the audit log as its own `AuditRecord`, carrying `tool_name`,
`blocked`, `duration_ms`, `agent_id`, and `session_id`. Given a `session_id`, the calls group
into a run and the count is directly readable:

```jsonl
{"timestamp":"...","tool_name":"fetch_document","blocked":false,"session_id":"sess-detour",...}
{"timestamp":"...","tool_name":"resolve_skill_dependencies","blocked":false,"session_id":"sess-detour",...}
{"timestamp":"...","tool_name":"detect_document_encoding","blocked":false,"session_id":"sess-detour",...}
{"timestamp":"...","tool_name":"normalize_whitespace","blocked":false,"session_id":"sess-detour",...}
{"timestamp":"...","tool_name":"estimate_reading_time","blocked":false,"session_id":"sess-detour",...}
{"timestamp":"...","tool_name":"summarize_text","blocked":false,"session_id":"sess-detour",...}
```

Six calls where two were needed. An outcome checker sees one identical answer twice; the
contract layer sees two calls and six. That difference is the finding, and it is asserted in
`TestPerRunRecordMakesRecruitedCallsVisible`.

### Not visible today

Three limits, each with a test that fails if it is ever fixed silently.

**No cost or token accounting on the record.** `AuditRecord` has no field for either, so the
quantity the paper measures cannot be read off the log even in principle. `duration_ms` is
tool execution time, not the agent's end-to-end wall time, and summing it does not
reconstruct the 92.45% figure because it excludes model latency, which is where a detour
spends most of what it wastes.

**No run identity without a harness context.** `session_id` is populated from a context
object passed as the first positional argument. A harness that does not supply one still
gets every call logged, but the records are anonymous and cannot be assembled into a run at
all. Run-level analysis needs grouping before it needs anything else.

**No detector fires.** `AnomalyDetector` watches call rate, endpoint diversity, error rate,
and consecutive blocks. A detour run has a zero error rate, zero blocks, no endpoint, and a
call count well under `max_calls_per_window`. By these four metrics it is the *quietest
possible run*. That is not a defect in the detector, whose remit is different. It is why the
detour needs its own answer.

The distance between the first list and the second is the distance between **visibility and
detection**. The layer records the extra calls. Nothing in it says they were extra.

## The mitigation that exists

[`SequenceGuard`](https://github.com/sattyamjjain/agent-airlock/blob/main/README.md#-behavioral-sequence-guard-v0812) in DECLARED mode does
refuse a detour today, because a detour is by definition a transition outside the expected
route:

```python
from agent_airlock import SecurityPolicy
from agent_airlock.sequence_guard import ENTRY_SENTINEL, SequenceGuard

policy = SecurityPolicy(
    sequence_guard=SequenceGuard(
        mode="declared",
        action="block",
        dag={
            ENTRY_SENTINEL: {"fetch_document"},
            "fetch_document": {"summarize_text"},
            "summarize_text": set(),
        },
    ),
)
```

The coordinator is the first step off the route, so that is where the block lands.

**The cost is real and worth stating.** DECLARED mode enforces a route the operator wrote
down in advance, and CDH targets skill-based agents precisely because their legitimate route
is discovered at runtime. Where you can declare the route, declare it. Where you cannot, this
control does not reach.

BASELINE mode is the closer fit in principle: it learns per-session transition probabilities
and flags low-probability ones. In practice a detour composed of legitimate skills in a
plausible order may not be low-probability at the level of any single transition, and the
guard will not flag anything until `min_baseline_samples` observations have accumulated from
the preceding tool. It is worth running; it is not a solution.

## Reproduce

```bash
python -m pytest tests/test_detour_hijacking.py -v
```
