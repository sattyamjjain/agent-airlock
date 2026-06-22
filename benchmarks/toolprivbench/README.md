# ToolPrivBench-style least-privilege block-rate benchmark

A public, MIT, re-runnable benchmark that measures how agent-airlock's
**deny-by-default + least-privilege** runtime policy handles **over-privileged
tool selection**, mapped to the OWASP Agentic Top-10.

Anchor: **ToolPrivBench** — *"When Lower Privileges Suffice: Investigating
Over-Privileged Tool Selection in LLM Agents"*
([arXiv:2606.20023](https://arxiv.org/abs/2606.20023)). 8 domains (Business,
Coding, Database, Education, Government, Healthcare, Infrastructure, Media),
5 risk patterns (Authority Escalation, Data Over-Exposure, Safety Bypass, Scope
Expansion, Temporal Persistence), with a **transient-failure amplifier** —
ToolPrivBench's finding that a transient tool failure pushes agents to escalate,
and that prompt-level controls degrade under it.

## What it measures

For each scenario (a task satisfiable with a **low-privilege** tool, plus an
**over-privileged** alternative), the harness wraps the candidate tools in
agent-airlock's deny-by-default least-privilege `SecurityPolicy`
(`default_deny=True`, allowlist = only the low-priv tool) and records:

- **over-priv blocked** — the over-privileged call raises `PolicyViolation`;
- **over-priv blocked after transient failure** — still blocked when the
  over-priv decision is retried after the low-priv tool "fails" (the amplifier);
- **low-priv allowed** — the legitimate low-priv call still passes, so the
  policy is *precise*, not a blunt deny-all.

The current number is in [`RESULTS.md`](RESULTS.md). **Results last run on
2026-06-22** (subset harness, 100 scenarios).

## Reproduce

```bash
python -m benchmarks.toolprivbench           # print the summary
python -m benchmarks.toolprivbench --write    # also regenerate RESULTS.md
```

No network access, no model calls — pure, deterministic policy evaluation.

### Full dataset (optional)

The official ToolPrivBench dataset
(`github.com/AISafetyHub/agent-tool-selection-bias`, 544 scenarios) is **not
vendored**. Drop a JSON export at
`benchmarks/toolprivbench/data/toolprivbench.json` (or point
`$TOOLPRIVBENCH_DATA` at one) with records carrying `domain` / `risk_pattern` /
`task` / `low_priv_tool` / `over_priv_tool`, and the harness consumes it
automatically. Otherwise it runs the labelled **subset harness** (~20
scenarios/pattern) — clearly marked as such in `RESULTS.md`.

## Honest caveat

This benchmark measures **runtime BLOCK behaviour under fixed presets — not
model behaviour.** A 100% block-rate means deny-by-default mechanically refuses
any tool that is not on the least-privilege allowlist (including under the
transient-failure amplifier where ToolPrivBench shows prompt-level controls
degrade). It is **not** a claim that the agent stopped *choosing*
over-privileged tools — it's a claim that the runtime firewall blocks the call
regardless of what the model selects. The complementary low-privilege
allow-rate is reported to show the policy is precise, not a blunt deny-all.

MIT-licensed, like the rest of agent-airlock. This is a public number + a
reproducible harness — not a paid feature.
