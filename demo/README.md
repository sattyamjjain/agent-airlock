# Agent-Airlock — live demo

**Thesis:** govern the *action* at the execution boundary. An agent gets prompt-injected;
airlock blocks the dangerous tool call in-process, deterministically, and audits it.

## Setup (no keys, no network)

```bash
git clone https://github.com/sattyamjjain/agent-airlock && cd agent-airlock
pip install -e .
```

## Run the demo — one command

```bash
python demo/presenter.py          # step through with Enter — you control the pace
python demo/presenter.py --auto   # run straight through (rehearsal / screen recording)
```

Three acts, ~9 minutes:

1. **The block** — an injected agent tries to wire money to an attacker. Airlock lets the
   authorized read through and blocks the type-confused transfer, the ghost-argument
   bypass flag, and the pivot to an unauthorized tool. Then it prints the audit trail.
2. **Shift left** — `scan-tools` statically type-checks the tool *definitions* against a
   least-privilege policy: two pass, one fails (open surface on a destructive tool +
   capability exceeds policy). Exit code 2 for CI.
3. **The proof** — the block-rate benchmark: 210 tool calls, 100% of malicious blocked,
   0% false-positive, ~1.5µs per decision. Incumbents marked scope-claimed, not re-run.

## Backup (if anything misbehaves live)

```bash
pytest tests/test_scan_tools.py tests/test_blockrate_benchmark.py -q   # 45 pass, ~0.2s
```

Or open `benchmarks/blockrate/RESULTS.md` and `benchmarks/agentdojo/RESULTS.md`.

## Notes / gotchas

- **No API keys anywhere** in this demo. Do **not** run `examples/e2b_sandbox.py` live (needs an E2B key).
- Act 3 (the benchmark) needs the **repo clone** — `benchmarks/` is not in the pip wheel.
  Acts 1–2 also run from a plain `pip install agent-airlock`.
- `demo/airlock_audit.jsonl` is generated fresh each run (gitignored).
- The individual pieces are also runnable standalone: `python demo/live_demo.py`,
  `airlock-scan-tools demo/tools.json --policy strict`, `python -m benchmarks.blockrate`.
