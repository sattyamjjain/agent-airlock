# fix_hints recovery

!!! info "One file, two locations"

    The page below is
    [`benchmarks/fix_hints/RESULTS.md`](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/fix_hints/RESULTS.md),
    included verbatim. `python -m benchmarks.fix_hints --score RUN_ID --write` appends
    one dated block per round to it, and it stays in the benchmark package next to the
    code that produces it
    ([`benchmarks/fix_hints/`](https://github.com/sattyamjjain/agent-airlock/tree/main/benchmarks/fix_hints)).
    There is no copy of it under `docs/` to fall out of date.

    Every result on this page comes from a paid model run, so it has no README benchmark
    row and no freshness date: a row would require a credit-funded re-run before every
    release. Each block carries its own run date, commit and batch ids instead.

--8<-- "benchmarks/fix_hints/RESULTS.md"
