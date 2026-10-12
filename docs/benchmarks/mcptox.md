# Tool poisoning: MCPTox

!!! info "One file, two locations"

    The page below is
    [`benchmarks/mcptox/RESULTS.md`](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/mcptox/RESULTS.md),
    included verbatim. `python -m benchmarks.mcptox replay --fetch --write` rewrites its
    replay block (on the canonical Linux host), and
    `python -m benchmarks.mcptox fresh --score <RUN_ID> --write` appends each dated
    fresh-run block below the last one. There is no copy of it under `docs/` to fall
    out of date.

    MCPTox's data is downloaded at run time and verified by sha256. It is never
    committed, because its repository carries no license, and nothing on this page
    quotes it: every table is counts, rates and intervals. The harness and its blind
    policy labels are in
    [`benchmarks/mcptox/`](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/mcptox/README.md).

--8<-- "benchmarks/mcptox/RESULTS.md"
