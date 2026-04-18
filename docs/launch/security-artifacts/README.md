# Launch-day security artifacts (v0.5.0)

Snapshot generated 2026-04-18 from the launch-readiness run. These are
PRE-LAUNCH evidence, not runtime outputs.

## Files

| File | Tool | Scope | Status |
|---|---|---|---|
| `bandit.txt` | `bandit -r src/agent_airlock/` | All source | **0 issues** across High / Medium / Low |
| `pip-audit-core.json` | `pip-audit` | Runtime deps only (pydantic, structlog + transitives) | **0 known CVEs** |

SBOM generation is a CI responsibility (to be added to `publish.yml` by a
maintainer with `workflow` scope) — the local `cyclonedx-py environment`
output is dominated by the maintainer's anaconda install and isn't
meaningful. See the outstanding CI-snippet note in PR #18 for the
recommended job.

## Regenerating

```bash
# bandit
bandit -r src/agent_airlock/ -f txt -o docs/launch/security-artifacts/bandit.txt

# pip-audit core
printf 'pydantic>=2.0,<3.0\nstructlog>=24.0\n' > /tmp/deps.txt
pip-audit -r /tmp/deps.txt --format=json \
  -o docs/launch/security-artifacts/pip-audit-core.json
```

## Why not `safety`?

`safety` v3 has a runtime dependency on `scipy`/`nltk` that conflicts with
NumPy 2.x in some conda-distributed environments (observed on the launch
laptop). `pip-audit` uses the PyPA-canonical OSV DB and runs without that
stack, so it's the tool of record here.

## Why a global-env pip-audit?

The `pip-audit.json` full-env report is kept as context, not as a
launch-blocker. `agent-airlock` itself only ships with two runtime deps
(`pydantic`, `structlog`) — those are what users actually install, and
the core audit above covers them. The full-env report picks up every
data-science package on the maintainer's laptop, which is noise.
