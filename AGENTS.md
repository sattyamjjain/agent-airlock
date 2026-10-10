# AGENTS.md

A deterministic entrypoint for agentic IDEs (Cursor, Claude Code, Windsurf,
Mintlify) and human contributors who want the safety primitives this
repo treats as load-bearing.

> **Philosophy:** when in doubt, prefer `STRICT_POLICY` and
> `sandbox_required=True`. Every layer in `src/agent_airlock/` exists
> because a pre-existing layer was insufficient for some real CVE.
> Don't remove a check unless you can name the CVE that motivated it.

## Build & Test

```bash
# Install in editable mode with dev deps
pip install -e ".[dev]"

# Optional extras (install only what you need)
pip install -e ".[sandbox]"        # E2B Firecracker
pip install -e ".[mcp]"            # FastMCP
pip install -e ".[claude-agent]"   # Anthropic Claude Agent SDK
pip install -e ".[console]"        # Textual TUI for `airlock console`
pip install -e ".[model-armor]"    # Google Cloud Model Armor
pip install -e ".[all]"            # everything above

# Default test suite — excludes Docker integration tests
pytest -m "not docker"

# Type-check (strict mode)
mypy src/

# Lint + format
ruff check src/ tests/
ruff format src/ tests/
```

## Forbidden patterns

- `subprocess.run(..., shell=True)` anywhere in `src/` (`mcp_spec/manifest_only_mode.py`,
  the only `subprocess` importer, passes `shell=False`)
- raw `eval()` / `exec()` (use `Airlock(sandbox=True, sandbox_required=True)`)
- mocking the fixture under test in CVE regression tests — they run against real fixtures
- removing a CVE fixture in `tests/cves/` without citing the upstream
  advisory and adding a successor

## CVE fixtures are immutable history

Files under `src/agent_airlock/corpus/wild_payload_corpus/` and
`tests/cves/` are signed-history. Edits require:
1. A primary-source URL (NVD, vendor advisory, OX/BlackHat write-up) in the commit message.
2. `docs/cves/index.md` regenerated in the same PR with
   `python3 scripts/gen_cve_catalog.py --write`. It is built from the `tests/cves/`
   docstring headers, so never hand-edit it.

## Default safety posture

```python
from agent_airlock import Airlock
from agent_airlock.policy import STRICT_POLICY

@Airlock(policy=STRICT_POLICY, sandbox=True, sandbox_required=True)
def your_function(...): ...
```

Anything weaker (PERMISSIVE_POLICY, `sandbox_required=False`) needs a
1-line justification in the docstring.

## Where to start as a new contributor

- `README.md` — public-facing positioning and the 30-second quickstart
- `docs/cves/index.md` — every shipped CVE mitigation, primary source linked
- `src/agent_airlock/core.py` — the `@Airlock` decorator entrypoint
- `tests/test_*.py` — every test class is `Test<Feature>` and runs in `<5s`
- `CHANGELOG.md` — every release ships with primary-source URLs for each row

## Conventions

- **Conventional commits** (`feat:`, `fix:`, `docs:`, `chore:`, `ci:`, `security:`,
  `bench:`, `test:`)
- **Branch naming** — `feat/<short>` / `fix/<short>` / `chore/<short>`
- **Tests first** — every `feat:` row needs at least one regression test
- **Coverage floor** — 82% (CI-enforced via `--cov-fail-under=82`)
- **Squash-merge** PRs into `main`; `main` is always tag-able

## Primary references

- Anthropic Agent Skills — https://docs.claude.com/en/agents-and-tools/agent-skills
- MCP specification — https://github.com/modelcontextprotocol/specification
- OWASP Agentic-AI 2026 Q1 — https://owasp.org/www-project-agentic-ai/
- This repo — https://github.com/sattyamjjain/agent-airlock
