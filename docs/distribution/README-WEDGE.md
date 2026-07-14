# Distribution copy — the wedge, one message everywhere

Single source of truth for how agent-airlock is described in external listings
(awesome-lists, PyPI, social). Keep every channel on this message so discovery
copy stays consistent. **Not a runtime feature — this directory is copy + draft
submissions only.**

## The one-liner (canonical)

> **in-process least-privilege for AI tool calls — deny-by-default, per-CVE presets.**

Lead with **least-privilege / type-checker / contract layer for tool calls**.
Do **not** call it a "firewall" (crowded term; collides with an existing WAF
vendor and several other "airlock" projects, and it undersells the in-process,
per-argument angle).

## The entry line (awesome-lists)

One factual sentence, reused verbatim across every list:

> **agent-airlock** — in-process least-privilege decorator for AI tool calls;
> deny-by-default, PII masking, per-CVE presets, 3,409 tests.

> [!NOTE]
> **Refresh the test count** to the current README **TEST-BADGE** value at the
> moment you submit each PR (badge is regenerated every release). As of v0.8.47
> it is **3,409**.

## PyPI description (already on-message)

The `[project].description` in `pyproject.toml` already reflects this wedge:

> A type-checker and contract layer for AI agent tool calls — deny-by-default,
> in-process, zero-dep. Strict argument validation, ghost-argument stripping,
> and self-healing retries for MCP servers and agent frameworks.

Keep them aligned: if you sharpen one, sharpen the other.

## Why these words

- **in-process** — the check runs at the `@Airlock` decorator seam, in the tool
  process. No sidecar, no model call, microsecond overhead.
- **least-privilege / deny-by-default** — a `SecurityPolicy` allow-lists exactly
  the tools/args a task needs; everything else is refused.
- **per-CVE presets** — curated, opt-in policy bundles that track named MCP CVEs
  and spec SEPs (composed from existing primitives, zero-dep core).
- **PII masking** — output sanitizer with 13 PII types incl. India DPDP
  (Aadhaar/PAN/UPI/IFSC/mobile).

## Distribution surfaces (submit where builders already look)

- `awesome-mcp-security.md` — MCP security tooling lists
- `awesome-llm-security.md` — LLM/AI security lists
- `awesome-agent-security.md` — agent-security lists
- `awesome-mcp-servers.md` — the **clients / tools** section (it is a library,
  **not** an MCP server — only the tools/clients section is appropriate)

Each file is **draft PR text for the operator to submit** — nothing here is
auto-submitted.
