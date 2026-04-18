# Cross-Project Synthesis — agent-airlock · agent-audit-kit · Verdict · whyCantWeHaveAnAgentForThis

**Report date:** 2026-04-18
**Scope:** How these four repos relate to each other, where they overlap, and what a combined roadmap looks like.

---

## 1. What the four projects have in common

All four are products of the same author (`sattyamjain96@gmail.com` appears as the SES admin in whyCantWeHaveAnAgentForThis and as the Verdict plugin author), and three of the four share a tight thematic focus: **security and quality for AI-agent pipelines.** The fourth — whyCantWeHaveAnAgentForThis — is a consumer-facing satirical product that critiques AI-agent *ideas*.

There is a natural layering:

```
     whyCantWeHaveAnAgentForThis
           (SaaS consumer product, Next.js)
                       │
            Submits: an idea → gets a verdict
                       │
───────────────────────┼───────────────────────
                       │
               ┌───────┴────────┐
               │                │
        agent-audit-kit   agent-airlock
        (static scan)     (runtime middleware)
               │                │
         Same mental model: MCP-era agent security
               │                │
               └───────┬────────┘
                       │
                   Verdict
     (quality evaluator for skill / agent output)
```

All four share a Python + markdown authoring style, stdlib-first sensibilities (Verdict explicitly; agent-audit-kit largely; agent-airlock where feasible), and deep familiarity with the MCP / Claude Code / Cowork ecosystem.

---

## 2. The two "agent security" siblings: airlock and audit-kit

**agent-airlock** and **agent-audit-kit** are the most obviously complementary — one is runtime, one is static:

| | agent-airlock | agent-audit-kit |
|---|---|---|
| When | At call time, inside the tool handler | Ahead of time, as a CI gate |
| What it sees | Arguments, return values, socket traffic, policy state | Source files, config files, hook definitions |
| What it prevents | LLM-invented args, unauthorized egress, PII leaks, sandbox escapes | Hardcoded secrets, bad MCP configs, insecure hooks, poisoned tools, trust-boundary violations |
| Output | Self-healing JSON response, audit record, OTel span | Finding objects, SARIF, OWASP map, compliance report |
| Protocol coverage | MCP (FastMCP), LangChain, OpenAI SDK, CrewAI, AutoGen, LlamaIndex, smolagents | 13 agent platforms (Claude Code, Cursor, VS Code, Windsurf, Amazon Q, Goose, Continue, Roo, Kiro, Gemini CLI) |
| Rule framework | Policy/Capability/Filesystem/Network objects | `RuleDefinition` dataclass, 77 rules across 11 categories |

**Integration opportunities:**

1. **Shared rule IDs.** Audit-kit findings and airlock block reasons could use a unified identifier schema — e.g. `AAK-MCP-003` (no timeouts) in a scan would map to an airlock `BlockReason("AAK-MCP-003")` at runtime. That would let a user trace a CI finding into the live audit log or vice versa.
2. **Shared OWASP + compliance mappings.** Audit-kit already maps findings to OWASP Agentic Top 10, OWASP MCP Top 10, Adversa AI Top 25, EU AI Act, SOC 2, ISO 27001, HIPAA, NIST AI RMF. Airlock has none of that in its audit records. Import audit-kit's mapping tables into airlock's `AuditRecord` for parity.
3. **Secret detection kernel.** Both projects detect API-key / JWT / AWS-credential patterns. Airlock's `sanitizer.py` has 14 carefully ReDoS-analyzed patterns; audit-kit's `secret_exposure.py` is simpler and more regex-brittle. Promote the airlock patterns into a shared `agent_security_commons` library both projects depend on.
4. **Pinning + honeypot.** Audit-kit's SHA-256 tool-pin file (`.agent-audit-kit/tool-pins.json`) is a static fingerprint of the tool surface; airlock's `honeypot.py` detects when the LLM is probing outside its policy. The combination — pin + runtime-mismatch alert — would be a strong rug-pull defense.
5. **MCP Proxy convergence.** Both projects ship an MCP proxy. Audit-kit's `proxy/interceptor.py` is read-only observation; airlock's `mcp_proxy_guard.py` enforces credential scope. They should be the same daemon with two modes (`--observe` vs `--enforce`).

---

## 3. Verdict is the quality sibling

**Verdict** evaluates how well a skill or subagent executed its task — orthogonal to airlock and audit-kit, which evaluate *security*. But the connection is real: Verdict's seven dimensions include **Safety**, whose heuristics overlap with audit-kit's findings (both look for `rm -rf /`, hardcoded credentials, destructive database commands). Today those are separate regex sets; they could trivially share.

**What Verdict could borrow:**
- The audit-kit secret-detection patterns (strong form) instead of its current keyword list.
- The airlock context-aware masking logic (skip credential patterns that are clearly in env-var usage), which is more robust than Verdict's `env|getenv|config` substring skip.

**What Verdict offers the others:**
- Agent-airlock's audit records and agent-audit-kit's scan runs are *exactly* the kind of transcripts Verdict can score. Running Verdict over the output of a red-team scan or a live audit log gives a composite quality grade that's harder to game than individual rule hits.

---

## 4. whyCantWeHaveAnAgentForThis is the product case study

It's the "dogfood" of the other three in spirit: a real, small, production-ish AI-agent product with a consumer-facing surface, real credentials, real prompt-injection attempts, and real rate-limiting. Everything the other three projects try to defend against happens here at runtime:

- **Prompt injection attempts** — the app's `validation.ts` has a regex-first filter; airlock's defense-in-depth model (ghost-arg stripping, capability gating, sanitization) is the mature version of the same idea, one layer up.
- **Secret exposure** — the most critical finding in the audit (live creds in `.env.local`) is exactly what audit-kit's `AAK-SECRET-*` rules exist to catch. Running `agent-audit-kit scan .` inside `whycantwehaveanagentforthis/` would have raised several of these on day one.
- **Admin-endpoint auth in a query parameter** — not covered by any of the three security tools today, but it's the kind of pattern that an "agent-config" scanner could detect.
- **Output quality** — Verdict-style scoring of the actual Claude responses (did the model produce valid JSON? did it include all 13 required fields? did it avoid obvious hallucination markers like `Unknown` in `killer`?) would be a useful CI check on prompt drift.

**Recommended concrete improvements for whyCantWeHaveAnAgentForThis specifically:**
1. Rotate all credentials in `.env.local` today.
2. Add `agent-audit-kit scan .` as a GitHub Action — use the author's own tool on the author's own app.
3. Use airlock (or its principles — ghost-arg stripping, strict Pydantic-style schemas in TypeScript with Zod) to wrap the Claude call. Today the JSON extraction is regex + `JSON.parse`; Zod would catch malformed responses earlier and give structured errors.
4. Add Verdict-style scoring of a sample of live responses to detect model drift (e.g., verdict distribution shifts over time).

---

## 5. Shared tech-debt patterns

Recurring themes across the four codebases:

| Pattern | Where it appears | Severity |
|---|---|---|
| Regex-based heuristics doing double duty as classifiers | Verdict (all 7 analyzers), audit-kit (secret_exposure), airlock (sanitizer), whyCant (validation.ts) | Medium — works, but false positives at the margins |
| No exception handling around plugin / scanner boundaries | audit-kit (`engine.run_scan`) | High |
| Optional heavy-weight dependency silently failing | audit-kit (Ollama), airlock (E2B fallback) | Medium — inconsistent UX |
| No test suite | whyCantWeHaveAnAgentForThis | High |
| Weight-sum / invariants not enforced by code | Verdict config | Low |
| Public API surface inflation | airlock (~200 exports) | Low |
| Documentation promising more than the code delivers | audit-kit (TypeScript/Rust "taint analysis" is regex) | Medium |

---

## 6. Suggested joint roadmap

### Short-term (1–2 weeks)
1. **Credential rotation + `.env.local` cleanup** in whyCantWeHaveAnAgentForThis (critical).
2. **Add exception handling** around each scanner in audit-kit's `engine.run_scan`, plus a new `AAK-INTERNAL-SCANNER-FAIL` INFO-level finding (one-day fix).
3. **Retire dead RUGPULL rules** in audit-kit or wire them into `pinning.verify_pins` (also one-day).

### Medium-term (1–2 months)
4. **Extract `agent_security_commons`** as a shared dependency used by airlock + audit-kit (+ optionally Verdict). Move the strongest secret patterns, PII detectors, and OWASP mapping there.
5. **Unify rule IDs** across airlock and audit-kit (`AAK-XYZ-###` referenced by both).
6. **Merge the two MCP proxies** into one tool with `--observe` and `--enforce` modes.
7. **LLM-backed analyzer option** in Verdict (keep heuristics as default, offer Claude Haiku as opt-in).

### Longer-term (quarter-scale)
8. **Cross-cutting dashboard.** Audit-kit produces SARIF; airlock produces JSON-Lines + OTel; Verdict produces scorecards. A single dashboard that ingests all three into one view (this is where a SaaS offering would naturally live).
9. **Framework-compatibility matrix** as a CI artifact maintained by airlock — tested framework versions, tested `vaccinate()` targets. Ship a badge.
10. **Verdict rubric versioning** + per-rubric weight overrides.

---

## 7. What this combined stack looks like in practice

A team that adopts all four:

- **Pre-commit / CI:** `agent-audit-kit scan .` blocks PRs that add hardcoded secrets, insecure MCP configs, or poisoned tools (SARIF uploaded to GitHub Security tab).
- **Runtime:** Every MCP tool is wrapped in `@Airlock(...)` with a policy tuned via `SecurityPolicy` / `CapabilityPolicy`. Sandbox runs on E2B. Audit records stream to OpenTelemetry.
- **Post-run quality:** Verdict hooks `Stop` and `SubagentStop` events; any skill below the threshold (`composite < 5.0`) exits 2 and blocks follow-up work.
- **Application layer (e.g. whyCantWeHaveAnAgentForThis):** benefits from all three, plus a Zod-validated LLM response schema modeled after airlock's ghost-arg stripping pattern.

The four projects are **already** a coherent stack; they just don't quite know about each other yet.

---

## 8. Bottom line

One author, one mental model, four lenses on the same problem:
- **whyCantWeHaveAnAgentForThis** is "what does an AI-agent product look like in production?"
- **agent-audit-kit** is "can I prove it's safe before it ships?"
- **agent-airlock** is "can I stop it from misbehaving while it runs?"
- **Verdict** is "was the output actually good?"

They were probably built in that order (reactive → proactive → runtime → quality), and the natural next step is to thread them together so findings in one surface in the others. The technical foundations are there; the glue is the missing piece.
