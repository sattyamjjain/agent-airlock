# Launch draft — "A type-checker for AI tool calls"

Status: **DRAFT** for review. Two versions below — a Show HN submission and a longer
blog/dev.to post. Both lead with the *problem and the data*, not the product, and keep
every honest caveat in (self-corpus, the false-positive rate, "complements gateways").
That honesty is the point: this audience punishes overclaiming and rewards reproducibility.

Pick the channels in this order (per the distribution research): build the benchmark
asset (done) → submit to MCP registry + awesome-lists (evergreen) → publish the blog post
on your own domain + dev.to (SEO) → Show HN / r/LocalLLaMA / r/Python (the spike). Lead
every one of them with the benchmark, not the tool.

---

## A. Show HN submission

**Title** (factual, no hype — HN strips hype):

> Show HN: Agent-Airlock – validate the arguments your AI agent passes to tools

**URL:** https://github.com/sattyamjjain/agent-airlock

**First comment** (post this immediately as the author — it's what actually drives the thread):

> I kept hitting the same class of bug building agents: the model invents tool-call
> arguments. Extra kwargs that don't exist, a string where an int belongs, a path that
> escapes the sandbox, a `${SECRET}` smuggled into a URL, a pickle blob into a "load"
> tool. Gateways and prompt-firewalls check the *prompt* and allow/deny whole *tools* —
> but almost nothing validates the *arguments* at the function boundary, which is where
> the actual damage happens.
>
> Agent-Airlock is a small MIT-licensed Python decorator that does that:
>
> - strips "ghost" arguments the LLM hallucinated (params not in your signature)
> - validates types with Pydantic in strict mode (no silent `"100"` → `100` coercion)
> - returns a self-healing error the model can read and retry, instead of throwing
> - ships guards for the specific MCP CVE classes (eval/exec RCE, stdio command
>   injection, pickle deserialization, env-var secret interpolation, codegen breakout,
>   subprocess-arg injection)
>
> ```python
> from agent_airlock import Airlock
>
> @Airlock()
> def read_file(path: str) -> str:
>     return open(path).read()
>
> # LLM calls read_file(path="../../etc/passwd", forecolor="blue")
> # → ghost arg `forecolor` stripped, path-escape blocked,
> #   structured fix-hint returned for the model to retry
> ```
>
> I didn't want to just claim it works, so there's a reproducible benchmark
> (`make benchmark`): the full guard suite over a 36-entry corpus of real CVE-shaped
> payloads + benign controls. Current result: **100% detection (21/21), 13.3%
> false-positives (2/15)**. I'm deliberately reporting the false positives — running
> every guard on every argument (max coverage) over-blocks benign code-like strings like
> `data['key']`; in production you scope guards to the fields they're for. It's a
> *self-corpus* (my own fixtures), so treat it as a coverage/regression baseline, not an
> adaptive-attacker score.
>
> It complements gateways (Cloudflare/Portkey/Lasso/etc.) rather than replacing them —
> they sit in the network path; this sits inside the tool function. Solo project, early,
> and I'd genuinely like to hear where the validation model breaks for you.

**Timing:** the data says Monday ~13:00–15:00 UTC is a reasonable slot. Be at the keyboard
for the first 2 hours to answer every comment — that's most of the ranking signal.

---

## B. Blog / dev.to post (longer; the evergreen SEO version)

**Title:** I benchmarked what AI agents actually pass to tools. Here's what gets through.

**Suggested tags:** `ai`, `security`, `python`, `llm`, `mcp`

---

### The bug nobody validates

Every agent framework now lets an LLM call your functions. The framework validates that
the model picked a *real tool*. It does not validate the *arguments* — and that's where
production incidents live:

- **Tool poisoning / argument injection.** Flowise's custom-tool node (CVE-2025-59528,
  CVSS 10.0) passes user input straight into `Function()` with full Node privileges; it's
  been exploited in the wild, with ~12–15k instances exposed.
- **MCP stdio command injection.** An Ox Security audit found unsafe-default stdio
  transport across the MCP ecosystem (LiteLLM, LangChain-Chatchat, Flowise, Windsurf,
  GPT-Researcher…), ~200,000 servers exposed; ~43% of tested MCP implementations had
  command injection (Equixly).
- **The "lethal trifecta"** (Simon Willison): private data access + untrusted content +
  an exfiltration channel. Agents almost always have all three, and the payload arrives
  as a *tool argument* — a `${JWT_SECRET}` in a URL, a pickle blob into a "load state"
  tool, a `; rm -rf /` appended to a config path.

(All figures above are from public sources — link them inline when you publish.)

Gateways and prompt-firewalls inspect the prompt and allow/deny entire tools. Useful, but
they operate at the network/prompt layer. **Nobody validates the argument payload at the
function boundary** — the WAF-for-tool-arguments layer.

### What I built

[Agent-Airlock](https://github.com/sattyamjjain/agent-airlock) is an MIT Python decorator
that treats tool-call arguments as untrusted input:

- **Ghost-argument stripping** — drops params the model invented that aren't in your
  signature (a huge fraction of real LLM tool-call errors).
- **Strict Pydantic validation** — no type coercion; `"100"` is not `100`.
- **Self-healing errors** — returns a structured `fix_hint` the model can read and retry,
  instead of a stack trace that ends the run.
- **CVE-class guards** — eval/exec RCE, stdio injection, pickle deserialization, env-var
  secret interpolation, codegen-delimiter breakout, subprocess-arg injection.

```python
from agent_airlock import Airlock

@Airlock()
def run_query(table: str, limit: int) -> list[dict]:
    ...

# Model emits run_query(table="users", limit="50", debug=True)
#   • ghost arg `debug`     → stripped
#   • limit "50" (str)      → rejected (strict), fix-hint: "limit must be int, not str"
#   • model retries cleanly with limit=50
```

### Don't trust me — run the benchmark

`make benchmark` runs the full guard suite over a deterministic, version-controlled corpus
of real CVE-shaped payloads plus benign controls, and writes
[`BENCHMARK.md`](../../BENCHMARK.md):

| metric | value |
|---|---|
| Detection (malicious blocked) | **100% (21/21)** |
| False-positives (benign blocked) | **13.3% (2/15)** |
| Missed attacks | 0 |

**And here's the honest part.** That 13.3% is real and I'm reporting it on purpose. The
benchmark runs *every guard on every argument* (maximum coverage). That catches even
obfuscated eval — the codegen guard's quote-breakout check is a safety net the eval guard
alone misses — but it also over-blocks benign code-like strings such as `data['key']` or
an embedded JSON snippet. In production you scope each guard to the fields it's meant for,
which trades a little coverage for far fewer false positives. And it's a *self-corpus*:
it grades the guards against their own CVE fixtures, so 100% detection is expected and is
**not** a claim of robustness against novel or adaptive attackers. It's a coverage and
regression baseline — the kind of thing you put in CI so your block rate can't silently
rot, not a competitive ASR number.

### Where it fits

It's not a gateway and doesn't try to be. Gateways (Cloudflare AI Gateway, Portkey, Lasso,
Cisco/PANW MCP scanners) sit in the network path and are the right place for org-wide auth,
rate-limiting, and prompt inspection. Agent-Airlock sits *inside* the tool function, in
your process, framework-agnostic (LangChain, LangGraph, PydanticAI, CrewAI, FastMCP). Use
both.

### Try it

```bash
pip install agent-airlock
```

It's MIT, solo-maintained, and early. The benchmark is reproducible and the corpus is in
the repo — if you can craft a payload that gets through (or a benign input that shouldn't
be blocked), that's exactly the issue I want.

---

## Notes for you (not for publishing)

- **Lead with the benchmark everywhere.** It's the one asset that compounds and the only
  honest hook that isn't "please look at my tool."
- **Keep the FP number in.** Deleting it to show a clean 100% is the fastest way to lose
  this audience — and it would be dishonest. The trade-off *is* the interesting finding.
- **Evergreen submissions first** (cost ~an afternoon, pay off for months): the MCP
  registry (registry.modelcontextprotocol.io), `punkpeye/awesome-mcp-servers`,
  `mcpservers.org`, and any `awesome-llm-security` lists.
- **Don't hardcode the benchmark number into the README** — it's linked, and the number
  lives in `BENCHMARK.md` (single source of truth) so it can't go stale.
