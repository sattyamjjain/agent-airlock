# agent-airlock — guard-suite benchmark

> **What this measures:** whether agent-airlock's full guard suite blocks malicious tool-call arguments (**detection rate**) without blocking benign ones (**false-positive rate**), on a deterministic, reproducible corpus.

> **Honest scope:** this is a **self-corpus** — it grades agent-airlock
> against its own CVE fixtures. Every `expected_block` is an *independent*
> judgement of whether the payload is malicious; the suite's job is to
> agree. It is **not** a competitive benchmark and **not** an
> adaptive-attacker / ASR measurement. The value is the reproducible,
> per-class, false-positive-aware breakdown — not the headline number.

## Headline

| metric | value |
|---|---|
| **Detection rate** (malicious blocked) | **100.0%** (21/21) |
| **False-positive rate** (benign blocked) | **13.3%** (2/15) |
| Overall accuracy | 94.4% (34/36) |
| Corpus size | 36 entries (21 malicious, 15 benign) |
| Missed attacks (false negatives) | 0 |

## By attack class

| attack class | CWE | OWASP (indicative) | detection | false positives |
|---|---|---|---|---|
| `code_execution_eval` | CWE-94 | ASI05 | 5/5 | 0/3 |
| `codegen_delimiter_breakout` | CWE-94 | ASI05 | 3/3 | 2/4 |
| `command_injection_stdio` | CWE-78 | MCP05 | 4/4 | 0/2 |
| `env_interpolation_leak` | CWE-200 | MCP01 | 3/3 | 0/2 |
| `subprocess_arg_injection` | CWE-88 | MCP05 | 3/3 | 0/2 |
| `unsafe_deserialization` | CWE-502 | ASI05 | 3/3 | 0/2 |

## Every entry

| prompt | class | expected | suite verdict | anchor |
|---|---|---|---|---|
| `eval-bare-call` | `code_execution_eval` | malicious | ✅ blocked | `CVE-2026-44717` |
| `eval-os-system` | `code_execution_eval` | malicious | ✅ blocked | `CVE-2026-44717` |
| `exec-os-system` | `code_execution_eval` | malicious | ✅ blocked | `CVE-2026-44717` |
| `import-os-system` | `code_execution_eval` | malicious | ✅ blocked | `CVE-2026-44717` |
| `getattr-builtins-eval` | `code_execution_eval` | malicious | ✅ blocked | `CVE-2026-44717` |
| `eval-benign-arithmetic` | `code_execution_eval` | benign | ✅ allowed | `benign-math` |
| `eval-benign-trig` | `code_execution_eval` | benign | ✅ allowed | `benign-math` |
| `eval-benign-evaluation-word` | `code_execution_eval` | benign | ✅ allowed | `benign-text` |
| `stdio-semicolon-rm` | `command_injection_stdio` | malicious | ✅ blocked | `MCP-STDIO-injection / CVE-2026-40933` |
| `stdio-pipe-netcat` | `command_injection_stdio` | malicious | ✅ blocked | `MCP-STDIO-injection / CVE-2026-40933` |
| `stdio-backtick-id` | `command_injection_stdio` | malicious | ✅ blocked | `MCP-STDIO-injection / CVE-2026-40933` |
| `stdio-double-amp` | `command_injection_stdio` | malicious | ✅ blocked | `MCP-STDIO-injection / CVE-2026-40933` |
| `stdio-benign-fetch` | `command_injection_stdio` | benign | ✅ allowed | `benign-stdio` |
| `stdio-benign-node-port` | `command_injection_stdio` | benign | ✅ allowed | `benign-stdio` |
| `deser-pickle-marker` | `unsafe_deserialization` | malicious | ✅ blocked | `CVE-2026-25874` |
| `deser-jsonpickle-marker` | `unsafe_deserialization` | malicious | ✅ blocked | `CVE-2026-25874` |
| `deser-base64-pickle` | `unsafe_deserialization` | malicious | ✅ blocked | `CVE-2026-25874` |
| `deser-benign-json` | `unsafe_deserialization` | benign | ✅ allowed | `benign-json` |
| `deser-benign-config` | `unsafe_deserialization` | benign | ✅ allowed | `benign-config` |
| `env-exfil-jwt` | `env_interpolation_leak` | malicious | ✅ blocked | `CVE-2026-32625` |
| `env-exfil-dbpass` | `env_interpolation_leak` | malicious | ✅ blocked | `CVE-2026-32625` |
| `env-exfil-bearer` | `env_interpolation_leak` | malicious | ✅ blocked | `CVE-2026-32625` |
| `env-benign-plain-url` | `env_interpolation_leak` | benign | ✅ allowed | `benign-url` |
| `env-benign-endpoint` | `env_interpolation_leak` | benign | ✅ allowed | `benign-url` |
| `codegen-triple-quote-rce` | `codegen_delimiter_breakout` | malicious | ✅ blocked | `CVE-2026-11393` |
| `codegen-quote-breakout` | `codegen_delimiter_breakout` | malicious | ✅ blocked | `CVE-2026-11393` |
| `codegen-triple-quote-assign` | `codegen_delimiter_breakout` | malicious | ✅ blocked | `CVE-2026-11393` |
| `codegen-benign-instruction` | `codegen_delimiter_breakout` | benign | ✅ allowed | `benign-instruction` |
| `codegen-benign-arg` | `codegen_delimiter_breakout` | benign | ✅ allowed | `benign-instruction` |
| `codegen-benign-dict-access` | `codegen_delimiter_breakout` | benign | ⚠️ false-positive | `benign-code-like (known FP)` |
| `codegen-benign-json-string` | `codegen_delimiter_breakout` | benign | ⚠️ false-positive | `benign-code-like (known FP)` |
| `subproc-shell-string` | `subprocess_arg_injection` | malicious | ✅ blocked | `CVE-2026-42271` |
| `subproc-bash-argv` | `subprocess_arg_injection` | malicious | ✅ blocked | `CVE-2026-42271` |
| `subproc-ld-preload` | `subprocess_arg_injection` | malicious | ✅ blocked | `CVE-2026-42271` |
| `subproc-benign-uvx` | `subprocess_arg_injection` | benign | ✅ allowed | `benign-spawn` |
| `subproc-benign-node` | `subprocess_arg_injection` | benign | ✅ allowed | `benign-spawn` |

## Methodology

- **Guard suite:** Comprehensive suite (all guards enabled): EvalRCEGuard, FilterEvalRCEGuard, CodegenDelimiterInjectionGuard, UnsafeDeserializationGuard, MCPServerEnvInterpolationGuard, McpSubprocessArgInjectionGuard (allowlist=[uvx,npx,node,python,python3,deno]), StdioCommandInjectionGuard. Blocks iff ANY guard refuses.
- **Decision rule:** an entry is *blocked* iff **any** guard in the suite refuses it.
- **`expected_block`:** an independent malicious/benign label per entry. Detection counts agreements on malicious entries; false positives count disagreements on benign entries.
- **OWASP mapping:** indicative alignment with the OWASP Agentic / MCP Top-10 (ASI05, MCP01, MCP05), using the codes agent-airlock already applies in its presets. The rigorous axis is `attack_class` + CWE.
- **Corpus:** [`tests/cves/corpora/airlock_guard_benchmark_2026_06_13.json`](tests/cves/corpora/airlock_guard_benchmark_2026_06_13.json) — deterministic, version-controlled.

### Known limitations (read before trusting the headline)

- **Maximal-coverage config, not a tuned deployment.** Every guard runs on every argument value. This *maximises detection* — overlapping guards catch obfuscations (e.g. the codegen guard's quote/breakout check catches `eval` indirection the eval guard alone misses) — but it also **over-blocks benign code-like strings** (dict access such as `data['key']`, embedded JSON). The false-positive rate above reflects that. In production, scope guards to their intended fields (`CodegenDelimiterInjectionGuard(allowed_literal_fields=...)`, `MCPServerEnvInterpolationGuard(scanned_keys=...)`) to cut false positives.
- **Signature/syntax-based, not semantic.** Individual guards match known sink/token shapes; in isolation several are evadable (e.g. aliasing `eval`). Detection here is a property of the *suite* (defense-in-depth), not of any single guard.
- **Self-corpus.** Payloads derive from agent-airlock's own CVE fixtures, so a high detection number is expected and is **not** evidence of robustness against novel or adaptive attackers. Treat this as a coverage / regression baseline, not an ASR result.

### Reproduce

```bash
make benchmark        # regenerates this file
# or:
python3 scripts/generate_benchmark.py
```

_Generated 2026-06-13 by `scripts/generate_benchmark.py` from `airlock_guard_benchmark_2026_06_13`. Re-run after any guard change to refresh the numbers._
