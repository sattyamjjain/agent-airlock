<!-- @generated from src/agent_airlock/owasp_agentic_coverage/agentic_coverage.yaml — do not edit by hand; regenerated and byte-diffed in tests/owasp_agentic_coverage/test_coverage_completeness.py -->

# OWASP Agentic v2.01 coverage

Spec: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
Last verified (global): 2026-08-31

| Risk ID | Risk | Guard module | Preset | Test | Last verified | Advisory |
|---------|------|--------------|--------|------|---------------|----------|
| ASI01 | Agent Goal Hijack (Partial) | `agent_airlock.validator` | `owasp_mcp_top_10_2026_policy` | `tests/test_validator.py` | 2026-08-31 | [link](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) |
| ASI02 | Tool Misuse and Exploitation (Full) | `agent_airlock.safe_types` | `flowise_cve_2025_59528_defaults` | `tests/test_safe_types.py` | 2026-08-31 | [link](https://labs.cloudsecurityalliance.org/research/csa-research-note-flowise-mcp-rce-exploitation-20260409-csa/) |
| ASI03 | Identity and Privilege Abuse (Partial) | `agent_airlock.mcp_spec.step_up_scope_guard` | `mcp_step_up_scope_2026_07_defaults` | `tests/test_mcp_step_up_scope_preset.py` | 2026-08-31 | [link](https://modelcontextprotocol.io/specification/2026-07-28) |
| ASI04 | Agentic Supply Chain Vulnerabilities (Partial) | `agent_airlock.mcp_spec.stdio_command_injection_guard` | `stdio_guard_ox_defaults` | `tests/mcp_spec/test_stdio_command_injection_guard.py` | 2026-08-31 | [link](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) |
| ASI05 | Unexpected Code Execution / RCE (Full) | `agent_airlock.capabilities` | `flowise_cve_2025_59528_defaults` | `tests/test_capabilities.py` | 2026-08-31 | [link](https://labs.cloudsecurityalliance.org/research/csa-research-note-flowise-mcp-rce-exploitation-20260409-csa/) |
| ASI06 | Memory and Context Poisoning (Partial) | `agent_airlock.context` | `owasp_mcp_top_10_2026_policy` | `tests/test_context.py` | 2026-08-31 | [link](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) |
| ASI07 | Insecure Inter-Agent Communication (Partial) | `agent_airlock.a2a` | `owasp_mcp_top_10_2026_policy` | `tests/test_a2a.py` | 2026-08-31 | [link](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) |
| ASI08 | Cascading Failures (Full) | `agent_airlock.circuit_breaker` | `owasp_mcp_top_10_2026_policy` | `tests/test_new_features.py` | 2026-08-31 | [link](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) |
| ASI09 | Human-Agent Trust Exploitation (Partial) | `agent_airlock.honeypot` | `owasp_mcp_top_10_2026_policy` | `tests/test_honeypot.py` | 2026-08-31 | [link](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) |
| ASI10 | Rogue Agents (Monitor-only) | `agent_airlock.anomaly` | `owasp_mcp_top_10_2026_policy` | `tests/test_anomaly.py` | 2026-08-31 | [link](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) |
