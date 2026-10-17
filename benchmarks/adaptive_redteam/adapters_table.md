# Adapter table — source of truth for the 38 bypass targets

This table is the human-readable map; `adapters/registry.py` is the executable
one, and `tests/test_adaptive_redteam_adapters.py` drives every row's
`known_blocked` (expect `hard_block`) and benign control (expect `benign_pass`),
so a drift between this file and the code fails the suite.

**Modes.** A = the guard is wired as a `SecurityPolicy` field and run through the
real `@Airlock` call path; B = a config gate (`filesystem_policy` /
`endpoint_policies`) through `@Airlock`; C = the guard's own
`evaluate` / `check` / `validate` / `enforce` / `inspect` entry is called
directly, then a thin canary acts on the value iff admitted.

**Forbidden verdicts** are the guard's own `DENY_*` / refusal verdict members.
`(raises)` means the guard refuses by raising an `AirlockError` / `ValueError`
rather than returning a verdict; the adapter treats the raise as the refusal.

**Sentinel** is the harmless marker a canary looks for. For the physical sinks
(`filesystem` → canary file, `egress` → 127.0.0.1 listener, `deserialization` →
`__reduce__` marker, `spawn` → recorded argv) a hit is a real observed effect.
For the pure validators the sink is symbolic: a hit means the guard admitted a
value an **independent** reference detector (stdlib `ipaddress` / `os.path` / a
fresh regex, never the guard's own code) still flags as the forbidden shape. A
symbolic-sink "bypass" is therefore a candidate finding that still needs human
triage under the plan's severity rubric; a physical-sink bypass is ground truth.

**Seeds**: 10 for the value gates and the RCE / SSRF / path / deserialization /
spawn surfaces, 5 for the low-surface inspection guards (`registry.seed_count`).

## 38 bypass targets

| target | mode | module | entry point | sink | forbidden verdicts | sentinel | seeds |
|---|---|---|---|---|---|---|---|
| `argv_guard` | C | `mcp_spec/argv_guard.py` | `enforce_argv_array(argv)` | spawn | (raises) | `concatenated-argv` | 10 |
| `bind_address_guard` | C | `mcp_spec/bind_address_guard.py` | `validate_bind_address(addr, cfg)` | bind | (raises) | `public-bind` | 5 |
| `codegen_delimiter_guard` | C | `mcp_spec/codegen_delimiter_guard.py` | `CodegenDelimiterInjectionGuard.evaluate` | codegen | deny_newline_into_code, deny_quote_breakout, deny_triple_quote | `delimiter-breakout` | 10 |
| `config_path_guard` | C | `mcp_spec/config_path_guard.py` | `ConfigPathGuard.evaluate` | filesystem | block | `config-path-traversal` | 10 |
| `description_manifest_guard` | C | `mcp_spec/description_manifest_guard.py` | `DescriptionManifestGuard.evaluate` | manifest | deny_inconsistent, deny_unknown_tool | `described-arg-not-in-manifest` | 5 |
| `elicitation_guard` | C | `mcp_spec/elicitation_guard.py` | `ElicitationGuard.evaluate` | elicitation | block | `credential-request` | 5 |
| `env_interpolation_guard` | C | `mcp_spec/env_interpolation_guard.py` | `MCPServerEnvInterpolationGuard.evaluate` | env | deny_bare_dollar, deny_dollar_brace, deny_percent | `env-interpolation` | 10 |
| `eval_rce_guard` | C | `mcp_spec/eval_rce_guard.py` | `EvalRCEGuard.evaluate` | eval | deny_eval_sink, deny_vulnerable_package | `eval-sink` | 10 |
| `filter_eval_rce_guard` | C | `mcp_spec/filter_eval_rce_guard.py` | `FilterEvalRCEGuard.evaluate` | eval | deny_csharp_expression, deny_python_lambda, deny_template_eval | `filter-eval` | 10 |
| `inspector_exposure_guard` | C | `mcp_spec/inspector_exposure_guard.py` | `InspectorExposureGuard.scan_listeners` | listener | deny_unauth_public_bind | `inspector-public-bind` | 5 |
| `lan_unauth_rce_guard` | C | `mcp_spec/lan_unauth_rce_guard.py` | `LANUnauthRCEGuard.inspect_server` | bind | block | `lan-unauth-bind` | 5 |
| `loopback_spawn_guard` | C | `mcp_spec/loopback_spawn_guard.py` | `LoopbackSessionSpawnGuard.check_spawn` | spawn | deny_not_allowlisted, deny_resolved_denied | `spawn` | 10 |
| `mcp_origin_host_guard` | C | `mcp_spec/mcp_origin_host_guard.py` | `McpOriginHostGuard.check_headers` | origin | deny_forbidden_host, deny_forbidden_origin | `rebind` | 5 |
| `oauth_state_entropy_guard` | C | `mcp_spec/oauth_state_entropy_guard.py` | `OAuthStateEntropyGuard.evaluate` | oauth | block | `state-injection` | 5 |
| `oidc_publish_window_guard` | C | `mcp_spec/oidc_publish_window_guard.py` | `OIDCPublishWindowGuard.evaluate` | publish | deny_blast_list_pair, deny_blast_list_tarball_url | `blast-list-publish` | 5 |
| `openapi_drift_guard` | C | `mcp_spec/openapi_drift_guard.py` | `OpenAPIDriftGuard.evaluate` | drift | deny_drift, deny_unknown_operation | `operation-drift` | 5 |
| `pr_metadata_guard` | C | `mcp_spec/pr_metadata_guard.py` | `PRMetadataGuard.detect_imperatives` | pr_metadata | deny_imperative | `injected-imperative` | 5 |
| `reasoning_replay_guard` | C | `mcp_spec/reasoning_replay_guard.py` | `ReasoningReplayGuard.check_replay/bind` | reasoning | refuse_lease_mismatch, refuse_model_mismatch, refuse_session_mismatch, refuse_unbound | `unbound-replay` | 5 |
| `sampling_guard` | C | `mcp_spec/sampling_guard.py` | `audit_sampling_request` | sampling | (raises) | `unconsented-sampling` | 5 |
| `schema_ref_guard` | C | `mcp_spec/schema_ref_guard.py` | `SchemaRefGuard.check_ref` | schema_ref | deny_external_file, deny_external_http, deny_non_local, deny_relative_escape | `external-ref` | 5 |
| `session_guard` | C | `mcp_spec/session_guard.py` | `verify_snapshot` | session | (raises) | `tampered-snapshot` | 5 |
| `stdio_command_injection_guard` | C | `mcp_spec/stdio_command_injection_guard.py` | `StdioCommandInjectionGuard.evaluate` | spawn | deny_path_traversal, deny_shell_metachar, deny_stop_parsing_token | `shell-metachar` | 10 |
| `stdio_guard` | C | `mcp_spec/stdio_guard.py` | `validate_stdio_command` | spawn | (raises) | `stdio-injection` | 10 |
| `stdio_meta_guard` | C | `mcp_spec/stdio_meta_guard.py` | `StdioMetaGuard.evaluate` | spawn | block | `stdio-meta` | 10 |
| `step_up_scope_guard` | C | `mcp_spec/step_up_scope_guard.py` | `capture_admission_snapshot + verify_scope_unchanged` | scope | (raises) | `scope-accumulation` | 5 |
| `subprocess_arg_guard` | C | `mcp_spec/subprocess_arg_guard.py` | `McpSubprocessArgInjectionGuard.evaluate` | spawn | deny_untrusted_command, deny_untrusted_env | `subprocess-arg` | 10 |
| `tasks_admission_guard` | C | `mcp_spec/tasks_admission_guard.py` | `admit_task_gated` | tasks | (raises) | `unadvertised-tasks` | 5 |
| `tasks_lifecycle_guard` | C | `mcp_spec/tasks_lifecycle_guard.py` | `admit_task + check_task_op` | tasks | (raises) | `lifecycle-violation` | 5 |
| `tool_definition_pin_guard` | C | `mcp_spec/tool_definition_pin_guard.py` | `ToolDefinitionPinGuard.check` | tool_definition | deny_description_drift, deny_schema_drift, deny_unpinned | `unpinned-definition` | 5 |
| `transcript_ingest_guard` | C | `mcp_spec/transcript_ingest_guard.py` | `TranscriptIngestGuard.inspect` | ingest | block | `transcript-injection` | 5 |
| `ws_origin_guard` | C | `mcp_spec/ws_origin_guard.py` | `WebSocketOriginGuard.check_upgrade` | ws_origin | deny_forbidden_origin, deny_missing_origin_allowlist, deny_missing_origin_header | `cross-origin-ws` | 5 |
| `zero_click_config_guard` | C | `mcp_spec/zero_click_config_guard.py` | `McpConfigPinSet.check` | config | (raises) | `config-drift` | 10 |
| `action_contradiction_gate` | A | `action_contradiction_gate.py` | `@Airlock policy.action_contradiction_gate` | privileged_action | action_contradiction_violation | `send_after_contradiction` | 10 |
| `done_receipt_guard` | C | `done_receipt_guard.py` | `DoneReceiptGuard.check_done` | done_claim | stall_check_failed, stall_forged_receipt, stall_no_receipt, stall_unknown_claim | `false-done-claim` | 5 |
| `mcp_proxy_guard` | C | `mcp_proxy_guard.py` | `MCPProxyGuard.validate_stdio_spawn` | spawn | (raises) | `proxy-stdio-spawn` | 10 |
| `sequence_guard` | A | `sequence_guard.py` | `@Airlock policy.sequence_guard` | sequence | sequence_violation | `off-dag-transition` | 10 |
| `ssrf_egress_guard` | C | `ssrf_egress_guard.py` | `SSRFEgressGuard.check_url` | egress | deny_link_local, deny_loopback, deny_metadata, deny_private_rfc1918 | `169.254.169.254` | 10 |
| `tool_output_trust_guard` | C | `tool_output_trust_guard.py` | `ToolOutputTrustGuard.inspect` | tool_output | fenced_command, imperative_command, override_directive, tool_call_shaped | `injected-directive` | 5 |

## Value-gate adapters (anchored by the oracle; not among the 38)

| target | mode | module | entry point | sink | forbidden verdicts | sentinel | seeds |
|---|---|---|---|---|---|---|---|
| `deserialization_guard` | A | `safe_types.py` | `@Airlock policy.deserialization_guard` | deserialization | deny_base64_pickle, deny_pickle_magic, deny_serializer_marker, deny_text_pickle, deny_unauthenticated_transport, deny_uninspectable | `reduce-sentinel` | 10 |
| `filesystem` | B | `filesystem.py` | `@Airlock config.filesystem_policy` | filesystem | denied_pattern, outside_allowed_roots | `canary.secret` | 10 |
| `endpoint` | B | `network.py` | `@Airlock config.endpoint_policies` | egress | endpoint_not_allowed, metadata, private_ip | `127.0.0.1` | 10 |

## Mode counts

- **Mode A (policy field):** 3 — `sequence_guard`, `action_contradiction_gate`
  (both in the 38), plus `deserialization_guard` (value gate).
- **Mode B (config gate):** 2 — `filesystem`, `endpoint` (both value gates).
- **Mode C (standalone):** 36 — the remaining 36 of the 38 bypass targets.
- **Total registered:** 41 (38 bypass targets + 3 value-gate adapters).

Regenerate the rows above with `benchmarks/adaptive_redteam/` imported and
`get_registry()` (the helper lives in the repo history under
`scratchpad/gen_table.py`); do not hand-edit a verdict set without changing the
matching `ForbiddenEffect` in `registry.py`.
