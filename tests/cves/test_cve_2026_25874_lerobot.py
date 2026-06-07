"""CVE-2026-25874 (HuggingFace LeRobot pickle-deserialization RCE) regression.

LeRobot's async-inference PolicyServer / robot-client call ``pickle.loads()``
on payloads received over an **unauthenticated, non-TLS** gRPC channel
(``SendObservations`` / ``SendPolicyInstructions`` / ``GetActions``). An
unauthenticated, network-reachable attacker reaches arbitrary OS command
execution by sending a crafted pickle blob (CVSS 9.3, published
2026-04-23, unpatched as of disclosure).

This suite pins, end-to-end:

- The reusable :class:`UnsafeDeserializationGuard` primitive across all
  five verdicts (pickle magic / base64 pickle / serializer marker /
  unauthenticated-transport / allow).
- The :func:`lerobot_cve_2026_25874_defaults` preset posture: deny-by-name
  globs + wired content guard + ``require_authenticated_transport``.
- A crafted pickle payload routed through a guarded ``@Airlock`` tool is
  BLOCKED before the sink runs, with a ``fix_hint`` naming CVE-2026-25874.

Primary sources (retrieved 2026-06-07):
  https://www.sentinelone.com/vulnerability-database/cve-2026-25874/
  https://labs.cloudsecurityalliance.org/research/csa-research-note-lerobot-cve-2026-25874-unauth-rce-20260429/
"""

from __future__ import annotations

import base64
import pickle  # nosec B403 - used only to FORGE an attack payload for the guard to block

import pytest

from agent_airlock import (
    LEROBOT_CVE_2026_25874_DEFAULTS,
    Airlock,
    PolicyViolation,
    UnsafeDeserializationGuard,
    UnsafeDeserializationVerdict,
    lerobot_cve_2026_25874_defaults,
)
from agent_airlock.policy_presets import (
    _LEROBOT_DESERIALIZATION_DENIED_TOOLS,
    list_active,
)

CVE = "CVE-2026-25874"


def _evil_pickle() -> bytes:
    """A pickle blob standing in for the attacker's payload (never executed)."""
    return pickle.dumps({"cmd": "os.system('id')"})  # nosec B301 - forged, never loaded


# ---------------------------------------------------------------------------
# Guard primitive — all five verdicts
# ---------------------------------------------------------------------------


class TestUnsafeDeserializationGuard:
    def setup_method(self) -> None:
        self.guard = UnsafeDeserializationGuard(
            require_authenticated_transport=True,
            advisory=CVE,
            advisory_url="https://www.sentinelone.com/vulnerability-database/cve-2026-25874/",
        )
        self.auth = {"authenticated": True, "tls": True}

    def test_raw_pickle_bytes_blocked(self) -> None:
        d = self.guard.evaluate({"payload": _evil_pickle(), "transport": self.auth})
        assert d.allowed is False
        assert d.verdict is UnsafeDeserializationVerdict.DENY_PICKLE_MAGIC
        assert d.matched_field == "payload"

    def test_base64_pickle_string_blocked(self) -> None:
        blob = base64.b64encode(_evil_pickle()).decode()
        d = self.guard.evaluate({"blob": blob, "transport": self.auth})
        assert d.verdict is UnsafeDeserializationVerdict.DENY_BASE64_PICKLE

    @pytest.mark.parametrize(
        "snippet",
        [
            "result = pickle.loads(data)",
            "marshal.loads(buf)",
            "obj = dill.loads(payload)",
            "jsonpickle.decode(s)",
            "yaml.unsafe_load(doc)",
        ],
    )
    def test_serializer_marker_blocked(self, snippet: str) -> None:
        d = self.guard.evaluate({"code": snippet})
        assert d.verdict is UnsafeDeserializationVerdict.DENY_SERIALIZER_MARKER
        assert d.matched_pattern is not None and d.matched_pattern in snippet.lower()

    def test_serialized_bytes_over_unauthenticated_transport_blocked(self) -> None:
        # Benign-looking (non-pickle) bytes, but no authenticated transport.
        d = self.guard.evaluate({"payload": b"not-a-pickle-but-still-opaque-bytes"})
        assert d.verdict is UnsafeDeserializationVerdict.DENY_UNAUTHENTICATED_TRANSPORT

    def test_serialized_bytes_over_authenticated_tls_allowed(self) -> None:
        d = self.guard.evaluate({"payload": b"opaque-bytes", "transport": self.auth})
        assert d.allowed is True

    def test_partial_transport_is_not_enough(self) -> None:
        # authenticated but no TLS, and TLS but no auth — both must hold.
        only_auth = self.guard.evaluate({"p": b"x", "transport": {"authenticated": True}})
        only_tls = self.guard.evaluate({"p": b"x", "transport": {"tls": True}})
        assert only_auth.verdict is UnsafeDeserializationVerdict.DENY_UNAUTHENTICATED_TRANSPORT
        assert only_tls.verdict is UnsafeDeserializationVerdict.DENY_UNAUTHENTICATED_TRANSPORT

    def test_benign_args_allowed(self) -> None:
        d = self.guard.evaluate({"name": "pick up the cube", "speed": 3, "loop": False})
        assert d.allowed is True
        assert d.verdict is UnsafeDeserializationVerdict.ALLOW

    def test_empty_args_allowed(self) -> None:
        assert self.guard.evaluate(None).allowed is True
        assert self.guard.evaluate({}).allowed is True

    def test_fix_hints_name_the_cve(self) -> None:
        d = self.guard.evaluate({"payload": _evil_pickle()})
        assert any(CVE in h for h in d.fix_hints)
        assert any("sentinelone.com" in h for h in d.fix_hints)

    def test_transport_metadata_field_itself_not_scanned(self) -> None:
        # A transport dict carrying a 'pickle.loads'-ish string must not
        # self-trip; the transport key is skipped from content scanning.
        d = self.guard.evaluate(
            {"payload": b"x", "transport": {"authenticated": True, "tls": True, "note": "pickle"}}
        )
        assert d.allowed is True

    def test_bad_extra_markers_type_raises(self) -> None:
        with pytest.raises(TypeError, match="extra_markers"):
            UnsafeDeserializationGuard(extra_markers=["pickle"])  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Preset structure
# ---------------------------------------------------------------------------


class TestPresetStructure:
    def test_returns_security_policy_with_guard(self) -> None:
        policy = lerobot_cve_2026_25874_defaults()
        assert policy.deserialization_guard is not None
        assert policy.deserialization_guard._require_auth is True  # type: ignore[union-attr]

    def test_denied_tools_cover_deserialize_and_grpc_methods(self) -> None:
        policy = lerobot_cve_2026_25874_defaults()
        assert "*deserialize*" in policy.denied_tools
        assert "*pickle.loads*" in policy.denied_tools
        # the three exploited gRPC methods
        for m in ("send_observations", "send_policy_instructions", "get_actions"):
            assert m in policy.denied_tools

    @pytest.mark.parametrize(
        "tool",
        ["deserialize_observation", "unpickle_state", "torch_load", "get_actions"],
    )
    def test_denied_tool_names_raise_policy_violation(self, tool: str) -> None:
        policy = lerobot_cve_2026_25874_defaults()
        with pytest.raises(PolicyViolation):
            policy.check_tool_allowed(tool)

    def test_eager_constant_is_a_security_policy(self) -> None:
        from agent_airlock.policy import SecurityPolicy

        assert isinstance(LEROBOT_CVE_2026_25874_DEFAULTS, SecurityPolicy)

    def test_factory_returns_independent_instances(self) -> None:
        assert lerobot_cve_2026_25874_defaults() is not lerobot_cve_2026_25874_defaults()

    def test_denied_tool_tuple_is_the_module_constant(self) -> None:
        policy = lerobot_cve_2026_25874_defaults()
        assert tuple(policy.denied_tools) == _LEROBOT_DESERIALIZATION_DENIED_TOOLS

    def test_discoverable_via_list_active(self) -> None:
        assert "lerobot_cve_2026_25874_defaults" in {m.preset_id for m in list_active()}


# ---------------------------------------------------------------------------
# End-to-end @Airlock interception — the CVE scenario
# ---------------------------------------------------------------------------


class TestEndToEndInterception:
    def test_crafted_pickle_blocked_before_sink_runs(self) -> None:
        ran: list[int] = []

        @Airlock(policy=lerobot_cve_2026_25874_defaults())
        def policy_server_recv(payload: bytes, transport: dict | None = None) -> str:
            # Stand-in for LeRobot's pickle.loads() sink — must NEVER run.
            ran.append(len(payload))
            return "deserialized"

        blocked = policy_server_recv(
            payload=_evil_pickle(),
            transport={"authenticated": True, "tls": True},
        )
        assert isinstance(blocked, dict)
        assert blocked.get("status") == "blocked"
        assert blocked.get("block_reason") == "policy_violation"
        assert ran == []  # fail-closed: the sink never executed
        assert any(CVE in h for h in blocked.get("fix_hints", []))
        assert blocked["metadata"]["verdict"] == "deny_pickle_magic"

    def test_base64_pickle_arg_blocked_end_to_end(self) -> None:
        @Airlock(policy=lerobot_cve_2026_25874_defaults())
        def recv(blob: str, transport: dict | None = None) -> str:
            return "ok"

        out = recv(
            blob=base64.b64encode(_evil_pickle()).decode(),
            transport={"authenticated": True, "tls": True},
        )
        assert out["status"] == "blocked"
        assert out["metadata"]["verdict"] == "deny_base64_pickle"

    def test_serialized_bytes_over_unauth_channel_blocked_end_to_end(self) -> None:
        @Airlock(policy=lerobot_cve_2026_25874_defaults())
        def recv(payload: bytes) -> str:
            return "ok"

        out = recv(payload=b"opaque-serialized-blob")
        assert out["status"] == "blocked"
        assert out["metadata"]["verdict"] == "deny_unauthenticated_transport"

    def test_legitimate_call_passes(self) -> None:
        @Airlock(policy=lerobot_cve_2026_25874_defaults())
        def recv(action: str, transport: dict | None = None) -> str:
            return f"did {action}"

        out = recv(action="grasp", transport={"authenticated": True, "tls": True})
        assert out == "did grasp"
