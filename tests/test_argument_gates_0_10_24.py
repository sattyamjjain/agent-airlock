"""Regressions for 0.10.24: the gates that read argument values read only some of them.

- The deserialization guard (step 2.7), the filesystem check (step 3) and the endpoint
  check (step 5) read only keyword arguments, and only top-level ``str`` (or ``bytes``)
  values. A positional argument, a list of paths, a nested mapping, a ``pathlib.Path``, a
  pydantic ``AnyUrl`` and a pickle inside a list all walked past them, and the real tool
  ran. They now read every argument the call passes (``agent_airlock._arg_walk``).
- ``BlockStrategy.HONEYPOT`` turned the filesystem check off: its branch was a bare
  ``pass``, so the real file came back instead of the honeypot's fake one. A honeypot
  reply also wrote no audit record; it now writes one marked ``honeypot``.
- A policy resolver that returned ``None`` ran the call with no policy at all. It now
  refuses the call; ``PERMISSIVE_POLICY`` allows one on purpose.

Pinned after code review, in the same release:

- The walk reads pydantic models and dataclasses the tool's author defined, mapping
  keys, any sequence or set, and ``*args`` under the parameter's own name. It skips the
  run wrapper the context came from and objects from agent frameworks.
- A nested string is a path only by its shape (absolute, ``~``, ``..``) or under a
  path-named key, so ``application/json`` in a headers mapping is not; bytes under
  ``file=`` are a path only when shaped like one, so an upload's content is not.
- A URL is any ``scheme://``, in any case, after whitespace, under any name; URL-named
  parameters include the plurals; a ``file:`` URI is a path.
- A NUL byte in a path is refused instead of raising ``ValueError``.
- The deserialization guard refuses text (protocol 0) pickles and any pickle naming a
  callable, which carry no 0x80 magic, and reads the transport argument for content.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import pickle
import urllib.parse
from collections import UserList, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from pydantic import AnyUrl, BaseModel

from agent_airlock import Airlock, AirlockConfig, AirlockContext
from agent_airlock._arg_walk import MAX_DEPTH, bind_arguments, signature_of
from agent_airlock.filesystem import FilesystemPolicy
from agent_airlock.honeypot import BlockStrategy, HoneypotConfig
from agent_airlock.network import EndpointPolicy
from agent_airlock.policy import PERMISSIVE_POLICY, SecurityPolicy
from agent_airlock.safe_types import UnsafeDeserializationGuard, UnsafeDeserializationVerdict

SECRET = "TOP-SECRET-CONTENT"


def _blocked(result: Any) -> str | None:
    """The block reason when ``result`` is a refusal, else None."""
    if isinstance(result, dict) and result.get("success") is False:
        return str(result.get("block_reason"))
    return None


def _nested(depth: int, leaf: Any) -> Any:
    value = leaf
    for _ in range(depth):
        value = [value]
    return value


def _records(path: Path) -> list[dict[str, Any]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line and not line.startswith("#")]


@dataclass
class _RunWrapper:
    """A run wrapper a framework hands the tool first: it carries the context."""

    context: Any
    workspace_dir: str


@dataclass
class _FrameworkState:
    """Stands in for a framework's own dataclass (a run context, a message)."""

    workspace_dir: str


_FrameworkState.__module__ = "pydantic_ai.tools"


@dataclass
class _CopyRequest:
    """A tool author's own argument type: the model's JSON once validated."""

    source: str


class _ReadRequest(BaseModel):
    path: str


@pytest.fixture
def roots(tmp_path: Path) -> tuple[Path, Path]:
    """An allowed root and a secret file outside it."""
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    (allowed / "ok.txt").write_text("fine")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text(SECRET)
    return allowed, outside / "secret.txt"


class TestThePathGateReadsEveryArgument:
    def test_a_positional_path(self, roots: tuple[Path, Path]) -> None:
        allowed, secret = roots

        @Airlock(config=AirlockConfig(filesystem_policy=FilesystemPolicy([allowed])))
        def read_file(path: str) -> str:
            return Path(path).read_text()

        assert _blocked(read_file(path=str(secret))) == "path_violation"
        assert _blocked(read_file(str(secret))) == "path_violation"

    def test_a_path_inside_a_list_a_tuple_or_a_mapping(self, roots: tuple[Path, Path]) -> None:
        allowed, secret = roots
        config = AirlockConfig(filesystem_policy=FilesystemPolicy([allowed]))

        @Airlock(config=config)
        def read_files(paths: list[str]) -> str:
            return "|".join(Path(p).read_text() for p in paths)

        @Airlock(config=config)
        def export(options: dict[str, Any]) -> str:
            return Path(options["output_file"]).read_text()

        @Airlock(config=config)
        def copy(pair: tuple[str, str]) -> str:
            return Path(pair[0]).read_text()

        assert _blocked(read_files(paths=[str(allowed / "ok.txt"), str(secret)])) == (
            "path_violation"
        )
        assert _blocked(export(options={"output_file": str(secret)})) == "path_violation"
        assert _blocked(copy(pair=(str(secret), "x"))) == "path_violation"

    def test_a_pathlib_path(self, roots: tuple[Path, Path]) -> None:
        allowed, secret = roots

        @Airlock(config=AirlockConfig(filesystem_policy=FilesystemPolicy([allowed])))
        def read_file(path: Path) -> str:
            return path.read_text()

        assert _blocked(read_file(path=secret)) == "path_violation"
        assert read_file(path=allowed / "ok.txt") == "fine"

    def test_bytes_under_a_path_parameter(self, roots: tuple[Path, Path]) -> None:
        allowed, secret = roots

        @Airlock(config=AirlockConfig(filesystem_policy=FilesystemPolicy([allowed])))
        def read_file(path: bytes) -> str:
            return Path(path.decode()).read_text()

        assert _blocked(read_file(path=str(secret).encode())) == "path_violation"

    def test_star_args_are_read(self, roots: tuple[Path, Path]) -> None:
        allowed, secret = roots

        @Airlock(config=AirlockConfig(filesystem_policy=FilesystemPolicy([allowed])))
        def concat(*paths: str) -> str:
            return "|".join(Path(p).read_text() for p in paths)

        assert _blocked(concat(str(allowed / "ok.txt"), str(secret))) == "path_violation"

    def test_an_allowed_path_still_runs_however_it_is_passed(
        self, roots: tuple[Path, Path]
    ) -> None:
        allowed, _ = roots
        config = AirlockConfig(filesystem_policy=FilesystemPolicy([allowed]))

        @Airlock(config=config)
        def read_file(path: str) -> str:
            return Path(path).read_text()

        @Airlock(config=config)
        def read_files(paths: list[str]) -> str:
            return "|".join(Path(p).read_text() for p in paths)

        ok = str(allowed / "ok.txt")
        assert read_file(ok) == "fine"
        assert read_files(paths=[ok, ok]) == "fine|fine"

    def test_input_nested_too_deep_to_read_is_refused(self, roots: tuple[Path, Path]) -> None:
        allowed, secret = roots

        @Airlock(config=AirlockConfig(filesystem_policy=FilesystemPolicy([allowed])))
        def read_any(paths: list[Any]) -> str:
            return "ran"

        result = read_any(paths=_nested(MAX_DEPTH + 2, str(secret)))
        assert _blocked(result) == "path_violation"
        assert "uninspectable_argument" in json.dumps(result)

    def test_a_list_that_contains_itself_is_refused(self, roots: tuple[Path, Path]) -> None:
        allowed, _ = roots
        loop: list[Any] = ["notes"]
        loop.append(loop)

        @Airlock(config=AirlockConfig(filesystem_policy=FilesystemPolicy([allowed])))
        def read_any(paths: list[Any]) -> str:
            return "ran"

        assert _blocked(read_any(paths=loop)) == "path_violation"

    def test_the_run_wrapper_is_not_walked(self, roots: tuple[Path, Path]) -> None:
        """The wrapper the context came from is the host's object, not the model's JSON."""
        allowed, secret = roots

        @Airlock(config=AirlockConfig(filesystem_policy=FilesystemPolicy([allowed])))
        def list_dir(ctx: _RunWrapper, path: str) -> str:
            return "listed"

        wrapper = _RunWrapper(context=AirlockContext(), workspace_dir=str(secret.parent))
        assert list_dir(wrapper, str(allowed)) == "listed"

    def test_a_framework_object_is_not_walked(self, roots: tuple[Path, Path]) -> None:
        allowed, secret = roots

        @Airlock(config=AirlockConfig(filesystem_policy=FilesystemPolicy([allowed])))
        def list_dir(state: Any, path: str) -> str:
            return "listed"

        assert list_dir(_FrameworkState(str(secret.parent)), str(allowed)) == "listed"

    def test_the_tool_authors_model_and_dataclass_are_walked(
        self, roots: tuple[Path, Path]
    ) -> None:
        """FastMCP, PydanticAI and the OpenAI Agents SDK hand a model-typed tool an instance."""
        allowed, secret = roots
        config = AirlockConfig(filesystem_policy=FilesystemPolicy([allowed]))

        @Airlock(config=config)
        def read(req: _ReadRequest) -> str:
            return Path(req.path).read_text()

        @Airlock(config=config)
        def copy(req: _CopyRequest) -> str:
            return "copied"

        assert _blocked(read(req=_ReadRequest(path=str(secret)))) == "path_violation"
        assert _blocked(copy(req=_CopyRequest(source=str(secret)))) == "path_violation"
        assert read(req=_ReadRequest(path=str(allowed / "ok.txt"))) == "fine"

    def test_mapping_keys_and_other_containers(self, roots: tuple[Path, Path]) -> None:
        allowed, secret = roots
        config = AirlockConfig(filesystem_policy=FilesystemPolicy([allowed]))

        @Airlock(config=config)
        def write_files(files: dict[str, str]) -> str:
            return "wrote"

        @Airlock(config=config)
        def read_any(paths: Any) -> str:
            return "ran"

        assert _blocked(write_files(files={str(secret): "x"})) == "path_violation"
        assert _blocked(read_any(paths=deque([str(secret)]))) == "path_violation"
        assert _blocked(read_any(paths=UserList([str(secret)]))) == "path_violation"
        assert _blocked(read_any(paths={"a": str(secret)}.values())) == "path_violation"

    def test_star_args_keep_the_parameters_name(self, roots: tuple[Path, Path]) -> None:
        """A relative name under ``*files`` is read under ``files``, a path-named key."""
        allowed, _ = roots

        @Airlock(config=AirlockConfig(filesystem_policy=FilesystemPolicy([allowed])))
        def concat(*files: str) -> str:
            return "ran"

        assert _blocked(concat("notes.txt")) == "path_violation"  # relative to the cwd

    def test_a_nul_byte_is_refused_not_raised(self, roots: tuple[Path, Path]) -> None:
        allowed, _ = roots

        @Airlock(config=AirlockConfig(filesystem_policy=FilesystemPolicy([allowed])))
        def read_file(path: str) -> str:
            return "ran"

        result = read_file(path=str(allowed) + "/a\x00b")
        assert _blocked(result) == "path_violation"
        assert "invalid_path" in json.dumps(result)

    def test_a_file_uri_is_a_path(self, roots: tuple[Path, Path]) -> None:
        allowed, secret = roots

        @Airlock(config=AirlockConfig(filesystem_policy=FilesystemPolicy([allowed])))
        def open_location(location: str) -> str:
            return "opened"

        assert _blocked(open_location(location="file://" + str(secret))) == "path_violation"


class TestNestedValuesAreNotPathsByAccident:
    """The nested walk must not refuse what plainly is not a path."""

    def test_a_mime_type_in_headers_is_not_a_path(self, roots: tuple[Path, Path]) -> None:
        allowed, _ = roots

        @Airlock(config=AirlockConfig(filesystem_policy=FilesystemPolicy([allowed])))
        def http_get(url: str, headers: dict[str, str]) -> str:
            return "got"

        headers = {"Accept": "application/json", "note": "read and/or write"}
        assert http_get(url="https://api.example.com/v1", headers=headers) == "got"

    def test_a_bare_word_under_a_path_named_key_is_not_a_path(
        self, roots: tuple[Path, Path]
    ) -> None:
        allowed, _ = roots

        @Airlock(config=AirlockConfig(filesystem_policy=FilesystemPolicy([allowed])))
        def search(query: dict[str, str]) -> str:
            return "found"

        assert search(query={"source": "arxiv", "target": "abstracts"}) == "found"

    def test_upload_content_under_file_is_not_a_path(self, roots: tuple[Path, Path]) -> None:
        allowed, secret = roots

        @Airlock(config=AirlockConfig(filesystem_policy=FilesystemPolicy([allowed])))
        def upload(file: bytes) -> str:
            return f"uploaded {len(file)}"

        assert upload(file=b"hello world") == "uploaded 11"
        assert upload(file=bytes(range(256))) == "uploaded 256"
        assert _blocked(upload(file=os.fsencode(secret))) == "path_violation"

    def test_the_async_wrapper_reads_positional_arguments(self, roots: tuple[Path, Path]) -> None:
        allowed, secret = roots

        @Airlock(config=AirlockConfig(filesystem_policy=FilesystemPolicy([allowed])))
        async def read_file(path: str) -> str:
            return Path(path).read_text()

        assert _blocked(asyncio.run(read_file(str(secret)))) == "path_violation"


class TestTheEndpointGateReadsEveryArgument:
    @staticmethod
    def _config() -> AirlockConfig:
        return AirlockConfig(
            endpoint_policies={"fetch": EndpointPolicy(allowed_endpoints=["api.example.com"])}
        )

    def test_a_positional_url(self) -> None:
        @Airlock(config=self._config())
        def fetch(url: str) -> str:
            return f"fetched {url}"

        assert _blocked(fetch("http://169.254.169.254/latest")) == "endpoint_blocked"
        assert fetch("https://api.example.com/v1") == "fetched https://api.example.com/v1"

    def test_url_objects(self) -> None:
        @Airlock(config=self._config())
        def fetch(url: Any) -> str:
            return f"fetched {url}"

        metadata = "http://169.254.169.254/latest"
        assert _blocked(fetch(url=AnyUrl(metadata))) == "endpoint_blocked"
        assert _blocked(fetch(url=urllib.parse.urlparse(metadata))) == "endpoint_blocked"
        assert _blocked(fetch(url=metadata.encode())) == "endpoint_blocked"
        assert fetch(url=AnyUrl("https://api.example.com/v1")).startswith("fetched")

    @pytest.mark.parametrize(
        "address",
        [
            "HTTP://169.254.169.254/latest",
            " http://169.254.169.254/latest",
            "gopher://169.254.169.254:70/_",
            "file:///etc/passwd",
        ],
    )
    def test_any_scheme_in_any_case_under_any_name(self, address: str) -> None:
        @Airlock(config=self._config())
        def fetch(address: str) -> str:
            return "fetched"

        assert _blocked(fetch(address=address)) == "endpoint_blocked"

    def test_url_named_plurals_and_lists(self) -> None:
        @Airlock(config=self._config())
        def fetch(urls: list[str], links: list[str]) -> str:
            return "fetched"

        assert _blocked(fetch(urls=["file:///etc/passwd"], links=[])) == "endpoint_blocked"
        assert fetch(urls=["https://api.example.com/a"], links=[]) == "fetched"

    def test_a_url_inside_a_list(self) -> None:
        @Airlock(config=self._config())
        def fetch(urls: list[str]) -> str:
            return "fetched"

        assert _blocked(fetch(urls=["https://api.example.com/a", "http://10.0.0.5/admin"])) == (
            "endpoint_blocked"
        )


class TestTheDeserializationGuardReadsNestedValues:
    def test_a_positional_or_nested_pickle(self) -> None:
        policy = SecurityPolicy(deserialization_guard=UnsafeDeserializationGuard())

        @Airlock(policy=policy)
        def load_blob(payload: bytes) -> str:
            return "loaded"

        @Airlock(policy=policy)
        def load_blobs(payloads: list[bytes]) -> str:
            return "loaded"

        @Airlock(policy=policy)
        def load_doc(doc: dict[str, Any]) -> str:
            return "loaded"

        blob = pickle.dumps({"a": 1})
        assert _blocked(load_blob(blob)) == "policy_violation"
        assert _blocked(load_blobs(payloads=[b"ok", blob])) == "policy_violation"
        encoded = base64.b64encode(blob).decode()
        assert _blocked(load_doc(doc={"inner": {"data": encoded}})) == "policy_violation"
        assert load_blobs(payloads=[b"plain bytes"]) == "loaded"

    def test_the_guard_names_the_nested_field(self) -> None:
        decision = UnsafeDeserializationGuard().evaluate({"payloads": [b"x", pickle.dumps(1)]})
        assert not decision.allowed
        assert decision.verdict is UnsafeDeserializationVerdict.DENY_PICKLE_MAGIC
        assert decision.matched_field == "payloads[1]"

    def test_input_too_deep_to_read_is_denied(self) -> None:
        decision = UnsafeDeserializationGuard().evaluate({"doc": _nested(MAX_DEPTH + 2, "x")})
        assert not decision.allowed
        assert decision.verdict is UnsafeDeserializationVerdict.DENY_UNINSPECTABLE

    @pytest.mark.parametrize(
        "blob",
        [
            "cos\nsystem\n(S'id'\ntR.",
            pickle.dumps({"a": 1}, protocol=0).decode("latin-1"),
            pickle.dumps({"a": 1}, protocol=0),
        ],
    )
    def test_a_text_pickle_has_no_magic_and_is_still_refused(self, blob: Any) -> None:
        decision = UnsafeDeserializationGuard().evaluate({"blob": blob})
        assert not decision.allowed
        assert decision.verdict is UnsafeDeserializationVerdict.DENY_TEXT_PICKLE

    def test_a_payload_in_the_transport_argument_is_read(self) -> None:
        transport = {"authenticated": True, "tls": True, "note": "cos\nsystem\n(S'id'\ntR."}
        decision = UnsafeDeserializationGuard().evaluate({"transport": transport})
        assert not decision.allowed

    def test_the_transport_declaration_is_still_honoured(self) -> None:
        guard = UnsafeDeserializationGuard(require_authenticated_transport=True)
        transport = {"authenticated": True, "tls": True}
        assert guard.evaluate({"blobs": [b"opaque"], "transport": transport}).allowed
        assert not guard.evaluate({"blobs": [b"opaque"]}).allowed


class TestHoneypotNoLongerTurnsThePathGateOff:
    def test_the_honeypot_answers_instead_of_the_real_file(
        self, roots: tuple[Path, Path], tmp_path: Path
    ) -> None:
        allowed, secret = roots
        log = tmp_path / "audit.jsonl"
        config = AirlockConfig(
            filesystem_policy=FilesystemPolicy([allowed]),
            honeypot_config=HoneypotConfig(strategy=BlockStrategy.HONEYPOT),
            audit_log_path=log,
        )

        @Airlock(config=config)
        def read_file(path: str) -> str:
            return Path(path).read_text()

        result = read_file(path=str(secret))
        assert SECRET not in str(result)
        assert _blocked(result) is None  # the caller sees fake success, by design
        (record,) = _records(log)
        assert record["blocked"] is True
        assert record["block_reason"] == "path_violation"
        assert record["honeypot"] is True

    def test_the_async_honeypot_is_audited_too(
        self, roots: tuple[Path, Path], tmp_path: Path
    ) -> None:
        allowed, secret = roots
        log = tmp_path / "audit.jsonl"
        config = AirlockConfig(
            filesystem_policy=FilesystemPolicy([allowed]),
            honeypot_config=HoneypotConfig(strategy=BlockStrategy.HONEYPOT),
            audit_log_path=log,
        )

        @Airlock(config=config)
        async def read_file(path: str) -> str:
            return Path(path).read_text()

        assert SECRET not in str(asyncio.run(read_file(str(secret))))
        (record,) = _records(log)
        assert record["honeypot"] is True

    def test_soft_block_still_logs_and_proceeds(self, roots: tuple[Path, Path]) -> None:
        allowed, secret = roots
        config = AirlockConfig(
            filesystem_policy=FilesystemPolicy([allowed]),
            honeypot_config=HoneypotConfig(strategy=BlockStrategy.SOFT_BLOCK),
        )

        @Airlock(config=config)
        def read_file(path: str) -> str:
            return Path(path).read_text()

        assert read_file(path=str(secret)) == SECRET

    def test_a_record_without_a_honeypot_carries_no_honeypot_field(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"

        @Airlock(config=AirlockConfig(audit_log_path=log))
        def ping() -> str:
            return "pong"

        ping()
        (record,) = _records(log)
        assert "honeypot" not in record


class TestAResolverThatReturnsNoPolicyRefuses:
    def test_an_unknown_tenant_is_refused(self) -> None:
        policies = {"acme": SecurityPolicy(denied_tools=["*"])}

        @Airlock(policy=lambda ctx: policies.get(ctx.workspace_id or ""))
        def delete_all() -> str:
            return "deleted"

        with AirlockContext(agent_id="a1", workspace_id="acme"):
            assert _blocked(delete_all()) == "policy_violation"
        with AirlockContext(agent_id="a1", workspace_id="unknown-co"):
            result = delete_all()
        assert _blocked(result) == "policy_violation"
        assert "PERMISSIVE_POLICY" in json.dumps(result)

    def test_permissive_policy_allows_on_purpose(self) -> None:
        @Airlock(policy=lambda ctx: PERMISSIVE_POLICY)
        def ping() -> str:
            return "pong"

        assert ping() == "pong"

    def test_no_policy_at_all_is_unchanged(self) -> None:
        @Airlock()
        def ping() -> str:
            return "pong"

        assert ping() == "pong"


class TestTheGatesStayOffWhenUnconfigured:
    def test_deep_input_runs_when_no_gate_reads_values(self) -> None:
        @Airlock()
        def echo(items: list[Any]) -> str:
            return "ran"

        assert echo(items=_nested(MAX_DEPTH + 2, "/etc/passwd")) == "ran"


class TestBindArguments:
    def test_names_positional_star_args_and_kwargs(self) -> None:
        def tool(a: str, *rest: str, b: int = 0, **extra: Any) -> None: ...

        named = bind_arguments(signature_of(tool), ("x", "y", "z"), {"b": 1, "k": "v"})
        assert named == {"a": "x", "rest": ("y", "z"), "b": 1, "k": "v"}

    def test_an_unbindable_call_still_names_every_value(self) -> None:
        def tool(a: str) -> None: ...

        named = bind_arguments(signature_of(tool), ("x", "extra"), {})
        assert named == {"arg[0]": "x", "arg[1]": "extra"}
