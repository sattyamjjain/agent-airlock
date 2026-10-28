"""Regressions for what an independent review of the 0.10.28 call-path fixes found.

- An empty host reaches this machine, and a host allowlist refused it nowhere: the
  connect check skipped an empty host, and a lookup of an empty or missing host admitted
  the loopback or wildcard address it returned. ``http://:PORT/`` got past
  ``allowed_hosts=["api.example.com"]`` to a local service.
- ``block_dns=True`` refused a lookup of an IP literal, which sends no DNS query, so a
  numeric host allowlist with it could not connect through ``urllib``.
- A framework's own pydantic model, which a framework builds from the model's JSON, was
  skipped by steps 2.7, 3 and 5: ``mcp.types.ResourceLink(uri="file:///secret")`` ran.
- A framework class installed as a symlink (``uv --link-mode=symlink``, Bazel, Nix
  per-file links) was never verified, so its run wrapper lost the call's identity.
- The output walk ran ``str()`` on every value inside a container: one that raised escaped
  after the tool ran and before its audit record, and 200,000 numbers took ten times as
  long. An output nested too deeply to mask raised ``RecursionError`` out of the call.
- A generator, ``map`` or coroutine inside a returned dict, list, tuple or set ran later,
  outside the airgap and unmasked: only a top-level one was guarded.
- An argument whose ``repr()`` raised escaped from the audit record after the tool ran.

Every network probe stays on this machine.
"""

from __future__ import annotations

import asyncio
import dataclasses
import importlib
import json
import socket
import sqlite3
import sys
import threading
import time
import types
import typing
import urllib.request
from collections import Counter
from collections.abc import Callable, Generator, Iterator
from pathlib import Path
from typing import Annotated, Any

import pytest
import typing_extensions
from pydantic import BaseModel, BeforeValidator, ConfigDict, RootModel, TypeAdapter, field_validator

import agent_airlock._arg_walk as arg_walk
import agent_airlock.network as network_module
from agent_airlock import Airlock, AirlockConfig
from agent_airlock.context import ContextExtractor
from agent_airlock.filesystem import FilesystemPolicy
from agent_airlock.network import (
    NO_NETWORK_POLICY,
    EndpointPolicy,
    NetworkBlockedError,
    NetworkPolicy,
    network_airgap,
)
from agent_airlock.sanitizer import _LEAF_SEPARATOR, PATTERNS

# TEST-NET-1 (RFC 5737): looked up numerically, never sent anywhere.
ELSEWHERE = "192.0.2.10"
EMAIL = "alice.smith@example.com"
# Assembled, so no secret scanner files this module.
SECRET = "AKIA" + "IOSFODNN7" + "EXAMPLE"
_ALLOWLIST = NetworkPolicy(allowed_hosts=["api.example.com"])


def _reason(result: Any) -> str | None:
    """The block reason when ``result`` is a refusal, else None."""
    if isinstance(result, dict) and result.get("success") is False:
        return str(result.get("block_reason"))
    return None


def _records(path: Path) -> list[dict[str, Any]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line and not line.startswith("#")]


@pytest.fixture(autouse=True)
def _no_airgap_left_open() -> Iterator[None]:
    yield
    left_open = network_module._interceptor_ref_count
    network_module._reset_interceptors()
    assert left_open == 0, "an airgap was left open"


@pytest.fixture
def http_port() -> Iterator[int]:
    """A local HTTP service on 127.0.0.1 that answers every connection with ``ok``."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(16)
    server.settimeout(0.2)
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except OSError:
                continue
            with conn:
                conn.settimeout(1)
                try:
                    conn.recv(4096)
                    conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
                except OSError:
                    pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield server.getsockname()[1]
    finally:
        stop.set()
        thread.join(timeout=2)
        server.close()


def _attempt(connect: Callable[[], Any]) -> str:
    """Run ``connect``: "refused" by the airgap, "unresolved" by the platform, else "connected"."""
    try:
        connect()
    except NetworkBlockedError:
        return "refused"
    except OSError:  # urllib's URLError included: this platform could not reach it
        return "unresolved"
    return "connected"


def _tool_under(policy: NetworkPolicy, connect: Callable[[], Any]) -> Callable[[], Any]:
    @Airlock(config=AirlockConfig(network_policy=policy))
    def tool() -> str:
        return _attempt(connect)

    return tool


def _connect_raw(host: Any, port: int) -> None:
    with socket.socket() as sock:
        sock.settimeout(2)
        sock.connect((host, port))


# ---------------------------------------------------------------------------------------
# An empty host is this machine, and a host allowlist names no such host
# ---------------------------------------------------------------------------------------


class TestAnEmptyHostIsRefusedUnderAHostAllowlist:
    def test_a_connect_to_an_empty_host(self, http_port: int) -> None:
        assert _tool_under(_ALLOWLIST, lambda: _connect_raw("", http_port))() == "refused"

    def test_the_address_a_lookup_of_an_empty_host_returned(self, http_port: int) -> None:
        def connect() -> None:
            address = socket.gethostbyname("")  # the wildcard address, which reaches here
            socket.create_connection((address, http_port), timeout=2).close()

        assert _tool_under(_ALLOWLIST, connect)() == "refused"

    def test_the_address_a_lookup_of_no_host_returned(self, http_port: int) -> None:
        def connect() -> None:
            infos = socket.getaddrinfo(None, http_port, type=socket.SOCK_STREAM)
            family, kind, proto, _name, address = infos[0]
            with socket.socket(family, kind, proto) as sock:
                sock.settimeout(2)
                sock.connect(address)

        assert _tool_under(_ALLOWLIST, connect)() == "refused"

    def test_urllib_with_an_empty_host(self, http_port: int) -> None:
        def fetch() -> None:
            urllib.request.urlopen(f"http://:{http_port}/", timeout=2).read()  # nosec B310

        assert _tool_under(_ALLOWLIST, fetch)() in {"refused", "unresolved"}

    async def test_asyncio_open_connection_to_an_empty_host(self, http_port: int) -> None:
        @Airlock(config=AirlockConfig(network_policy=_ALLOWLIST))
        async def tool() -> str:
            try:
                _reader, writer = await asyncio.open_connection("", http_port)
            except NetworkBlockedError:
                return "refused"
            except OSError:
                return "unresolved"
            writer.close()
            return "connected"

        assert await tool() in {"refused", "unresolved"}

    def test_a_direct_network_airgap_refuses_it_too(self, http_port: int) -> None:
        with network_airgap(_ALLOWLIST):
            assert _attempt(lambda: _connect_raw("", http_port)) == "refused"
            address = socket.gethostbyname("")
            assert _attempt(lambda: _connect_raw(address, http_port)) == "refused"

    def test_control_no_allowlist_lets_an_empty_host_connect(self, http_port: int) -> None:
        assert _tool_under(NetworkPolicy(), lambda: _connect_raw("", http_port))() == ("connected")

    def test_control_a_listed_address_still_connects(self, http_port: int) -> None:
        def connect() -> None:
            socket.create_connection(("127.0.0.1", http_port), timeout=2).close()

        policy = NetworkPolicy(allowed_hosts=["127.0.0.1"])
        assert _tool_under(policy, connect)() == "connected"


# ---------------------------------------------------------------------------------------
# block_dns refuses the lookups that ask DNS, not one of an IP literal
# ---------------------------------------------------------------------------------------


class TestBlockDnsRefusesOnlyLookupsThatAskDns:
    def test_an_allowed_address_is_reachable_with_block_dns(self, http_port: int) -> None:
        policy = NetworkPolicy(allowed_hosts=["127.0.0.1"], block_dns=True)

        @Airlock(config=AirlockConfig(network_policy=policy), return_dict=True)
        def fetch() -> str:
            url = f"http://127.0.0.1:{http_port}/"
            return str(urllib.request.urlopen(url, timeout=2).read().decode())  # nosec B310

        assert fetch()["result"] == "ok"

    def test_a_name_is_still_refused(self) -> None:
        with network_airgap(NetworkPolicy(block_dns=True)), pytest.raises(NetworkBlockedError):
            socket.getaddrinfo("localhost", 80)

    def test_a_reverse_lookup_of_an_address_is_still_refused(self) -> None:
        with network_airgap(NetworkPolicy(block_dns=True)), pytest.raises(NetworkBlockedError):
            socket.gethostbyaddr("127.0.0.1")

    def test_an_address_outside_the_allowlist_is_still_refused(self) -> None:
        policy = NetworkPolicy(allowed_hosts=["127.0.0.1"], block_dns=True)
        with network_airgap(policy), pytest.raises(NetworkBlockedError):
            socket.getaddrinfo(ELSEWHERE, 443, flags=socket.AI_NUMERICHOST)

    def test_no_network_still_refuses_a_numeric_lookup(self) -> None:
        with network_airgap(NO_NETWORK_POLICY), pytest.raises(NetworkBlockedError):
            socket.getaddrinfo("127.0.0.1", 443, flags=socket.AI_NUMERICHOST)


# ---------------------------------------------------------------------------------------
# A fake agent framework, installed from a RECORD the way pip, uv or Bazel lay it out
# ---------------------------------------------------------------------------------------

_FRAMEWORK = "smolagents"  # a FRAMEWORK_PACKAGES name no CI job installs
_RUN_MODULE = (
    "from dataclasses import dataclass\n"
    "from typing import Any\n\n"
    "from pydantic import BaseModel\n\n\n"
    "class Caller(BaseModel):\n"
    "    agent_id: str\n\n\n"
    "@dataclass\n"
    "class RunCtx:\n"
    "    context: Any\n\n\n"
    "@dataclass\n"
    "class TypedRunCtx:\n"
    "    context: Caller\n"
)


def _install(tmp_path: Path, layout: str) -> None:
    """Lay out a ``smolagents`` distribution whose ``tools.py`` defines ``RunCtx``."""
    site = tmp_path / "site"
    store = tmp_path / "store"
    package = site / _FRAMEWORK
    store.mkdir()
    (store / "tools.py").write_text(_RUN_MODULE)
    (store / "__init__.py").write_text("")
    if layout == "package-symlink":
        site.mkdir()
        package.symlink_to(store, target_is_directory=True)
    else:
        package.mkdir(parents=True)
        (package / "__init__.py").write_text("")
        if layout == "file-symlink":
            (package / "tools.py").symlink_to(store / "tools.py")
        else:
            (package / "tools.py").write_text(_RUN_MODULE)
    info = site / f"{_FRAMEWORK}-1.0.dist-info"
    info.mkdir()
    (info / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {_FRAMEWORK}\nVersion: 1.0\n")
    record = [f"{_FRAMEWORK}/__init__.py,,", f"{_FRAMEWORK}/tools.py,,"]
    record += [f"{info.name}/METADATA,,", f"{info.name}/RECORD,,"]
    (info / "RECORD").write_text("\n".join(record) + "\n")


@pytest.fixture
def framework(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Callable[[str], types.ModuleType]]:
    """Install the fake framework in a given layout and return its ``tools`` module."""

    def purge() -> None:
        for name in [n for n in sys.modules if n == _FRAMEWORK or n.startswith(_FRAMEWORK + ".")]:
            del sys.modules[name]
        arg_walk._distribution_files.cache_clear()
        importlib.invalidate_caches()

    def install(layout: str) -> types.ModuleType:
        _install(tmp_path, layout)
        monkeypatch.syspath_prepend(str(tmp_path / "site"))
        purge()
        return importlib.import_module(f"{_FRAMEWORK}.tools")

    yield install
    purge()


class TestFrameworkVerificationFollowsSymlinks:
    @pytest.mark.parametrize("layout", ["file-symlink", "package-symlink", "copy"])
    def test_a_framework_run_wrapper_is_verified(
        self, framework: Callable[[str], types.ModuleType], layout: str
    ) -> None:
        tools = framework(layout)
        wrapper = tools.RunCtx(context=types.SimpleNamespace(agent_id="agent-7", roles=["reader"]))

        assert arg_walk.is_framework_object(wrapper)
        assert ContextExtractor.extract_from_args((wrapper,), {}).agent_id == "agent-7"

    def test_control_a_module_the_record_does_not_list_is_not_verified(
        self, framework: Callable[[str], types.ModuleType], tmp_path: Path
    ) -> None:
        framework("copy")
        extra = tmp_path / "site" / _FRAMEWORK / "unlisted.py"
        extra.write_text(_RUN_MODULE)
        importlib.invalidate_caches()
        unlisted = importlib.import_module(f"{_FRAMEWORK}.unlisted").RunCtx

        assert not arg_walk.is_framework_object(unlisted(context=None))

    def test_limit_a_framework_dataclass_built_from_json_is_trusted(
        self, framework: Callable[[str], types.ModuleType]
    ) -> None:
        """Pydantic builds a standard-library dataclass from JSON, and a pydantic-built
        instance is indistinguishable from the framework's own. A framework that built a
        parameter typed as another framework's run-context dataclass from the model's JSON,
        and passed it first and positionally, would let the model write the identity. No
        shipped framework does: each injects its own and keeps it out of the schema."""
        tools = framework("copy")
        built = TypeAdapter(tools.TypedRunCtx).validate_python({"context": {"agent_id": "forged"}})

        assert ContextExtractor.extract_from_args((built,), {}).agent_id == "forged"


# ---------------------------------------------------------------------------------------
# A framework's own pydantic model is model JSON: steps 2.7, 3 and 5 walk it
# ---------------------------------------------------------------------------------------


@pytest.fixture
def roots(tmp_path: Path) -> tuple[Path, Path]:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    (allowed / "ok.txt").write_text("fine")
    secret_dir = tmp_path / "secret"
    secret_dir.mkdir()
    (secret_dir / "key.pem").write_text("key")
    return allowed, secret_dir / "key.pem"


class TestAFrameworkModelIsWalkedWhereItsClassIsNamed:
    """Pydantic builds a framework's own model from the model's JSON only where the tool's
    annotation names its class. There it is walked (``mcp.types.ResourceLink`` ran until
    0.10.28); anywhere else it is the host's or the framework's, a LangGraph state's chat
    history or a RAG document, and walking it read that history as tool arguments."""

    @staticmethod
    def _tool(allowed: Path, annotation: Any, *, endpoints: bool = False) -> Callable[..., Any]:
        policies = {"tool": EndpointPolicy(allowed_endpoints=["api.example.com"])}
        config = AirlockConfig(
            filesystem_policy=FilesystemPolicy(allowed_roots=[allowed]),
            endpoint_policies=policies if endpoints else {},
        )

        def tool(text: str, item: Any) -> str:
            return "ran"

        tool.__annotations__["item"] = annotation  # resolved, as a real annotation would be
        return Airlock(config=config, return_dict=True)(tool)

    def test_a_resource_link_parameter_to_a_file_outside_the_roots(
        self, roots: tuple[Path, Path]
    ) -> None:
        mcp_types = pytest.importorskip("mcp.types")
        allowed, secret = roots
        link = mcp_types.ResourceLink.model_validate(
            {"type": "resource_link", "uri": secret.as_uri(), "name": "k"}
        )

        assert arg_walk.is_framework_object(link)
        tool = self._tool(allowed, mcp_types.ResourceLink)
        assert _reason(tool(text="t", item=link)) == "path_violation"
        assert _reason(
            self._tool(allowed, list[mcp_types.ResourceLink])(text="t", item=[link])
        ) == ("path_violation")

    def test_control_the_same_link_inside_the_roots(self, roots: tuple[Path, Path]) -> None:
        mcp_types = pytest.importorskip("mcp.types")
        allowed, _secret = roots
        link = mcp_types.ResourceLink.model_validate(
            {"type": "resource_link", "uri": (allowed / "ok.txt").as_uri(), "name": "k"}
        )

        assert self._tool(allowed, mcp_types.ResourceLink)(text="t", item=link)["result"] == "ran"

    @pytest.mark.parametrize(
        "turn", ["https://intranet.corp/wiki", "/etc/passwd has the error"], ids=["url", "path"]
    )
    def test_chat_history_in_host_state_is_not_walked(
        self, roots: tuple[Path, Path], turn: str
    ) -> None:
        mcp_types = pytest.importorskip("mcp.types")
        allowed, _secret = roots
        history = {"messages": [mcp_types.TextContent(type="text", text=turn)]}

        in_state = self._tool(allowed, dict, endpoints=True)
        injected = self._tool(allowed, Any, endpoints=True)
        assert in_state(text="t", item=history)["result"] == "ran"
        assert injected(text="t", item=history["messages"][0])["result"] == "ran"

    def test_control_the_same_turn_written_as_json_is_walked(
        self, roots: tuple[Path, Path]
    ) -> None:
        allowed, _secret = roots
        for turn, refusal in (
            ("/etc/passwd", "path_violation"),
            ("https://x.corp/", "endpoint_blocked"),
        ):
            history = {"messages": [{"type": "text", "text": turn}]}
            tool = self._tool(allowed, dict, endpoints=True)
            assert _reason(tool(text="t", item=history)) == refusal

    def test_a_model_named_inside_the_tools_own_model_is_walked(
        self, roots: tuple[Path, Path]
    ) -> None:
        mcp_types = pytest.importorskip("mcp.types")
        allowed, secret = roots

        class Request(BaseModel):
            link: mcp_types.ResourceLink  # type: ignore[name-defined]

        link = mcp_types.ResourceLink.model_validate(
            {"type": "resource_link", "uri": secret.as_uri(), "name": "k"}
        )
        tool = self._tool(allowed, Request)
        assert _reason(tool(text="t", item=Request(link=link))) == "path_violation"

    @pytest.mark.parametrize(
        "shape",
        ["typed-dict", "new-type", "type-var-bound", "type-alias", "validator", "validated-model"],
    )
    def test_every_annotation_that_builds_a_link_names_it(
        self, roots: tuple[Path, Path], shape: str
    ) -> None:
        """typing_extensions' TypedDict (pydantic's on Python 3.10 and 3.11), a NewType, a
        bound TypeVar and a type alias name the model they build; a validator, in
        ``Annotated`` or on a model, may build any model, so it names every one. Each of
        these let a pydantic-built ``ResourceLink`` run until the review's re-check."""
        mcp_types = pytest.importorskip("mcp.types")
        allowed, secret = roots
        link_type = mcp_types.ResourceLink
        link = link_type.model_validate(
            {"type": "resource_link", "uri": secret.as_uri(), "name": "k"}
        )

        class Validated(BaseModel):
            link: Any

            @field_validator("link", mode="before")
            @classmethod
            def build(cls, value: Any) -> Any:
                return value

        annotation, item = {
            "typed-dict": (typing_extensions.TypedDict("Box", {"link": link_type}), {"link": link}),
            "new-type": (typing.NewType("Link", link_type), link),
            "type-var-bound": (typing.TypeVar("L", bound=link_type), link),
            "type-alias": (typing_extensions.TypeAliasType("LinkAlias", link_type), link),
            "validator": (Annotated[Any, BeforeValidator(lambda value: value)], link),
            "validated-model": (Validated, Validated(link=link)),
        }[shape]

        assert _reason(self._tool(allowed, annotation)(text="t", item=item)) == "path_violation"

    def test_a_typed_state_the_framework_injects_is_not_walked(
        self, roots: tuple[Path, Path]
    ) -> None:
        """LangChain leaves out of a tool's schema, and fills itself, a parameter whose
        ``Annotated`` carries an ``InjectedToolArg`` (LangGraph's ``InjectedState``
        included), so the model never writes it, however its type is declared."""
        mcp_types = pytest.importorskip("mcp.types")
        allowed, _secret = roots

        class InjectedToolArg:  # langchain_core's base, which LangChain checks by MRO
            pass

        class InjectedState(InjectedToolArg):
            pass

        # Functional syntax keeps the annotation an object: class syntax would make it a
        # string naming a local, which this module's `from __future__` import leaves unresolved.
        state_type = typing.TypedDict(  # type: ignore[operator]  # noqa: UP013
            "State", {"messages": list[mcp_types.TextContent]}
        )
        history = {"messages": [mcp_types.TextContent(type="text", text="/etc/passwd")]}

        injected = self._tool(allowed, Annotated[state_type, InjectedState])
        assert injected(text="t", item=history)["result"] == "ran"
        unmarked = self._tool(allowed, state_type)  # control: the model writes this one
        assert _reason(unmarked(text="t", item=history)) == "path_violation"

    def test_annotations_that_do_not_resolve_name_every_model(self) -> None:
        def tool(item: NoSuchType) -> str:  # type: ignore[name-defined]  # noqa: F821
            return "ran"

        assert arg_walk.named_models(tool) is None  # the walk then reads every model

    def test_limit_a_framework_dataclass_is_not_walked(
        self, roots: tuple[Path, Path], framework: Callable[[str], types.ModuleType]
    ) -> None:
        """Run contexts are framework dataclasses (pydantic-ai's ``RunContext``,
        LangChain's ``ToolRuntime``): walking them would read the run's messages and the
        host's state as if the model wrote them, so a framework dataclass is not walked,
        even one a framework built from the model's JSON."""
        allowed, secret = roots
        tools = framework("copy")

        assert (
            self._tool(allowed, tools.RunCtx)(text="t", item=tools.RunCtx(str(secret)))["result"]
            == "ran"
        )


# ---------------------------------------------------------------------------------------
# Reading the output never raises out of the call, and skips what no detector can match
# ---------------------------------------------------------------------------------------


class _NoText:
    """An object whose text form raises, like an ORM row bound to a closed session."""

    def __str__(self) -> str:
        raise RuntimeError("detached instance")

    def __repr__(self) -> str:
        return "<_NoText>"


class _NoRepr:
    def __repr__(self) -> str:
        raise RuntimeError("no repr")


class _CountingFloat(float):
    calls = 0

    def __str__(self) -> str:
        type(self).calls += 1
        return super().__str__()


class _CountingInt(int):
    calls = 0

    def __str__(self) -> str:
        type(self).calls += 1
        return super().__str__()


def _nest(depth: int) -> list[Any]:
    value: list[Any] = [EMAIL]
    for _ in range(depth):
        value = [value]
    return value


class TestReadingTheOutputNeverRaisesOutOfTheCall:
    def test_a_value_whose_text_raises_inside_a_container(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        ran: list[str] = []

        @Airlock(config=AirlockConfig(audit_log_path=log), return_dict=True)
        def delete_rows(table: str) -> dict[str, Any]:
            ran.append(table)
            return {"deleted": [_NoText()], "note": EMAIL}

        response = delete_rows(table="users")

        assert ran == ["users"]
        assert response["success"] is True
        assert EMAIL not in json.dumps(response["result"]["note"])
        assert any("_NoText" in w and "could not be read" in w for w in response["warnings"])
        assert [r["blocked"] for r in _records(log)] == [False]

    def test_a_top_level_value_whose_text_raises(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        value = _NoText()

        @Airlock(config=AirlockConfig(audit_log_path=log), return_dict=True)
        def tool() -> Any:
            return value

        response = tool()

        assert response["result"] is value
        assert any("could not be read" in w for w in response["warnings"])
        assert [r["blocked"] for r in _records(log)] == [False]

    def test_an_argument_whose_repr_raises_is_audited(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"

        @Airlock(config=AirlockConfig(audit_log_path=log))
        def tool(row: Any) -> str:
            return "done"

        assert tool(row=_NoRepr()) == "done"
        assert _records(log)[0]["args_preview"]["row"] == "<_NoRepr>"

    def test_an_output_nested_too_deeply_to_mask_is_refused(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"

        @Airlock(config=AirlockConfig(audit_log_path=log))
        def tool(depth: int) -> Any:
            return _nest(depth)

        assert _reason(tool(depth=5000)) == "output_unreadable"
        assert _records(log)[-1]["block_reason"] == "output_unreadable"
        masked = tool(depth=50)  # control: deep, but not past what the walk can rebuild
        assert EMAIL not in json.dumps(masked)

    def test_a_container_that_raises_while_read_is_refused(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"

        class Closed(list):  # type: ignore[type-arg]
            def __iter__(self) -> Iterator[Any]:
                raise RuntimeError("cursor closed")

        @Airlock(config=AirlockConfig(audit_log_path=log))
        def tool() -> Any:
            return {"rows": Closed([1])}

        assert _reason(tool()) == "output_unreadable"
        assert _records(log)[-1]["block_reason"] == "output_unreadable"

    def test_numbers_no_detector_can_match_are_not_turned_into_text(self) -> None:
        _CountingFloat.calls = _CountingInt.calls = 0
        values = [_CountingFloat(1.5), _CountingInt(12_345_678), _CountingInt(-99_999_999)]

        response = Airlock(return_dict=True)(lambda: {"values": values})()

        assert response["result"]["values"] is values
        assert (_CountingFloat.calls, _CountingInt.calls) == (0, 0)

    def test_a_card_number_in_a_float_is_still_read(self) -> None:
        """A float holds every integer up to 2**53 exactly: a float64 column of card
        numbers is still reported (the fast path first skipped every float)."""
        response = Airlock(return_dict=True)(lambda: {"card": 4111111111111111.0})()

        assert any(
            w.endswith("in float inside dict output; not masked") for w in response["warnings"]
        )

    def test_a_large_bytes_value_is_read_from_its_start_quickly(self) -> None:
        """Bytes are decoded, not escaped into their repr, and one leaf's text is cut
        short: a 5 MB image in a dict took 2.4 seconds per call."""
        blob = SECRET.encode() + bytes(5 * 1024 * 1024)

        start = time.perf_counter()
        response = Airlock(return_dict=True)(lambda: {"mime": "image/png", "data": blob})()
        elapsed = time.perf_counter() - start

        assert response["result"]["data"] is blob
        assert any("in bytes inside dict output" in w for w in response["warnings"])
        assert elapsed < 1.0, f"{elapsed:.2f}s"

    def test_control_a_long_integer_is_still_read(self) -> None:
        response = Airlock(return_dict=True)(lambda: {"card": 4111111111111111})()

        assert any(
            w.endswith("in int inside dict output; not masked") for w in response["warnings"]
        )

    def test_no_detector_matches_eight_digits(self) -> None:
        """The floor the integer skip relies on: the shortest digit-only detector, a US
        social security number, needs nine digits. A detector added with fewer fails here."""
        text = _LEAF_SEPARATOR.join(["12345678", "-99999999", "+44999999", "00000000"])
        for pattern in PATTERNS.values():
            assert pattern.search(text) is None, pattern.pattern


# ---------------------------------------------------------------------------------------
# A deferred value inside a returned container runs under the call's guards
# ---------------------------------------------------------------------------------------


def _lookup(_index: int = 0) -> str:
    try:
        socket.getaddrinfo(ELSEWHERE, 443, flags=socket.AI_NUMERICHOST)
    except NetworkBlockedError:
        return f"refused {EMAIL}"
    return f"allowed {EMAIL}"


@dataclasses.dataclass(frozen=True)
class _Page:
    rows: Any


class _PageModel(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)
    rows: Any


def _no_network(**kwargs: Any) -> AirlockConfig:
    return AirlockConfig(network_policy=NO_NETWORK_POLICY, **kwargs)


class TestADeferredValueInsideAResultIsGuarded:
    @pytest.mark.parametrize(
        ("make", "reach"),
        [
            pytest.param(
                lambda: {"status": "ok", "rows": (_lookup() for _ in range(1))},
                lambda r: list(r["rows"]),
                id="generator-in-dict",
            ),
            pytest.param(
                lambda: ("summary", map(_lookup, [0])),
                lambda r: list(r[1]),
                id="map-in-tuple",
            ),
            pytest.param(
                lambda: [[filter(None, map(_lookup, [0]))]],
                lambda r: list(r[0][0]),
                id="filter-two-lists-down",
            ),
        ],
    )
    def test_it_runs_inside_the_airgap_and_is_masked(
        self, make: Callable[[], Any], reach: Callable[[Any], list[str]]
    ) -> None:
        items = reach(Airlock(config=_no_network())(make)())

        assert len(items) == 1
        assert items[0].startswith("refused ")
        assert EMAIL not in items[0]

    async def test_a_coroutine_in_a_list(self) -> None:
        async def body() -> str:
            return _lookup()

        @Airlock(config=_no_network())
        def tool() -> Any:
            return [body()]

        value = await tool()[0]
        assert value.startswith("refused ") and EMAIL not in value

    def test_it_is_airgapped_with_output_masking_off(self) -> None:
        rows = Airlock(config=_no_network(sanitize_output=False))(
            lambda: {"rows": map(_lookup, [0])}
        )()["rows"]

        assert list(rows) == [f"refused {EMAIL}"]

    def test_inside_an_item_a_stream_yields(self) -> None:
        @Airlock(config=_no_network())
        def tool() -> Generator[dict[str, Any], None, None]:
            yield {"rows": map(_lookup, [0])}

        (item,) = list(tool())
        (row,) = list(item["rows"])
        assert row.startswith("refused ") and EMAIL not in row

    def test_a_cycle_is_rebuilt_through_its_back_reference(self) -> None:
        def make() -> dict[str, Any]:
            result: dict[str, Any] = {"rows": map(_lookup, [0])}
            result["self"] = result
            return result

        result = Airlock(config=_no_network())(make)()

        assert result["self"] is result
        assert list(result["self"]["rows"])[0].startswith("refused ")

    @pytest.mark.parametrize("shape", ["dataclass", "model"])
    def test_inside_a_returned_dataclass_or_model(self, shape: str) -> None:
        def make() -> Any:
            rows = (_lookup() for _ in range(1))
            return _Page(rows=rows) if shape == "dataclass" else _PageModel(rows=rows)

        page = Airlock(config=_no_network())(make)()

        (row,) = list(page.rows)
        assert row.startswith("refused ") and EMAIL not in row

    def test_a_counter_beside_one_keeps_its_counts(self) -> None:
        """A dict is refilled key by key: ``Counter.update`` adds to a count instead of
        setting it, so a rebuilt ``Counter`` read ``{('a', 2): 1}`` until the review."""
        words = ["a", "b", "a"]
        result = Airlock(config=_no_network())(
            lambda: {"counts": Counter(words), "upper": map(str.upper, words)}
        )()

        assert result["counts"] == Counter({"a": 2, "b": 1})
        assert list(result["upper"]) == ["A", "B", "A"]

    def test_a_model_overriding_iter_is_read_by_its_fields(self, tmp_path: Path) -> None:
        """The pydantic docs show a RootModel over a list with its own ``__iter__``; the
        guard read fields through that, and refused a result holding nothing deferred."""

        class Pets(RootModel[list[str]]):
            def __iter__(self) -> Iterator[str]:  # type: ignore[override]
                return iter(self.root)

        config = AirlockConfig(
            filesystem_policy=FilesystemPolicy(allowed_roots=[tmp_path]),
            network_policy=NO_NETWORK_POLICY,
        )

        @Airlock(config=config)
        def adopt(pets: Any) -> Any:  # walked either way: Pets is the tool author's model
            return Pets([*pets.root, "fish"])

        assert list(adopt(pets=Pets(["dog", "cat"]))) == ["dog", "cat", "fish"]

    def test_control_a_result_without_one_keeps_its_identity(self) -> None:
        value = {"rows": [[1, 2], (3, 4)], "ok": True}
        assert Airlock(config=_no_network())(lambda: value)() is value

    def test_a_database_cursor_comes_back_as_its_masked_rows(self) -> None:
        """A cursor is a lazy iterator: its rows are produced after the call, so they are
        produced under the call's guards, and the cursor's own API is gone. Return
        ``cursor.fetchall()`` to hand back a list."""
        con = sqlite3.connect(":memory:")
        con.execute("create table t(email text)")
        con.execute("insert into t values (?)", (EMAIL,))

        result = Airlock()(lambda: con.execute("select email from t"))()

        assert not isinstance(result, sqlite3.Cursor)
        (row,) = list(result)
        assert EMAIL not in row[0]
        con.close()
