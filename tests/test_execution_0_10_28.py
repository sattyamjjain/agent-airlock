"""Regressions for the execution-path fixes in 0.10.28: the airgap, deferred results,
output masking and the audit record.

- The network airgap kept its policy in a ``threading.local``. Two airgapped tools
  interleaved on one event-loop thread left each other without it (egress allowed), and
  while one awaited inside its airgap, the host's own coroutines were refused. It now
  lives in a ContextVar, one per thread and asyncio task.
- An allow-egress ``NetworkPolicy`` on ``AirlockConfig`` (a host or port allowlist,
  ``block_dns``) was never applied: ``@Airlock`` entered the airgap only when
  ``allow_egress`` was False. Nested airgaps now intersect, and a listed name admits the
  addresses its lookup returned, in that call only.
- The airgap intercepted only ``connect`` / ``connect_ex`` / ``getaddrinfo``: a UDP
  datagram, ``gethostbyname`` and the like, and asyncio's ``loop.getaddrinfo`` (run in
  an executor thread) went out under ``NO_NETWORK_POLICY``.
- A sync tool's coroutine, or a lazy iterator such as ``map``, ran after ``@Airlock``
  returned: outside the airgap, without the call's context, and unmasked.
- The audit ``result_preview`` was written unmasked; dict keys, and values the walk
  cannot rebuild (bytes, models, dataclasses...), were neither masked nor reported, and
  a container referenced twice was masked only at its first reference.
- A ``network_blocked`` audit record had no agent or session id, and a stream refused in
  the middle of iteration wrote no record of the refusal.

Every network probe stays on this machine: a numeric ``getaddrinfo`` (no DNS query), a
connection or datagram to 127.0.0.1, or a lookup of ``localhost`` / 127.0.0.1.
"""

from __future__ import annotations

import asyncio
import io
import json
import socket
import sys
import threading
from collections import UserDict, deque
from collections.abc import AsyncIterator, Callable, Generator, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

import agent_airlock.network as network_module
from agent_airlock import Airlock, AirlockConfig, AirlockContext, get_current_context
from agent_airlock.filesystem import FilesystemPolicy, PathValidationError, validate_path
from agent_airlock.network import (
    HTTPS_ONLY_POLICY,
    INTERNAL_ONLY_POLICY,
    NO_NETWORK_POLICY,
    NetworkBlockedError,
    NetworkPolicy,
    _get_current_policy,
    network_airgap,
)
from agent_airlock.sanitizer import sanitize_structured

# TEST-NET-1 (RFC 5737): looked up numerically, never sent anywhere.
ELSEWHERE = "192.0.2.10"
# Assembled, so no secret scanner files this module.
SECRET = "AKIA" + "IOSFODNN7" + "EXAMPLE"
EMAIL = "alice.smith@example.com"
_NO_EGRESS = NetworkPolicy(allow_egress=False)


def _lookup(host: str = ELSEWHERE) -> str:
    """Look ``host`` up numerically, so no DNS query is made: "allowed" or "refused"."""
    try:
        socket.getaddrinfo(host, 443, flags=socket.AI_NUMERICHOST)
    except NetworkBlockedError:
        return "refused"
    return "allowed"


def _connect(port: int, host: str = "127.0.0.1") -> str:
    """Open a TCP connection on this machine: "refused" by the airgap, else "admitted"."""
    sock = socket.socket()
    sock.settimeout(1)
    try:
        sock.connect((host, port))
    except NetworkBlockedError:
        return "refused"
    except OSError:
        return "admitted"  # the airgap let it through; nothing listens there
    finally:
        sock.close()
    return "admitted"


def _datagram(port: int = 9) -> str:
    """Send a UDP datagram to this machine: "refused" by the airgap, else "admitted"."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(b"x", ("127.0.0.1", port))
    except NetworkBlockedError:
        return "refused"
    finally:
        sock.close()
    return "admitted"


def _send_datagram() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(b"x", ("127.0.0.1", 9))
    finally:
        sock.close()


def _send_datagram_by_sendmsg() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendmsg([b"x"], [], 0, ("127.0.0.1", 9))
    finally:
        sock.close()


def _config(policy: NetworkPolicy | None = None, **kwargs: Any) -> AirlockConfig:
    return AirlockConfig(network_policy=policy, **kwargs)


def _records(path: Path) -> list[dict[str, Any]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line and not line.startswith("#")]


async def _run_in_shape(shape: str, config: AirlockConfig, probe: Callable[[], str]) -> str:
    """Run ``probe`` as the body of a tool of the given shape, under ``config``."""
    if shape == "sync":

        @Airlock(config=config)
        def sync_tool() -> str:
            return probe()

        return str(sync_tool())
    if shape == "async":

        @Airlock(config=config)
        async def async_tool() -> str:
            return probe()

        return str(await async_tool())
    if shape == "stream":

        @Airlock(config=config)
        def stream_tool() -> Generator[str, None, None]:
            yield probe()

        return str(next(iter(stream_tool())))

    @Airlock(config=config)
    async def async_stream_tool() -> AsyncIterator[str]:
        yield probe()

    return str([item async for item in async_stream_tool()][0])


_SHAPES = ["sync", "async", "stream", "async-stream"]


@pytest.fixture(autouse=True)
def _no_airgap_left_open() -> Iterator[None]:
    yield
    left_open = network_module._interceptor_ref_count
    network_module._reset_interceptors()
    assert left_open == 0, "an airgap was left open"


class TestTheAirgapFollowsEachCall:
    """The policy lives in a ContextVar: one per thread and per asyncio task."""

    @pytest.mark.parametrize("leaver_enters_first", [True, False], ids=["leaver", "holder"])
    @pytest.mark.parametrize("holder_task_first", [True, False], ids=["gather-hl", "gather-lh"])
    async def test_a_call_keeps_its_airgap_when_another_call_leaves_its_own(
        self, leaver_enters_first: bool, holder_task_first: bool
    ) -> None:
        leaver_in = asyncio.Event()
        holder_in = asyncio.Event()
        leaver_out = asyncio.Event()

        @Airlock(config=_config(_NO_EGRESS))
        async def leaver() -> str:
            leaver_in.set()
            await holder_in.wait()
            return "left"

        @Airlock(config=_config(_NO_EGRESS))
        async def holder() -> str:
            holder_in.set()
            await leaver_out.wait()
            return _lookup()

        async def run_leaver() -> str:
            if not leaver_enters_first:
                await holder_in.wait()
            result = await leaver()
            leaver_out.set()
            return str(result)

        async def run_holder() -> str:
            if leaver_enters_first:
                await leaver_in.wait()
            return str(await holder())

        if holder_task_first:
            held, left = await asyncio.wait_for(asyncio.gather(run_holder(), run_leaver()), 5)
        else:
            left, held = await asyncio.wait_for(asyncio.gather(run_leaver(), run_holder()), 5)

        assert left == "left"
        assert held == "refused"
        assert _get_current_policy() is None

    async def test_the_hosts_own_coroutines_run_free_while_a_tool_waits(self) -> None:
        tool_in = asyncio.Event()
        host_done = asyncio.Event()

        @Airlock(config=_config(_NO_EGRESS))
        async def tool() -> str:
            tool_in.set()
            await host_done.wait()
            return _lookup()

        async def host() -> str:
            await tool_in.wait()
            try:
                return _lookup()
            finally:
                host_done.set()

        from_tool, from_host = await asyncio.wait_for(asyncio.gather(tool(), host()), 5)

        assert from_tool == "refused"
        assert from_host == "allowed"

    def test_a_sync_tool(self) -> None:
        @Airlock(config=_config(_NO_EGRESS))
        def tool() -> str:
            return _lookup()

        assert tool() == "refused"
        assert _lookup() == "allowed"

    async def test_an_airgap_outlives_a_nested_one(self) -> None:
        @Airlock(config=_config(_NO_EGRESS))
        async def inner() -> str:
            return _lookup()

        @Airlock(config=_config(_NO_EGRESS))
        async def outer() -> tuple[str, str]:
            got = await inner()
            return str(got), _lookup()

        assert await outer() == ("refused", "refused")
        assert _lookup() == "allowed"

    def test_nested_airgaps_intersect(self) -> None:
        with network_airgap(_NO_EGRESS):
            with network_airgap(NetworkPolicy()):
                assert _lookup() == "refused"
            with network_airgap(INTERNAL_ONLY_POLICY):
                assert _lookup("127.0.0.1") == "refused"
        with network_airgap(INTERNAL_ONLY_POLICY):
            assert _lookup("127.0.0.1") == "allowed"  # control: the policy on its own
            with network_airgap(NetworkPolicy(allowed_hosts=["10.0.0.1"])):
                assert _lookup("127.0.0.1") == "refused"
                assert _lookup("10.0.0.1") == "refused"
        assert _get_current_policy() is None

    def test_an_inner_call_cannot_widen_the_outer_calls_airgap(self) -> None:
        @Airlock(config=_config(INTERNAL_ONLY_POLICY))
        def inner() -> str:
            return _lookup("127.0.0.1")

        @Airlock(config=_config(_NO_EGRESS))
        def outer() -> tuple[str, str]:
            return str(inner()), _lookup("127.0.0.1")

        assert inner() == "allowed"  # control: the inner policy admits 127.0.0.1 alone
        assert outer() == ("refused", "refused")

    async def test_the_host_runs_free_while_an_async_stream_step_waits(self) -> None:
        step_in = asyncio.Event()
        host_done = asyncio.Event()

        @Airlock(config=_config(_NO_EGRESS))
        async def stream() -> AsyncIterator[str]:
            yield _lookup()
            step_in.set()
            await host_done.wait()
            yield _lookup()

        async def consume() -> list[str]:
            return [item async for item in stream()]

        async def host() -> str:
            await step_in.wait()
            try:
                return _lookup()
            finally:
                host_done.set()

        items, from_host = await asyncio.wait_for(asyncio.gather(consume(), host()), 5)

        assert items == ["refused", "refused"]
        assert from_host == "allowed"

    async def test_a_sync_stream_steps_inside_the_airgap_from_any_task(self) -> None:
        @Airlock(config=_config(_NO_EGRESS))
        def stream() -> Generator[str, None, None]:
            yield _lookup()
            yield _lookup()

        async def step(gen: Iterator[str]) -> str:
            return next(gen)

        gen = stream()
        assert next(gen) == "refused"
        assert _lookup() == "allowed"  # between steps the consumer runs free
        assert await asyncio.create_task(step(gen)) == "refused"

    async def test_a_sync_tool_in_an_executor_leaves_the_loop_free(self) -> None:
        entered = threading.Event()
        release = threading.Event()

        @Airlock(config=_config(_NO_EGRESS))
        def tool() -> str:
            entered.set()
            release.wait(5)
            return _lookup()

        loop = asyncio.get_running_loop()
        pending = loop.run_in_executor(None, tool)
        try:
            assert await loop.run_in_executor(None, entered.wait, 5)
            from_loop = _lookup()
        finally:
            release.set()

        assert await asyncio.wait_for(pending, 5) == "refused"
        assert from_loop == "allowed"

    async def test_a_task_the_tool_creates_is_airgapped(self) -> None:
        async def child() -> str:
            return _lookup()

        @Airlock(config=_config(_NO_EGRESS))
        async def tool() -> str:
            return await asyncio.create_task(child())

        assert await tool() == "refused"
        assert await asyncio.create_task(child()) == "allowed"

    async def test_limit_a_task_left_running_is_checked_only_while_an_airgap_is_open(
        self,
    ) -> None:
        """A task the tool leaves running keeps the call's policy in its context, but
        the socket patch is removed when the last airgap in the process closes."""
        release = asyncio.Event()

        async def child() -> str:
            await release.wait()
            return _lookup()

        @Airlock(config=_config(_NO_EGRESS))
        async def tool() -> Any:
            return asyncio.create_task(child())

        after_return = await tool()
        while_another_is_open = await tool()
        with network_airgap(NetworkPolicy()):  # any airgap: the patch is back
            release.set()
            assert await while_another_is_open == "refused"
        assert await after_return == "refused"  # it ran while the patch was in place

        late = await tool()
        await asyncio.sleep(0)
        assert network_module._interceptor_ref_count == 0
        assert await late == "allowed"  # nothing is open: its policy is not enforced

    async def test_asyncio_to_thread_carries_the_airgap(self) -> None:
        @Airlock(config=_config(_NO_EGRESS))
        async def tool() -> str:
            return await asyncio.to_thread(_lookup)

        assert await tool() == "refused"
        assert await asyncio.to_thread(_lookup) == "allowed"

    def test_limit_a_thread_the_tool_starts_runs_without_the_airgap(self) -> None:
        """The airgap follows the context, which Python copies into asyncio tasks and
        ``asyncio.to_thread`` but not into ``threading.Thread`` or a
        ``ThreadPoolExecutor`` (unless ``sys.flags.thread_inherit_context`` is set)."""

        @Airlock(config=_config(_NO_EGRESS))
        def tool() -> list[str]:
            seen: list[str] = []
            worker = threading.Thread(target=lambda: seen.append(_lookup()))
            worker.start()
            worker.join(5)
            with ThreadPoolExecutor(max_workers=1) as pool:
                seen.append(pool.submit(_lookup).result(5))
            seen.append(_lookup())
            return seen

        inherits = bool(getattr(sys.flags, "thread_inherit_context", False))
        expected = "refused" if inherits else "allowed"
        assert tool() == [expected, expected, "refused"]

    async def test_the_patch_is_removed_when_the_last_concurrent_airgap_closes(self) -> None:
        original = socket.getaddrinfo
        release = asyncio.Event()

        @Airlock(config=_config(_NO_EGRESS))
        async def tool() -> str:
            await release.wait()
            return _lookup()

        tasks = [asyncio.create_task(tool()) for _ in range(3)]
        for _ in range(20):
            if network_module._interceptor_ref_count == 3:
                break
            await asyncio.sleep(0)
        assert network_module._interceptor_ref_count == 3
        release.set()

        assert await asyncio.wait_for(asyncio.gather(*tasks), 5) == ["refused"] * 3
        assert network_module._interceptor_ref_count == 0
        assert socket.getaddrinfo is original


class TestAllowEgressPoliciesAreEnforced:
    """An allow-egress NetworkPolicy on AirlockConfig is applied, not only allow_egress=False."""

    @pytest.mark.parametrize("shape", _SHAPES)
    @pytest.mark.parametrize(
        ("policy", "probe"),
        [
            pytest.param(INTERNAL_ONLY_POLICY, lambda: _lookup(ELSEWHERE), id="internal-only"),
            pytest.param(HTTPS_ONLY_POLICY, lambda: _connect(9), id="https-only"),
            pytest.param(NetworkPolicy(block_dns=True), lambda: _lookup("127.0.0.1"), id="no-dns"),
        ],
    )
    async def test_a_restricting_policy_refuses(
        self, policy: NetworkPolicy, probe: Callable[[], str], shape: str
    ) -> None:
        assert await _run_in_shape(shape, _config(policy), probe) == "refused"
        assert probe() != "refused"  # control: the same probe outside the call

    @pytest.mark.parametrize("shape", _SHAPES)
    async def test_an_unrestricted_policy_admits(self, shape: str) -> None:
        config = _config(NetworkPolicy())
        assert await _run_in_shape(shape, config, _lookup) == "allowed"
        assert await _run_in_shape(shape, config, lambda: _connect(9)) == "admitted"

    @pytest.mark.parametrize("shape", _SHAPES)
    async def test_allow_egress_false_refuses_as_before(self, shape: str) -> None:
        config = _config(_NO_EGRESS)
        assert await _run_in_shape(shape, config, _lookup) == "refused"
        assert await _run_in_shape(shape, config, lambda: _connect(443)) == "refused"

    def test_a_config_without_a_policy_patches_nothing(self) -> None:
        original = socket.getaddrinfo

        @Airlock()
        def tool() -> bool:
            return socket.getaddrinfo is original

        assert AirlockConfig().network_policy is None
        assert tool() is True

    def test_a_host_allowlist_admits_its_host_and_refuses_another(self) -> None:
        @Airlock(config=_config(NetworkPolicy(allowed_hosts=["127.0.0.1"])))
        def tool() -> tuple[str, str]:
            return _lookup("127.0.0.1"), _lookup(ELSEWHERE)

        assert tool() == ("allowed", "refused")

    def test_a_port_allowlist_admits_its_port_and_refuses_another(self) -> None:
        @Airlock(config=_config(NetworkPolicy(allowed_ports=[9])))
        def tool() -> tuple[str, str]:
            return _connect(9), _connect(10)

        assert tool() == ("admitted", "refused")

    def test_a_listed_name_admits_the_address_it_resolves_to(self) -> None:
        """The connection is checked by the address the name resolved to, so a listed
        name admits the addresses its lookup returned in this call. That includes an
        internal address like this one: keeping a tool off those is the job of
        EndpointPolicy and the SSRF egress guard, not of the airgap's allowlist."""
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            port = server.getsockname()[1]

            @Airlock(config=_config(NetworkPolicy(allowed_hosts=["localhost"])))
            def tool() -> str:
                with socket.create_connection(("localhost", port), timeout=2):
                    return "connected"

            assert tool() == "connected"

    def test_an_admitted_address_does_not_outlive_its_call(self) -> None:
        policy = NetworkPolicy(allowed_hosts=["localhost"])

        @Airlock(config=_config(policy))
        def resolve() -> int:
            return len(socket.getaddrinfo("localhost", 9))

        @Airlock(config=_config(policy))
        def connect_by_address() -> str:
            return _connect(9)

        assert resolve() > 0
        assert connect_by_address() == "refused"


class TestTheAirgapCoversDatagramsAndEveryLookup:
    """sendto / sendmsg and the lookups beyond getaddrinfo are intercepted."""

    @pytest.mark.parametrize(
        "send",
        [
            pytest.param(_send_datagram, id="sendto"),
            pytest.param(
                _send_datagram_by_sendmsg,
                id="sendmsg",
                marks=pytest.mark.skipif(
                    not hasattr(socket.socket, "sendmsg"), reason="no sendmsg here"
                ),
            ),
        ],
    )
    def test_a_datagram_is_refused_under_no_network(self, send: Callable[[], None]) -> None:
        send()  # control: outside an airgap it goes out (to this machine)
        with network_airgap(NO_NETWORK_POLICY), pytest.raises(NetworkBlockedError):
            send()

    @pytest.mark.parametrize(
        "lookup",
        [
            pytest.param(lambda: socket.gethostbyname("localhost"), id="gethostbyname"),
            pytest.param(lambda: socket.gethostbyname_ex("localhost"), id="gethostbyname_ex"),
            pytest.param(lambda: socket.gethostbyaddr("127.0.0.1"), id="gethostbyaddr"),
            pytest.param(lambda: socket.getnameinfo(("127.0.0.1", 80), 0), id="getnameinfo"),
        ],
    )
    def test_a_lookup_is_refused_under_no_network(self, lookup: Callable[[], Any]) -> None:
        # No control outside the airgap here: a reverse lookup, even of 127.0.0.1, can
        # leave this machine (and wait out a DNS timeout) where the resolver asks DNS.
        with network_airgap(NO_NETWORK_POLICY), pytest.raises(NetworkBlockedError):
            lookup()

    def test_a_datagram_follows_the_host_and_port_allowlists(self) -> None:
        with network_airgap(NetworkPolicy(allowed_hosts=["127.0.0.1"], allowed_ports=[9])):
            assert _datagram(9) == "admitted"
            assert _datagram(10) == "refused"

    def test_this_machines_own_name_is_looked_up_unchecked(self) -> None:
        """``socket.getfqdn()`` (so ``smtplib`` and ``email.utils.make_msgid()``) and
        ``gethostbyname(gethostname())`` look up this machine's own name, which carries
        nothing from the call. It is not refused, and it admits nothing at connect.
        Checked without running the lookup, which may leave this machine."""
        own = socket.gethostname()
        with network_airgap(NO_NETWORK_POLICY):
            assert network_module._checked_lookup(own, "dns_lookup") == ()
            assert network_module._checked_lookup(own.upper(), "dns_lookup") == ()
            with pytest.raises(NetworkBlockedError):  # control: any other name
                network_module._checked_lookup("not-this-machine.test", "dns_lookup")

    def test_formatting_an_address_is_not_a_lookup(self) -> None:
        flags = socket.NI_NUMERICHOST | socket.NI_NUMERICSERV
        with network_airgap(NO_NETWORK_POLICY):
            assert socket.getnameinfo(("127.0.0.1", 80), flags) == ("127.0.0.1", "80")

    def test_getaddrinfo_takes_its_keyword_arguments(self) -> None:
        with network_airgap(NetworkPolicy()):
            infos = socket.getaddrinfo(
                "127.0.0.1", 9, type=socket.SOCK_STREAM, flags=socket.AI_NUMERICHOST
            )
        assert infos

    async def test_an_event_loop_lookup_is_checked_before_its_executor(self) -> None:
        loop = asyncio.get_running_loop()

        @Airlock(config=_config(_NO_EGRESS))
        async def tool() -> str:
            try:
                await loop.getaddrinfo(ELSEWHERE, 443, flags=socket.AI_NUMERICHOST)
            except NetworkBlockedError:
                return "refused"
            return "allowed"

        assert await tool() == "refused"
        assert await loop.getaddrinfo(ELSEWHERE, 443, flags=socket.AI_NUMERICHOST)  # control

    async def test_an_event_loop_reverse_lookup_is_checked(self) -> None:
        loop = asyncio.get_running_loop()
        numeric = socket.NI_NUMERICHOST | socket.NI_NUMERICSERV

        @Airlock(config=_config(_NO_EGRESS))
        async def tool() -> tuple[str, bool]:
            # Compared here: the tool's output is masked, and an IP address is masked.
            formatted = await loop.getnameinfo(("127.0.0.1", 80), numeric) == ("127.0.0.1", "80")
            try:
                await loop.getnameinfo(("127.0.0.1", 80))
            except NetworkBlockedError:
                return "refused", formatted
            return "allowed", formatted

        assert await tool() == ("refused", True)


class _Countdown:
    """A lazy iterator that is not a generator."""

    def __init__(self, produce: Callable[[int], Any], count: int) -> None:
        self.produce = produce
        self.count = count

    def __iter__(self) -> _Countdown:
        return self

    def __next__(self) -> Any:
        if self.count == 0:
            raise StopIteration
        self.count -= 1
        return self.produce(self.count)


class _AsyncCountdown:
    """A lazy async iterator that is not an async generator."""

    def __init__(self, produce: Callable[[int], Any], count: int) -> None:
        self.produce = produce
        self.count = count

    def __aiter__(self) -> _AsyncCountdown:
        return self

    async def __anext__(self) -> Any:
        if self.count == 0:
            raise StopAsyncIteration
        self.count -= 1
        return self.produce(self.count)


class _Plain(BaseModel):
    a: int


def _sensitive_item(_index: int) -> str:
    return f"{_lookup()} {SECRET}"


class TestDeferredResultsRunUnderTheCallsGuards:
    """A coroutine or lazy iterator a tool returns runs inside the airgap, context and masking."""

    async def test_a_coroutine_from_a_sync_tool(self) -> None:
        async def body() -> str:
            current = get_current_context()
            return f"{_lookup()} {current.agent_id if current else None} {SECRET}"

        @Airlock(config=_config(_NO_EGRESS))
        def tool() -> Any:
            return body()

        with AirlockContext(agent_id="agent-1"):
            pending = tool()
        assert asyncio.iscoroutine(pending)
        result = await pending

        assert result.startswith("refused agent-1 ")
        assert SECRET not in result

    async def test_a_coroutine_from_an_async_tool(self) -> None:
        async def body() -> str:
            return _lookup()

        @Airlock(config=_config(_NO_EGRESS))
        async def tool() -> Any:
            return body()

        pending = await tool()
        assert await pending == "refused"

    async def test_masking_a_coroutines_value_follows_sanitize_output(self) -> None:
        async def body() -> str:
            return SECRET

        @Airlock(config=AirlockConfig(sanitize_output=False))
        def tool() -> Any:
            return body()

        assert await tool() == SECRET

    @pytest.mark.parametrize(
        "make",
        [
            pytest.param(lambda: map(_sensitive_item, [1, 2]), id="map"),
            pytest.param(lambda: filter(None, map(_sensitive_item, [1, 2])), id="filter"),
            pytest.param(lambda: zip(map(_sensitive_item, [1, 2]), "ab", strict=True), id="zip"),
            pytest.param(lambda: _Countdown(_sensitive_item, 2), id="custom-next"),
        ],
    )
    def test_a_lazy_iterator_runs_each_step_inside_the_airgap(
        self, make: Callable[[], Iterator[Any]]
    ) -> None:
        @Airlock(config=_config(_NO_EGRESS))
        def tool() -> Any:
            return make()

        items = json.dumps(list(tool()))

        assert items.count("refused") == 2
        assert "allowed" not in items
        assert SECRET not in items

    async def test_a_lazy_async_iterator(self) -> None:
        @Airlock(config=_config(_NO_EGRESS))
        def tool() -> Any:
            return _AsyncCountdown(_sensitive_item, 2)

        items = [item async for item in tool()]

        assert len(items) == 2
        assert all(item.startswith("refused") and SECRET not in item for item in items)

    def test_the_calls_context_is_current_while_a_lazy_iterator_runs(self) -> None:
        def agent_id(_index: int) -> str | None:
            return getattr(get_current_context(), "agent_id", None)

        @Airlock()
        def tool() -> Any:
            return map(agent_id, [1])

        with AirlockContext(agent_id="agent-2"):
            lazy = tool()
        assert list(lazy) == ["agent-2"]

    def test_closing_early_closes_the_iterator_inside_the_airgap(self) -> None:
        seen: list[str] = []

        class Closable(_Countdown):
            def close(self) -> None:
                seen.append(_lookup())

        @Airlock(config=_config(_NO_EGRESS))
        def tool() -> Any:
            return Closable(lambda _i: "item", 3)

        lazy = tool()
        assert next(lazy) == "item"
        lazy.close()

        assert seen == ["refused"]

    @pytest.mark.parametrize(
        "value",
        [[1, 2], (1, 2), {"a": 1}, {1, 2}, "text", b"bytes", _Plain(a=1)],
        ids=["list", "tuple", "dict", "set", "str", "bytes", "model"],
    )
    def test_a_concrete_result_is_returned_as_it_is(self, value: Any) -> None:
        assert Airlock()(lambda: value)() is value

    def test_limit_a_context_managed_iterator_is_returned_as_it_is(self) -> None:
        handle = io.StringIO("line\n")
        assert Airlock()(lambda: handle)() is handle

    async def test_limit_an_already_scheduled_task_is_returned_as_it_is(self) -> None:
        async def body() -> str:
            return "done"

        @Airlock()
        def tool() -> Any:
            return asyncio.get_running_loop().create_task(body())

        task = tool()
        assert isinstance(task, asyncio.Task)
        assert await task == "done"


@dataclass
class _Note:
    text: str


class _Model(BaseModel):
    note: str


class TestTheAuditPreviewIsMasked:
    def test_the_result_preview_is_masked_with_output_masking_off(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"

        @Airlock(config=AirlockConfig(sanitize_output=False, audit_log_path=log))
        def echo(note: str) -> str:
            return f"result has {note}"

        assert SECRET in echo(note=SECRET)  # the caller asked for raw output

        (record,) = _records(log)
        assert SECRET not in record["args_preview"]["note"]  # control: masked before 0.10.28
        assert SECRET not in record["result_preview"]
        assert record["result_preview"].startswith("result has ")

    def test_an_object_returned_unmasked_is_masked_in_the_preview(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        note = _Note(f"mail {EMAIL}")

        @Airlock(config=AirlockConfig(audit_log_path=log))
        def tool() -> _Note:
            return note

        assert tool() is note  # returned as it is, reported as not masked

        (record,) = _records(log)
        assert EMAIL not in record["result_preview"]
        assert "_Note(" in record["result_preview"]

    def test_a_returned_reason_is_masked_in_the_preview(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"

        @Airlock(config=AirlockConfig(sanitize_output=False, audit_log_path=log))
        def tool() -> dict[str, Any]:
            return {"blocked": True, "reason": f"user {EMAIL} is banned"}

        tool()

        (record,) = _records(log)
        assert record["result_preview"].startswith("BLOCKED: user ")
        assert EMAIL not in record["result_preview"]


class TestStructuredMaskingReadsKeysAndLeaves:
    def test_a_secret_in_a_key_is_masked(self) -> None:
        masked, count = sanitize_structured({f"key {SECRET}": 1, "plain": 2})

        assert count == 1
        assert SECRET not in json.dumps(list(masked))
        assert list(masked.values()) == [1, 2]
        assert "plain" in masked

    def test_a_dict_result_with_a_secret_key(self) -> None:
        result = Airlock()(lambda: {EMAIL: "row"})()

        assert EMAIL not in json.dumps(result)
        assert list(result.values()) == ["row"]

    def test_keys_that_mask_alike_keep_every_value(self) -> None:
        value = {"123-45-6789": "a", "[REDACTED]": "kept", "987-65-4321": "b"}

        masked, count = sanitize_structured(value)

        assert count == 2
        assert list(masked.items()) == [
            ("[REDACTED] (2)", "a"),
            ("[REDACTED]", "kept"),
            ("[REDACTED] (3)", "b"),
        ]
        assert list(sanitize_structured(dict(value))[0].items()) == list(masked.items())

    def test_a_tuple_key_is_masked(self) -> None:
        masked, count = sanitize_structured({("user", EMAIL): 1})

        assert count == 1
        ((key, value),) = masked.items()
        assert isinstance(key, tuple)
        assert key[0] == "user"
        assert EMAIL not in key[1]
        assert value == 1

    @pytest.mark.parametrize(
        ("make", "leaf_type"),
        [
            pytest.param(lambda s: {"blob": s.encode()}, "bytes", id="bytes"),
            pytest.param(lambda s: [bytearray(s.encode())], "bytearray", id="bytearray"),
            pytest.param(lambda s: [_Model(note=s)], "_Model", id="pydantic-model"),
            pytest.param(lambda s: {"note": _Note(s)}, "_Note", id="dataclass"),
            pytest.param(lambda s: {"queue": deque([s])}, "deque", id="deque"),
            pytest.param(lambda s: [UserDict({"k": s})], "UserDict", id="userdict"),
            pytest.param(lambda _s: {"card": 4111111111111111}, "int", id="int"),
        ],
    )
    def test_a_leaf_the_walk_cannot_rebuild_is_reported_not_masked(
        self, make: Callable[[str], Any], leaf_type: str
    ) -> None:
        value = make(f"{SECRET} {EMAIL}")

        response = Airlock(return_dict=True)(lambda: value)()

        assert response["result"] is value
        suffix = f"in {leaf_type} inside {type(value).__name__} output; not masked"
        assert any(w.endswith(suffix) for w in response["warnings"]), response["warnings"]

    def test_a_leaf_with_nothing_in_it_is_not_reported(self) -> None:
        value = {"blob": b"plain bytes", "n": 3, "ok": True, "none": None}

        response = Airlock(return_dict=True)(lambda: value)()

        assert response["result"] is value
        assert not response.get("warnings")

    def test_masked_strings_and_reported_leaves_together(self) -> None:
        value = {"text": f"mail {EMAIL}", "blob": EMAIL.encode()}

        response = Airlock(return_dict=True)(lambda: value)()

        assert EMAIL not in response["result"]["text"]
        assert response["result"]["blob"] == EMAIL.encode()
        assert response["warnings"] == [
            "Masked 1 sensitive value(s) in output",
            "Detected 1 sensitive value(s) in bytes inside dict output; not masked",
        ]

    def test_a_shared_container_is_masked_at_every_reference(self) -> None:
        user = {"email": EMAIL}

        masked, count = sanitize_structured({"owner": user, "editor": user})

        assert EMAIL not in json.dumps(masked)
        assert masked["owner"] is masked["editor"]
        assert count == 2
        assert user == {"email": EMAIL}

    def test_a_cycle_is_masked_through_its_back_reference(self) -> None:
        value: list[Any] = [f"mail {EMAIL}"]
        value.append(value)

        masked, count = sanitize_structured(value)

        assert count == 1
        assert EMAIL not in masked[0]
        assert masked[1] is masked
        assert value[0] == f"mail {EMAIL}"


class TestANetworkRefusalNamesTheCaller:
    @pytest.mark.parametrize("is_async", [False, True], ids=["sync", "async"])
    async def test_the_record_carries_the_agent_and_session(
        self, tmp_path: Path, is_async: bool
    ) -> None:
        log = tmp_path / "audit.jsonl"
        config = AirlockConfig(audit_log_path=log, network_policy=_NO_EGRESS)

        def fetch_body() -> str:
            socket.getaddrinfo(ELSEWHERE, 443, flags=socket.AI_NUMERICHOST)
            return "fetched"

        @Airlock(config=config)
        def fetch() -> str:
            return fetch_body()

        @Airlock(config=config)
        async def fetch_async() -> str:
            return fetch_body()

        with AirlockContext(agent_id="agent-7", session_id="sess-7"):
            response = await fetch_async() if is_async else fetch()

        assert response["block_reason"] == "network_blocked"
        (record,) = _records(log)
        assert record["blocked"] is True
        assert record["block_reason"] == "network_blocked"
        assert record["agent_id"] == "agent-7"
        assert record["session_id"] == "sess-7"


class TestAResultRefusedMidwayIsAudited:
    def test_a_generator(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"

        @Airlock(config=AirlockConfig(audit_log_path=log, network_policy=_NO_EGRESS))
        def stream() -> Generator[str, None, None]:
            yield "first"
            socket.getaddrinfo(ELSEWHERE, 443, flags=socket.AI_NUMERICHOST)
            yield "second"

        with AirlockContext(agent_id="agent-8", session_id="sess-8"):
            gen = stream()
        assert next(gen) == "first"
        with pytest.raises(NetworkBlockedError):
            next(gen)

        returned, refused = _records(log)
        assert returned["blocked"] is False
        assert returned["result_type"] == "generator"
        assert refused["tool_name"] == "stream"
        assert refused["blocked"] is True
        assert refused["block_reason"] == "network_blocked"
        assert (refused["agent_id"], refused["session_id"]) == ("agent-8", "sess-8")
        assert refused["error"].startswith("AIRLOCK_BLOCK")

    async def test_an_async_generator(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"

        @Airlock(config=AirlockConfig(audit_log_path=log, network_policy=_NO_EGRESS))
        async def stream() -> AsyncIterator[str]:
            yield "first"
            socket.getaddrinfo(ELSEWHERE, 443, flags=socket.AI_NUMERICHOST)
            yield "second"

        with AirlockContext(agent_id="agent-9"):
            gen = stream()
        assert await gen.__anext__() == "first"
        with pytest.raises(NetworkBlockedError):
            await gen.__anext__()

        refused = _records(log)[-1]
        assert refused["blocked"] is True
        assert refused["block_reason"] == "network_blocked"
        assert refused["agent_id"] == "agent-9"

    async def test_a_coroutine_and_a_lazy_iterator(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        config = AirlockConfig(audit_log_path=log, network_policy=_NO_EGRESS)

        def blocked(_i: int = 0) -> str:
            socket.getaddrinfo(ELSEWHERE, 443, flags=socket.AI_NUMERICHOST)
            return "unreachable"

        async def body() -> str:
            return blocked()

        @Airlock(config=config)
        def later() -> Any:
            return body()

        @Airlock(config=config)
        def lazy() -> Any:
            return map(blocked, [1])

        with pytest.raises(NetworkBlockedError):
            await later()
        with pytest.raises(NetworkBlockedError):
            list(lazy())

        refusals = [r for r in _records(log) if r["blocked"]]
        assert [(r["tool_name"], r["block_reason"]) for r in refusals] == [
            ("later", "network_blocked"),
            ("lazy", "network_blocked"),
        ]

    def test_another_airlock_refusal_raised_midway(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        policy = FilesystemPolicy(allowed_roots=[tmp_path])

        @Airlock(config=AirlockConfig(audit_log_path=log))
        def stream() -> Generator[str, None, None]:
            yield "first"
            validate_path("/etc/passwd", policy)
            yield "second"

        gen = stream()
        assert next(gen) == "first"
        with pytest.raises(PathValidationError):
            next(gen)

        refused = _records(log)[-1]
        assert refused["blocked"] is True
        assert refused["block_reason"] == "path_violation"

    def test_an_ordinary_error_midway_is_not_recorded_as_a_refusal(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"

        @Airlock(config=AirlockConfig(audit_log_path=log))
        def stream() -> Generator[str, None, None]:
            yield "first"
            raise ValueError("the tool's own error")

        gen = stream()
        assert next(gen) == "first"
        with pytest.raises(ValueError, match="own error"):
            next(gen)

        assert [r["blocked"] for r in _records(log)] == [False]
