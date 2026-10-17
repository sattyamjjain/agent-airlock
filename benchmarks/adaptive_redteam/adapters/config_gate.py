"""Mode B: the config gates — filesystem paths (step 3) and endpoint URLs (step 5).

These run the real ``@Airlock`` call path with an :class:`AirlockConfig` carrying a
``filesystem_policy`` or an ``endpoint_policies`` entry, so the candidate goes
through ``bind_arguments`` / ``_arg_walk`` and the same gate a deployment uses.

The sentinel is physical: a canary file under a temp forbidden root
(:class:`FileCanary`) for the filesystem gate, and a bound ``127.0.0.1`` listener
(:class:`LoopbackCanary`) for the endpoint gate. Candidates reference them through
tokens (``{FORBIDDEN_FILE}``, ``{ALLOWED_FILE}``, ``{LOOPBACK_URL}``,
``{METADATA_URL}``, ``{ALLOWED_URL}``) so the JSON a candidate file carries stays
machine-independent; ``run`` substitutes the live path/port.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_airlock.config import AirlockConfig
from agent_airlock.core import Airlock
from agent_airlock.filesystem import FilesystemPolicy
from agent_airlock.network import EndpointPolicy

from ..canaries import FileCanary, LoopbackCanary, canary_env, read_audit
from ..oracle import CallSpec, Canary, Candidate, ForbiddenEffect, Intent

METADATA_URL = "http://169.254.169.254/latest/meta-data/"


def _subst(value: Any, tokens: Mapping[str, str]) -> Any:
    """Recursively replace ``{TOKEN}`` markers in strings with live values."""
    if isinstance(value, str):
        for key, repl in tokens.items():
            value = value.replace("{" + key + "}", repl)
        return value
    if isinstance(value, Mapping):
        return {k: _subst(v, tokens) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(_subst(v, tokens) for v in value)
    return value


@dataclass
class FilesystemAdapter:
    """Mode B: the filesystem path gate (``config.filesystem_policy``)."""

    name: str = "filesystem"
    mode: str = "B"

    def intent(self) -> ForbiddenEffect:
        return ForbiddenEffect(
            sink="filesystem",
            deny_verdicts=frozenset({"outside_allowed_roots", "denied_pattern"}),
            sentinel="canary.secret",
        )

    def known_blocked(self, seed: int) -> Candidate:
        return Candidate(
            guard=self.name,
            seed=seed,
            candidate_id=f"{self.name}-s{seed:02d}-blocked",
            call=CallSpec(kwargs={"path": "{FORBIDDEN_FILE}"}),
            intent=Intent.ATTACK,
        )

    def benign_control(self, seed: int) -> Candidate:
        return Candidate(
            guard=self.name,
            seed=seed,
            candidate_id=f"{self.name}-s{seed:02d}-benign",
            call=CallSpec(kwargs={"path": "{ALLOWED_FILE}"}),
            intent=Intent.BENIGN,
        )

    def run(self, candidate: Candidate) -> Canary:
        canary = Canary()
        with FileCanary.create() as forbidden, canary_env() as audit_path:
            allowed_root = Path(audit_path).parent
            allowed_file = allowed_root / "ok.txt"
            tokens = {
                "FORBIDDEN_FILE": str(forbidden.canary),
                "FORBIDDEN_ROOT": str(forbidden.root),
                "ALLOWED_FILE": str(allowed_file),
                "ALLOWED_ROOT": str(allowed_root),
            }
            kwargs = _subst(dict(candidate.call.kwargs), tokens)
            config = AirlockConfig(
                filesystem_policy=FilesystemPolicy(allowed_roots=[allowed_root]),
            )

            def read_file(path: str, **_rest: Any) -> str:
                # Admitted path: the tool would read it. Fire the canary iff it
                # resolves onto the forbidden root.
                forbidden.touched_by(path)
                return "ok"

            wrapped = Airlock(config=config, return_dict=True)(read_file)
            try:
                response = wrapped(**kwargs)
            except Exception as exc:  # noqa: BLE001
                canary.raised = exc
                return canary
            canary.response = response
            canary.audit = read_audit(audit_path)
            canary.sink_hits = list(forbidden.hits)
        return canary


@dataclass
class EndpointAdapter:
    """Mode B: the per-tool endpoint URL gate (``config.endpoint_policies``)."""

    name: str = "endpoint"
    mode: str = "B"

    def intent(self) -> ForbiddenEffect:
        return ForbiddenEffect(
            sink="egress",
            deny_verdicts=frozenset({"endpoint_not_allowed", "private_ip", "metadata"}),
            sentinel="127.0.0.1",
        )

    def known_blocked(self, seed: int) -> Candidate:
        return Candidate(
            guard=self.name,
            seed=seed,
            candidate_id=f"{self.name}-s{seed:02d}-blocked",
            call=CallSpec(kwargs={"url": "{METADATA_URL}"}),
            intent=Intent.ATTACK,
        )

    def benign_control(self, seed: int) -> Candidate:
        return Candidate(
            guard=self.name,
            seed=seed,
            candidate_id=f"{self.name}-s{seed:02d}-benign",
            call=CallSpec(kwargs={"url": "{ALLOWED_URL}"}),
            intent=Intent.BENIGN,
        )

    def run(self, candidate: Candidate) -> Canary:
        canary = Canary()
        with LoopbackCanary.create() as loop, canary_env() as audit_path:
            tokens = {
                "LOOPBACK_URL": f"http://127.0.0.1:{loop.port}/",
                "METADATA_URL": METADATA_URL,
                "ALLOWED_URL": "https://api.allowed.example/v1",
            }
            kwargs = _subst(dict(candidate.call.kwargs), tokens)
            policy = EndpointPolicy(allowed_endpoints=["api.allowed.example"])
            config = AirlockConfig(endpoint_policies={"fetch_url": policy})

            def fetch_url(url: str, **_rest: Any) -> str:
                host = _host_of(url)
                if host in {"127.0.0.1", "localhost", "::1"}:
                    loop.connect(host, None)
                return "ok"

            wrapped = Airlock(config=config, return_dict=True)(fetch_url)
            try:
                response = wrapped(**kwargs)
            except Exception as exc:  # noqa: BLE001
                canary.raised = exc
                return canary
            canary.response = response
            canary.audit = read_audit(audit_path)
            canary.sink_hits = list(loop.hits)
            # Metadata / private targets never reach the loopback listener, so a
            # physical hit is impossible; fall back to an independent reference
            # confirmation that the admitted URL is a forbidden egress target.
            if (
                not canary.sink_hits
                and candidate.intent is Intent.ATTACK
                and not _response_blocked(response)
                and _is_forbidden_egress(kwargs.get("url"))
            ):
                canary.sink_hits.append(f"egress:{_host_of(kwargs.get('url'))}")
        return canary


def _host_of(url: Any) -> str | None:
    if not isinstance(url, str):
        return None
    from urllib.parse import urlparse

    candidate = url if "://" in url else "//" + url
    try:
        return urlparse(candidate).hostname
    except ValueError:
        return None


def _response_blocked(response: Any) -> bool:
    return isinstance(response, Mapping) and response.get("success") is False


def _is_forbidden_egress(url: Any) -> bool:
    """Independent (stdlib ``ipaddress``) confirmation of a forbidden egress host."""
    import ipaddress

    host = _host_of(url)
    if host is None:
        return False
    host = host.strip("[]")
    if host in {"localhost", "metadata.google.internal"}:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or str(ip) in {"169.254.169.254"}
    )
