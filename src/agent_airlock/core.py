"""Core Airlock decorator for securing MCP tool calls.

The @Airlock decorator provides:
1. Ghost argument detection and stripping
2. Pydantic strict schema validation
3. Self-healing error responses
4. Optional E2B sandbox execution
5. Policy enforcement
6. Audit logging (JSON Lines format)
7. Full async function support
8. Filesystem path validation (V0.3.0)
9. Network egress control (V0.3.0)
10. Honeypot deception (V0.3.0)

Security Notes
--------------

exec() Usage:
    This module contains exec() calls ONLY in docstring examples demonstrating
    how to safely execute user code with sandbox=True. These examples show the
    intended pattern:

        @Airlock(sandbox=True, sandbox_required=True)
        def run_code(code: str) -> str:
            exec(code)  # Runs in E2B MicroVM, never locally
            return "ok"

    With sandbox=True the function never runs in this process because E2B is missing
    or failed: the call is refused with a ``sandbox_error`` response. sandbox_required=True
    also refuses in the one case sandbox=True alone runs locally, which is
    ``agent_airlock.sandbox`` itself failing to import.
    Never use exec() without sandbox protection in production.

Thread Safety:
    This module is thread-safe. The Airlock class can be used as a decorator
    from multiple threads concurrently. State is managed through:
    - contextvars for request-scoped context (AirlockContext)
    - contextvars for the network airgap (in network.py), one per thread and asyncio task
    - Locks in sandbox pool and audit logger

    Lock Acquisition Order (to prevent deadlocks):
    1. _pool_lock (sandbox.py) - sandbox pool access
    2. audit._file_lock (audit.py) - audit file writes
    3. _patch_lock (network.py) - socket interceptor installation

    Note: Locks should never be held across await boundaries or external calls.
"""

from __future__ import annotations

import asyncio
import contextlib
import copy
import dataclasses
import functools
import inspect
import numbers
import os
import re
import time
import uuid
from collections.abc import (
    AsyncGenerator,
    AsyncIterator,
    Callable,
    Coroutine,
    Generator,
    Iterable,
    Iterator,
    Mapping,
)
from datetime import datetime, timezone
from typing import Any, Literal, ParamSpec, TypeVar, overload
from urllib.parse import urlparse
from urllib.request import url2pathname

from pydantic import BaseModel, ValidationError

from ._arg_walk import (
    MAX_DEPTH,
    ArgumentNestingError,
    ArgumentValue,
    bind_arguments,
    iter_argument_values,
    named_models,
    path_text,
    signature_of,
    url_text,
)
from ._log import structlog
from ._sandbox_errors import SandboxError
from ._sandbox_errors import SandboxExecutionError as SandboxExecutionError
from ._sandbox_errors import SandboxUnavailableError as SandboxUnavailableError
from .audit import AuditLogger
from .capabilities import (
    Capability,
    CapabilityDeniedError,
    capabilities_to_list,
    get_required_capabilities,
)
from .config import DEFAULT_CONFIG, AirlockConfig
from .context import (
    AirlockContext,
    ContextExtractor,
    get_current_context,
    reset_context,
    set_current_context,
)
from .cost_tracking import (
    AirlockBudgetExceeded,
    BudgetEstimate,
    TokenUsage,
    UnknownTierError,
    get_global_tracker,
)
from .exceptions import AirlockError
from .filesystem import PathValidationError, validate_path
from .honeypot import (
    create_honeypot_response,
    create_honeypot_response_async,
    should_soft_block,
    should_use_honeypot,
)
from .kill_switch.registry import get as _kill_switch_get
from .kill_switch.registry import is_frozen as _kill_switch_frozen
from .network import NetworkBlockedError, network_airgap
from .oversight import _ApproverOutcome, _await_with_deadline, _call_with_deadline
from .policy import (
    AgentIdentity,
    PolicyEscalation,
    PolicyMutationError,
    PolicyViolation,
    SecurityPolicy,
    ViolationType,
)
from .sanitizer import _rebuild_like, sanitize_output, sanitize_structured_report
from .self_heal import (
    AirlockResponse,
    BlockReason,
    handle_amplification_exceeded,
    handle_budget_exceeded,
    handle_capability_denied,
    handle_endpoint_violation,
    handle_escalation,
    handle_ghost_argument_error,
    handle_network_blocked,
    handle_path_violation,
    handle_policy_violation,
    handle_rate_limit,
    handle_validation_error,
)
from .unknown_args import UnknownArgsMode, handle_unknown_args
from .validator import (
    GhostArgumentError,
    create_argument_validator,
    create_strict_validator,
    strip_ghost_arguments,
)

logger = structlog.get_logger("agent-airlock")

P = ParamSpec("P")
R = TypeVar("R")
_T = TypeVar("_T")


@dataclasses.dataclass(frozen=True)
class _ApprovalAsk:
    """What step 2 waits on when a call escalates: the approver, the request it is asked,
    and the deadline (``escalation_timeout_seconds``). The pre-execution steps yield one
    and are sent back the :class:`~agent_airlock.oversight._ApproverOutcome`, so the sync
    path answers it in a worker thread and the async path without blocking the loop."""

    approver: Callable[[Any], Any]
    request: Any
    timeout: float


def _drive(steps: Generator[_ApprovalAsk, _ApproverOutcome, _T]) -> _T:
    """Run ``steps`` to their result, answering each approval in a worker thread."""
    try:
        ask = next(steps)
        while True:
            ask = steps.send(_call_with_deadline(ask.approver, ask.request, ask.timeout))
    except StopIteration as done:
        result: _T = done.value
        return result


async def _drive_async(steps: Generator[_ApprovalAsk, _ApproverOutcome, _T]) -> _T:
    """:func:`_drive` for the async path: an approval is awaited, the loop runs meanwhile."""
    try:
        ask = next(steps)
        while True:
            outcome = await _await_with_deadline(ask.approver, ask.request, ask.timeout)
            ask = steps.send(outcome)
    except StopIteration as done:
        result: _T = done.value
        return result


# Type alias for policy resolver functions. A resolver that returns None refuses the call
# (V0.10.24; it used to run the call with no policy at all): return PERMISSIVE_POLICY to
# allow a call on purpose.
PolicyResolver = Callable[[AirlockContext[Any]], SecurityPolicy | None]

# Substrings that indicate a parameter name is sensitive and must not
# appear in debug logs. Any key whose lowercase form CONTAINS any of
# these substrings is filtered. This catches both exact matches
# (`password`) and compound variants (`user_password`, `my_api_key`,
# `aws_secret_key`, `session_cookie`, `db_token`, ...) that a previous
# exact-match implementation leaked.
SENSITIVE_PARAM_SUBSTRINGS: tuple[str, ...] = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "credential",
    "private_key",
    "privatekey",
    "access_token",
    "refresh_token",
    "session",
    "cookie",
    "ssn",
    "credit_card",
    "card_number",
)

# Legacy exact-match set kept for backward compatibility with any
# downstream code that imported SENSITIVE_PARAM_NAMES before v0.5.0.
# New code should rely on the substring check in _filter_sensitive_keys.
SENSITIVE_PARAM_NAMES = frozenset(SENSITIVE_PARAM_SUBSTRINGS) | {"key"}


def _filter_sensitive_keys(keys: list[str]) -> list[str]:
    """Filter out sensitive parameter names from a list of keys.

    SECURITY: Prevents leaking sensitive parameter names to logs. Uses
    substring matching so that compound names (`user_password`,
    `my_api_key`, `aws_secret_key`, `session_cookie`) are caught in
    addition to exact matches.
    """
    filtered: list[str] = []
    for k in keys:
        lowered = k.lower()
        if any(s in lowered for s in SENSITIVE_PARAM_SUBSTRINGS):
            continue
        filtered.append(k)
    return filtered


# Parameter names that typically contain file paths. The plurals name a list of paths: an
# item of a list or set is checked under its container's name (`_arg_walk`).
PATH_PARAM_NAMES = frozenset(
    {
        "path",
        "paths",
        "file",
        "files",
        "filename",
        "filenames",
        "filepath",
        "filepaths",
        "file_path",
        "file_paths",
        "directory",
        "directories",
        "dir",
        "dirs",
        "folder",
        "folders",
        "source",
        "destination",
        "dest",
        "src",
        "target",
        "input_file",
        "output_file",
        "config_file",
        "log_file",
    }
)


def _looks_like_path(key: str, value: Any) -> bool:
    """Check if a parameter looks like a file path.

    Uses heuristics based on:
    - Parameter name patterns
    - Value patterns (absolute, drive-rooted, home-relative or traversing shape, path
      separators, common file extensions)
    """
    if not isinstance(value, str):
        return False

    # Check parameter name
    if key.lower() in PATH_PARAM_NAMES:
        return True

    # Check value patterns
    value_lower = value.lower()

    # Absolute, drive-rooted, home-relative or parent-traversing by shape: the test the
    # nested walk applies. Until 0.10.26 only the first two were read here, so a bare
    # ``~`` or ``..`` under a parameter not named like a path had no separator to match
    # and never reached the filesystem gate, while the same value inside a list did.
    if _is_absolute_or_escaping(value):
        return True

    # Relative paths with separators
    if "/" in value or "\\" in value:
        # Exclude URLs
        return "://" not in value

    # Common file extensions
    return any(
        value_lower.endswith(ext) for ext in (".txt", ".json", ".yaml", ".yml", ".env", ".py")
    )


# Parameter names that typically contain URLs
URL_PARAM_NAMES = frozenset(
    {
        "url",
        "uri",
        "endpoint",
        "href",
        "link",
        "api_url",
        "base_url",
        "callback_url",
        "redirect_url",
        "webhook_url",
        "resource_url",
        "urls",
        "uris",
        "endpoints",
        "links",
        "hrefs",
    }
)


def _looks_like_url(key: str, value: Any) -> bool:
    """Check if a parameter looks like a URL.

    Uses heuristics based on:
    - Parameter name patterns
    - Value patterns (starts with http://, https://)
    """
    if not isinstance(value, str):
        return False

    # Check parameter name
    if key.lower() in URL_PARAM_NAMES:
        return True

    # Check value patterns
    return value.startswith("http://") or value.startswith("https://")


# A URL as a string: any `scheme://`, case-insensitive, after optional whitespace. HTTP
# clients accept `HTTP://` and a leading space, and `file://` or `gopher://` reach a host or
# a file just as surely; deny-by-default reads them all.
_URL_SCHEME_PREFIX = re.compile(r"\s*[A-Za-z][A-Za-z0-9+.\-]*://")
_FILE_URI_PREFIX = re.compile(r"\s*file:", re.IGNORECASE)
_DRIVE_PATH = re.compile(r"[A-Za-z]:[\\/]")
# Home-relative by shape: a bare `~`, `~/...` or `~user/...` (a separator after the name).
# Not `~5` or `~ 10 minutes`: approximations in free text are not paths.
_HOME_RELATIVE = re.compile(r"~(?:[A-Za-z0-9._-]*[\\/]|$)")
_PATH_EXTENSIONS = (".txt", ".json", ".yaml", ".yml", ".env", ".py")


def _file_uri_path(value: str) -> str | None:
    """The path a ``file:`` URI names (``file:///etc/passwd`` -> ``/etc/passwd``), else None."""
    if _FILE_URI_PREFIX.match(value) is None:
        return None
    parsed = urlparse(value.strip())
    return url2pathname(parsed.path) or "/"


def _is_absolute_or_escaping(value: str) -> bool:
    """An absolute, drive-rooted, home-relative or parent-traversing path, by its shape."""
    stripped = value.strip()
    return (
        stripped.startswith(("/", "\\"))
        or _HOME_RELATIVE.match(stripped) is not None
        or _DRIVE_PATH.match(stripped) is not None
        or stripped == ".."
        or "../" in stripped
        or "..\\" in stripped
    )


def _looks_like_nested_path(key: str, value: str) -> bool:
    """Whether a string inside a container (or a mapping key) is a filesystem path.

    Stricter than :func:`_looks_like_path`, which still decides top-level arguments: a
    nested string is a path when its shape is absolute, home-relative or traversing, or
    when it sits under a path-named key and has a separator or a file extension, or when
    it has both a separator and a file extension. A MIME type (``application/json``),
    ``and/or`` in prose, or a bare word under ``source`` is not.
    """
    if _is_absolute_or_escaping(value):
        return True
    has_separator = "/" in value or "\\" in value
    has_extension = value.lower().endswith(_PATH_EXTENSIONS)
    if key.lower() in PATH_PARAM_NAMES:
        return (has_separator or has_extension) and "://" not in value
    return has_separator and has_extension and "://" not in value


def _filesystem_path(item: ArgumentValue) -> str | None:
    """The filesystem path one argument value names, or None when it names none.

    An ``os.PathLike`` always names one, and so does a ``file:`` URI, as a string or as a
    URL object (pydantic ``FileUrl`` / ``AnyUrl``, ``urllib.parse`` results); until
    0.10.28 a URL object never did, so ``FileUrl("file:///etc/shadow")`` skipped this gate.
    A URL object of any other scheme names no path; step 5 reads it as a URL. A top-level
    string does when :func:`_looks_like_path` says so (unchanged); a nested string or a
    mapping key when :func:`_looks_like_nested_path` does. Bytes count only under a
    path-named key and only when they are shaped like a path (absolute or traversing, no
    NUL): ``open(b"/etc/passwd")`` works, but most bytes arguments are content, and an
    upload's bytes under ``file=`` are not a path.
    """
    value = item.value
    pathlike = path_text(value)
    if pathlike is not None:
        return pathlike
    url = url_text(value)
    if url is not None:
        return _file_uri_path(url)
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if item.key.lower() not in PATH_PARAM_NAMES or b"\x00" in raw or len(raw) > 4096:
            return None
        decoded = os.fsdecode(raw)
        return decoded if _is_absolute_or_escaping(decoded) else None
    if not isinstance(value, str):
        return None
    file_path = _file_uri_path(value)
    if file_path is not None:
        return file_path
    if item.depth == 0 and not item.is_key:
        return value if _looks_like_path(item.key, value) else None
    return value if _looks_like_nested_path(item.key, value) else None


def _endpoint_url(item: ArgumentValue) -> str | None:
    """The URL one argument value names, or None when it names none.

    A URL object (pydantic ``AnyUrl``, ``urllib.parse`` results, ``httpx.URL``) always
    names one. A string or bytes value does when it starts with a ``scheme://`` (any
    scheme, any case, after whitespace) or, for a value rather than a mapping key, when it
    sits under a URL-named key.
    """
    value = item.value
    url = url_text(value)
    if url is not None:
        return url
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", "replace")
    if not isinstance(value, str):
        return None
    if _URL_SCHEME_PREFIX.match(value) is not None:
        return value.strip()
    if not item.is_key and item.key.lower() in URL_PARAM_NAMES:
        return value.strip()
    return None


def _extract_token_usage(result: Any) -> TokenUsage | None:
    """Best-effort extraction of TokenUsage from a tool result (v0.8.7).

    Tries, in order:
      1. ``result.token_usage`` attribute (direct TokenUsage or dict-like).
      2. ``result["token_usage"]`` key (dict-style result envelopes).
      3. ``result.usage`` attribute with ``input_tokens`` / ``output_tokens``
         (OpenAI / Anthropic SDK convention).
    Returns None on any failure or absence — reconciliation is best-effort.
    """
    if result is None:
        return None
    candidate: Any = None
    # 1. Direct attribute
    candidate = getattr(result, "token_usage", None)
    # 2. Dict-style envelope
    if candidate is None and isinstance(result, dict):
        candidate = result.get("token_usage")
    # 3. LLM SDK ``usage`` attribute
    if candidate is None:
        candidate = getattr(result, "usage", None)
    if candidate is None:
        return None
    # Coerce to TokenUsage
    if isinstance(candidate, TokenUsage):
        return candidate
    try:
        if isinstance(candidate, dict):
            return TokenUsage(
                input_tokens=int(candidate.get("input_tokens", 0)),
                output_tokens=int(candidate.get("output_tokens", 0)),
            )
        # Duck-typed: read attributes
        input_tokens = int(getattr(candidate, "input_tokens", 0))
        output_tokens = int(getattr(candidate, "output_tokens", 0))
        if input_tokens == 0 and output_tokens == 0:
            return None
        return TokenUsage(input_tokens=input_tokens, output_tokens=output_tokens)
    except (TypeError, ValueError):
        return None


def _sanitize_tool_output(
    result: Any, config: AirlockConfig, func_name: str
) -> tuple[Any, list[str], int, bool]:
    """Mask sensitive data in a tool's result without changing its type.

    Returns ``(result, warnings, masked_count, was_truncated)``. A string is masked and
    truncated as it always was. A dict, list, tuple or set is masked value by value,
    keys included, and keeps its shape; ``max_output_chars`` does not apply to it,
    because truncating its serialized form would hand back a different type. Anything
    else is returned as it is, since rebuilding an arbitrary object with masked fields
    could break its own invariants, and what was detected in it is reported as *not*
    masked. So is what was detected in such an object inside a container (until 0.10.28
    those were skipped without a word).

    This replaced a defect as old as the sanitizer: every non-string result was
    serialized to JSON, masked, and the masked text discarded, while the log said
    ``output_sanitized``, the warning said "Masked N" and the audit record counted N,
    for data returned raw.
    """
    options: dict[str, Any] = {
        "mask_pii": config.mask_pii,
        "mask_secrets": config.mask_secrets,
        "pii_locales": config.pii_locales or None,
    }
    if isinstance(result, str):
        max_chars = config.max_output_chars if config.max_output_chars > 0 else None
        sanitization = sanitize_output(result, max_chars=max_chars, **options)
        warnings = _masked_warnings(sanitization.detection_count, func_name)
        if sanitization.was_truncated:
            warnings.append(
                f"Output truncated from {sanitization.original_length:,} "
                f"to {sanitization.sanitized_length:,} characters"
            )
        return (
            sanitization.content,
            warnings,
            sanitization.detection_count,
            sanitization.was_truncated,
        )
    if isinstance(result, dict | list | tuple | set | frozenset):
        try:
            report = sanitize_structured_report(result, **options)
        except RecursionError as error:
            raise OutputUnreadableError(func_name, "nested too deeply to mask") from error
        except Exception as error:  # noqa: BLE001 - a container that cannot be read is refused
            raise OutputUnreadableError(
                func_name, f"{type(error).__name__} while masking"
            ) from error
        warnings = _masked_warnings(report.masked_count, func_name)
        output_type = type(result).__name__
        for leaf_type, found in report.unmasked.items():
            logger.warning(
                "output_sensitive_data_unmasked",
                function=func_name,
                detections=found,
                output_type=output_type,
                value_type=leaf_type,
            )
            warnings.append(
                f"Detected {found} sensitive value(s) in {leaf_type} inside "
                f"{output_type} output; not masked"
            )
        for leaf_type, count in report.unreadable.items():
            warnings.append(_unreadable_warning(func_name, leaf_type, count, output_type))
        return report.value, warnings, report.masked_count, False
    output_type = type(result).__name__
    try:
        detected = sanitize_output(result, **options).detection_count
    except Exception:  # noqa: BLE001 - an object with no text is reported, never raised
        return result, [_unreadable_warning(func_name, output_type)], 0, False
    if not detected:
        return result, [], 0, False
    logger.warning(
        "output_sensitive_data_unmasked",
        function=func_name,
        detections=detected,
        output_type=output_type,
    )
    return (
        result,
        [f"Detected {detected} sensitive value(s) in {output_type} output; not masked"],
        0,
        False,
    )


def _unreadable_warning(
    func_name: str, value_type: str, count: int = 1, output_type: str | None = None
) -> str:
    """Log, and word as a warning, output values whose text could not be read.

    Until 0.10.28 the exception their ``str()`` raised escaped the call after the tool
    ran, before its audit record was written. They are returned as they are, unchecked.
    """
    logger.warning(
        "output_value_unreadable",
        function=func_name,
        values=count,
        value_type=value_type,
        output_type=output_type or value_type,
    )
    if output_type is None:
        return f"{value_type} output could not be read; not checked"
    return (
        f"{count} {value_type} value(s) inside {output_type} output could not be read; not checked"
    )


class OutputUnreadableError(AirlockError):
    """A tool's result could not be read to be masked, so the call is refused.

    It stands in for a result nested too deeply for the output walk to rebuild: returning
    it would hand back unmasked every string the walk would have masked. A deferred result
    raises it to its consumer for a value it produced that cannot be read. Until 0.10.28 a
    ``RecursionError`` escaped the call instead, after the tool ran and with no audit record.

    Attributes:
        function: The tool's name.
        reason: Why its result could not be read.
    """

    def __init__(self, function: str, reason: str) -> None:
        self.function = function
        self.reason = reason
        super().__init__(f"the result of '{function}' could not be read: {reason}")


class _ResultRefused(Exception):  # noqa: N818 - private control flow, not an error
    """Carries the refusal ``_post_execution`` made of a result back to the wrapper."""

    def __init__(self, response: dict[str, Any]) -> None:
        self.response = response
        super().__init__(response.get("error"))


@contextlib.contextmanager
def _call_scope(config: AirlockConfig, context: AirlockContext[Any] | None) -> Iterator[None]:
    """The call's context and network airgap, which the tool's body runs inside.

    The airgap is entered whenever ``network_policy`` is set. Until 0.10.28 it was entered
    only when the policy disallowed egress, so a host or port allowlist, or ``block_dns``,
    on a policy that allowed egress was never applied.
    """
    token = set_current_context(context) if context is not None else None
    try:
        if config.network_policy is not None:
            with network_airgap(config.network_policy):
                yield
        else:
            yield
    finally:
        if token is not None:
            reset_context(token)


#: Told about an exception a deferred result raised while producing a value, before it
#: reaches the consumer, so the call's refusal is audited (``_post_execution``).
_RefusalReporter = Callable[[Exception], None]


def _refusal_reason(error: BaseException) -> BlockReason | None:
    """The block reason of an Airlock refusal raised while a deferred result ran, or None.

    In the middle of a stream a refusal reaches the consumer as the exception itself, not
    as a refusal response; this names it for the audit record. Anything else is the
    tool's own error.
    """
    if isinstance(error, NetworkBlockedError):
        return BlockReason.NETWORK_BLOCKED
    if isinstance(error, PathValidationError):
        return BlockReason.PATH_VIOLATION
    if isinstance(error, CapabilityDeniedError):
        return BlockReason.CAPABILITY_DENIED
    if isinstance(error, AirlockBudgetExceeded):
        return BlockReason.BUDGET_EXCEEDED
    if isinstance(error, GhostArgumentError):
        return BlockReason.GHOST_ARGUMENTS
    if isinstance(error, PolicyEscalation):
        return BlockReason.ESCALATION_REQUIRED
    if isinstance(error, PolicyViolation):
        if error.violation_type == ViolationType.RATE_LIMITED.value:
            return BlockReason.RATE_LIMIT
        return BlockReason.POLICY_VIOLATION
    if isinstance(error, OutputUnreadableError):
        return BlockReason.OUTPUT_UNREADABLE
    return None


def _report_refusal(on_refusal: _RefusalReporter | None, error: Exception) -> None:
    """Hand ``error`` to ``on_refusal``. Never raises, so the error itself propagates."""
    if on_refusal is None:
        return
    try:
        on_refusal(error)
    except Exception as e:  # the refusal still reaches the consumer
        logger.error("deferred_refusal_audit_failed", error=str(e))


def _is_resource_handle(value: Any) -> bool:
    """A context manager (an open file, ``os.scandir``, a mock): its lifecycle is the caller's."""
    kind = type(value)
    return hasattr(kind, "__enter__") or hasattr(kind, "__aenter__")


def _guard_deferred(
    result: Any,
    config: AirlockConfig,
    func_name: str,
    context: AirlockContext[Any] | None,
    on_refusal: _RefusalReporter | None = None,
) -> Any | None:
    """The guarded form of a result whose body runs after the call returns, or None.

    A generator, an async generator, a coroutine, and a lazy iterator or async iterator
    (``map``, ``filter``, ``zip``, a class with ``__next__`` / ``__anext__``) compute their
    values when the caller asks for them, after ``@Airlock`` has returned. Each is wrapped
    so every step runs inside the call's airgap and context and every value it produces is
    sanitized as a returned value would be. Until 0.10.28 only generators were: a sync
    tool returning a coroutine or a ``map`` ran its body outside the airgap, without the
    call's context, and unmasked.

    Concrete values (strings, containers, models) are not deferred. Neither is an
    iterator that is also a context manager, whose lifecycle stays the caller's, nor an
    asyncio Task or Future, which runs on the loop whether or not it is awaited.
    """
    if inspect.isgenerator(result):
        return _guard_stream(result, config, func_name, context, on_refusal)
    if inspect.isasyncgen(result):
        return _guard_async_stream(result, config, func_name, context, on_refusal)
    if inspect.iscoroutine(result):
        return _guard_coroutine(result, config, func_name, context, on_refusal)
    if _is_resource_handle(result):
        return None
    if isinstance(result, Iterator):
        return _guard_iterator(result, config, func_name, context, on_refusal)
    if isinstance(result, AsyncIterator):
        return _guard_async_iterator(result, config, func_name, context, on_refusal)
    return None


#: The containers a result is walked through for deferred values, as output masking walks
#: it (``sanitizer.sanitize_structured``).
_RESULT_CONTAINERS = (dict, list, tuple, set, frozenset)

#: Leaf types that are never deferred, checked first so a large result is scanned quickly.
_PLAIN_TYPES = frozenset({str, bytes, bytearray, int, float, complex, bool, type(None)})


def _is_deferred(value: Any) -> bool:
    """Whether ``value`` computes its values after the call: what ``_guard_deferred`` guards."""
    if inspect.isgenerator(value) or inspect.isasyncgen(value) or inspect.iscoroutine(value):
        return True
    if _is_resource_handle(value):
        return False
    return isinstance(value, Iterator | AsyncIterator)


def _is_rebuilt_shape(value: Any) -> bool:
    """A dict, list, tuple, set, pydantic model or dataclass instance: what the guard rebuilds."""
    return isinstance(value, (*_RESULT_CONTAINERS, BaseModel)) or (
        dataclasses.is_dataclass(value) and not isinstance(value, type)
    )


def _items_inside(node: Any) -> Iterable[Any]:
    """The values inside a dict (its keys too), list, tuple, set, model or dataclass."""
    if isinstance(node, dict):
        return [*node.keys(), *node.values()]
    if isinstance(node, BaseModel):  # BaseModel's own __iter__, whatever a model overrides
        return [value for _name, value in BaseModel.__iter__(node)]
    if isinstance(node, _RESULT_CONTAINERS):
        return node
    return [getattr(node, item.name, None) for item in dataclasses.fields(node)]


def _holds_deferred(result: Any) -> bool:
    """Whether a deferred value is anywhere in ``result``'s containers, models and dataclasses."""
    pending = [result]
    seen: set[int] = set()
    while pending:
        node = pending.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        for item in _items_inside(node):
            if type(item) in _PLAIN_TYPES:
                continue
            if _is_rebuilt_shape(item):
                pending.append(item)
            elif _is_deferred(item):
                return True
    return False


def _guard_nested_deferred(
    result: Any,
    config: AirlockConfig,
    func_name: str,
    context: AirlockContext[Any] | None,
    on_refusal: _RefusalReporter | None = None,
) -> Any:
    """``result`` with every deferred value inside it guarded.

    A generator, coroutine or lazy iterator held in a returned dict, list, tuple, set,
    pydantic model or dataclass runs when the caller reaches it, after the call. Until
    0.10.28 only one returned at the top level was guarded: ``{"rows": map(fetch, urls)}``
    ran outside the airgap, without the call's context, and unmasked. ``result`` itself
    comes back when it holds none; otherwise every container in it is rebuilt with each
    deferred value guarded (dict keys included; a model through ``model_copy``, a
    dataclass as a shallow copy, so neither runs its validation or ``__init__`` again), a
    container referenced twice or from inside itself once.

    Raises:
        OutputUnreadableError: ``result`` is nested too deeply to rebuild, or one of its
            containers raised while it was read or rebuilt.
    """
    if not _is_rebuilt_shape(result):
        return result
    memo: dict[int, Any] = {}

    def rebuild(node: Any) -> Any:
        if type(node) in _PLAIN_TYPES:
            return node
        if id(node) in memo:
            return memo[id(node)]
        if isinstance(node, dict):
            mapping = copy.copy(node)
            memo[id(node)] = mapping  # registered first, so a back-reference reaches the copy
            entries = [(rebuild(key), rebuild(item)) for key, item in node.items()]
            mapping.clear()
            for key, item in entries:  # one by one: Counter.update would add, not set
                mapping[key] = item
            return mapping
        if isinstance(node, list):
            items = copy.copy(node)
            memo[id(node)] = items
            items[:] = [rebuild(item) for item in node]
            return items
        if isinstance(node, _RESULT_CONTAINERS):
            rebuilt: Any = _rebuild_like(node, [rebuild(item) for item in node])
        elif isinstance(node, BaseModel):
            fields = BaseModel.__iter__(node)
            rebuilt = node.model_copy(update={name: rebuild(value) for name, value in fields})
        elif dataclasses.is_dataclass(node) and not isinstance(node, type):
            rebuilt = copy.copy(node)
            memo[id(node)] = rebuilt
            for item in dataclasses.fields(node):
                if hasattr(node, item.name):  # set as the dataclass's own __init__ sets it
                    object.__setattr__(rebuilt, item.name, rebuild(getattr(node, item.name)))
            return rebuilt
        else:
            guarded = _guard_deferred(node, config, func_name, context, on_refusal)
            rebuilt = node if guarded is None else guarded
        memo[id(node)] = rebuilt
        return rebuilt

    try:
        return rebuild(result) if _holds_deferred(result) else result
    except RecursionError as error:
        raise OutputUnreadableError(func_name, "nested too deeply to guard") from error
    except Exception as error:  # noqa: BLE001 - a container that cannot be rebuilt is refused
        raise OutputUnreadableError(func_name, f"{type(error).__name__} while guarding") from error


def _guard_result(
    result: Any,
    config: AirlockConfig,
    func_name: str,
    context: AirlockContext[Any] | None,
    on_refusal: _RefusalReporter | None = None,
) -> tuple[Any, list[str], int, bool]:
    """A result as its caller gets it: deferred values guarded, everything else masked.

    Returns ``(result, warnings, masked_count, was_truncated)``. A deferred result is
    returned guarded and masked value by value as it produces them, so nothing is counted
    here.

    Raises:
        OutputUnreadableError: The result cannot be read to be masked.
    """
    guarded = _guard_deferred(result, config, func_name, context, on_refusal)
    if guarded is not None:
        return guarded, [], 0, False
    result = _guard_nested_deferred(result, config, func_name, context, on_refusal)
    if not config.sanitize_output or result is None:
        return result, [], 0, False
    return _sanitize_tool_output(result, config, func_name)


def _sanitize_stream_item(
    item: Any,
    config: AirlockConfig,
    func_name: str,
    context: AirlockContext[Any] | None = None,
    on_refusal: _RefusalReporter | None = None,
) -> Any:
    """One value a deferred result produced, guarded and sanitized as a returned value.

    A value that cannot be read is refused: ``OutputUnreadableError`` reaches the consumer
    after ``on_refusal`` has audited it.
    """
    try:
        return _guard_result(item, config, func_name, context, on_refusal)[0]
    except OutputUnreadableError as error:
        _report_refusal(on_refusal, error)
        raise


def _guard_stream(
    stream: Generator[Any, Any, Any],
    config: AirlockConfig,
    func_name: str,
    context: AirlockContext[Any] | None,
    on_refusal: _RefusalReporter | None = None,
) -> Generator[Any, Any, Any]:
    """Run a generator tool's body under the call's guards, one step at a time.

    A generator's body runs when it is iterated, after ``@Airlock`` has returned. Until
    0.10.20 it therefore ran outside the network airgap and without the call's context,
    and nothing it yielded was sanitized: a tool that streamed its output could reach
    the network under ``allow_egress=False`` and stream PII unmasked. Each step, and the
    cleanup when the stream is closed early, now runs inside both, and each item is
    sanitized as a returned value would be. Values sent in pass through and the return
    value is kept. A refusal a step raises (the airgap's ``NetworkBlockedError``, or any
    Airlock refusal the body raised) goes to ``on_refusal`` before it reaches the
    consumer; until 0.10.28 the stream's audit record was the only one.
    """
    try:
        sent: Any = None
        while True:
            try:
                with _call_scope(config, context):
                    try:
                        item = stream.send(sent)
                    except StopIteration as stop:
                        return stop.value
            except Exception as error:
                _report_refusal(on_refusal, error)
                raise
            sent = yield _sanitize_stream_item(item, config, func_name, context, on_refusal)
    finally:
        with _call_scope(config, context):
            stream.close()


async def _guard_async_stream(
    stream: AsyncGenerator[Any, Any],
    config: AirlockConfig,
    func_name: str,
    context: AirlockContext[Any] | None,
    on_refusal: _RefusalReporter | None = None,
) -> AsyncGenerator[Any, Any]:
    """The async-generator form of ``_guard_stream``."""
    try:
        sent: Any = None
        while True:
            try:
                with _call_scope(config, context):
                    try:
                        item = await stream.asend(sent)
                    except StopAsyncIteration:
                        return
            except Exception as error:
                _report_refusal(on_refusal, error)
                raise
            sent = yield _sanitize_stream_item(item, config, func_name, context, on_refusal)
    finally:
        with _call_scope(config, context):
            await stream.aclose()


async def _guard_coroutine(
    coroutine: Coroutine[Any, Any, Any],
    config: AirlockConfig,
    func_name: str,
    context: AirlockContext[Any] | None,
    on_refusal: _RefusalReporter | None = None,
) -> Any:
    """Await a coroutine a tool returned under the call's guards, and sanitize its value."""
    try:
        with _call_scope(config, context):
            value = await coroutine
    except Exception as error:
        _report_refusal(on_refusal, error)
        raise
    return _sanitize_stream_item(value, config, func_name, context, on_refusal)


def _guard_iterator(
    iterator: Iterator[Any],
    config: AirlockConfig,
    func_name: str,
    context: AirlockContext[Any] | None,
    on_refusal: _RefusalReporter | None = None,
) -> Generator[Any, None, None]:
    """Step a lazy iterator a tool returned under the call's guards, one item at a time.

    The iterator is closed inside the airgap when the guard is (if it has ``close``).
    """
    try:
        while True:
            try:
                with _call_scope(config, context):
                    try:
                        item = next(iterator)
                    except StopIteration:
                        return
            except Exception as error:
                _report_refusal(on_refusal, error)
                raise
            yield _sanitize_stream_item(item, config, func_name, context, on_refusal)
    finally:
        close = getattr(iterator, "close", None)
        if callable(close):
            with _call_scope(config, context):
                close()


async def _guard_async_iterator(
    iterator: AsyncIterator[Any],
    config: AirlockConfig,
    func_name: str,
    context: AirlockContext[Any] | None,
    on_refusal: _RefusalReporter | None = None,
) -> AsyncGenerator[Any, None]:
    """The async form of ``_guard_iterator``; ``aclose`` is called when the guard closes."""
    try:
        while True:
            try:
                with _call_scope(config, context):
                    try:
                        item = await iterator.__anext__()
                    except StopAsyncIteration:
                        return
            except Exception as error:
                _report_refusal(on_refusal, error)
                raise
            yield _sanitize_stream_item(item, config, func_name, context, on_refusal)
    finally:
        aclose = getattr(iterator, "aclose", None)
        if callable(aclose):
            with _call_scope(config, context):
                closing = aclose()
                if inspect.isawaitable(closing):
                    await closing


def _masked_warnings(count: int, func_name: str) -> list[str]:
    """The warning (and log line) for ``count`` values actually masked, or nothing."""
    if not count:
        return []
    logger.info("output_sanitized", function=func_name, detections=count)
    return [f"Masked {count} sensitive value(s) in output"]


def _caller_identity(context: AirlockContext[Any]) -> AgentIdentity | None:
    """The identity ``SecurityPolicy.check`` judges this call by, or ``None`` if it has none.

    ``context`` is read from the tool's first argument. A framework that passes none, or
    one without an agent id, leaves it empty; the context a host set around the call with
    ``with AirlockContext(agent_id=..., roles=[...])`` is used then. Until 0.10.13 no
    identity was passed at all, so ``require_agent_id`` refused every call and
    ``allowed_roles`` let every call through.
    """
    for candidate in (context, get_current_context()):
        if candidate is not None and candidate.agent_id:
            return AgentIdentity(
                agent_id=candidate.agent_id,
                session_id=candidate.session_id,
                roles=list(candidate.roles),
            )
    return None


def _inherit_ambient_identity(context: AirlockContext[Any]) -> None:
    """Give a call the identity and run ids of the context set around it, in place.

    The policy check has fallen back to the ambient context since 0.10.13, but the audit
    record, a policy resolver and ``get_current_context()`` inside the tool read the call's
    own context, so an identity set with ``with AirlockContext(...)`` was checked and never
    recorded. The agent id and roles are taken only when the call has none of its own. The
    session, workspace and user ids follow the rule ``_run_context`` applies: taken from
    the ambient context whenever the call lacks them, unless that context names a
    different agent. Until 0.10.26 they came only with an ambient agent id, so a run
    marked with ``with AirlockContext(session_id=...)`` alone kept no session on its
    calls: the per-run amplification ledger and the session-keyed guards folded every
    such run into one anonymous key.
    """
    ambient = get_current_context()
    if ambient is None or ambient is context:
        return
    if ambient.agent_id and context.agent_id and ambient.agent_id != context.agent_id:
        return
    if not context.agent_id and ambient.agent_id:
        context.agent_id = ambient.agent_id
        if not context.roles:
            context.roles = list(ambient.roles)
    context.session_id = context.session_id or ambient.session_id
    context.workspace_id = context.workspace_id or ambient.workspace_id
    context.user_id = context.user_id or ambient.user_id


def _run_context(context: AirlockContext[Any]) -> AirlockContext[Any] | None:
    """The ``AirlockContext`` that outlives this call, or None when there is none.

    That is an ``AirlockContext`` the call's run wrapper carries (``context.user_context``,
    a first argument ``ContextExtractor.run_wrapper`` accepted), else the one set around
    the call with ``with AirlockContext(...)`` — unless that one names a different agent
    than the call does, so belongs to another run. The wrapper is judged by the same
    predicate that admitted it; until 0.10.28 any first argument with a ``context`` /
    ``ctx`` attribute counted, in an order ``PYTHONHASHSEED`` decided.
    """
    wrapper = (
        ContextExtractor.run_wrapper(context.user_context)
        if context.user_context is not None
        else None
    )
    if wrapper is not None and isinstance(wrapper.context, AirlockContext):
        return wrapper.context
    ambient = get_current_context()
    if ambient is None or ambient is context:
        return None
    if ambient.agent_id and context.agent_id and ambient.agent_id != context.agent_id:
        return None
    return ambient


def _share_run_state(context: AirlockContext[Any]) -> AirlockContext[Any] | None:
    """Point this call's context at the run's guard state, in place; return the run's context.

    ``ContextExtractor`` builds a new context for every call, so until 0.10.23 the untrusted-
    output count and the ``authorize_once`` grants lived on an object the next call never saw:
    ``reauth_on_untrusted_reinvocation`` never fired, a tripped action-contradiction gate could
    not be re-opened, and a signal set on the run's metadata never reached that gate. The count
    and the grants are shared, not copied, so a mark or a consumed grant lands on the run. The
    run's metadata goes under the call's own, the precedence ``_call_metadata`` already uses.
    """
    run = _run_context(context)
    if run is None:
        return None
    context.untrusted_reinvocation_count = run.untrusted_reinvocation_count
    context._authorized_once = run._authorized_once
    context.metadata = {**run.metadata, **context.metadata}
    return run


# The keyword arguments a router once tagged a call with. See _warn_on_retired_control_arguments.
_RETIRED_CONTROL_ARGUMENTS = ("_airlock_tier", "_airlock_input_tokens")


def _call_metadata(context: AirlockContext[Any], key: str) -> Any:
    """A tag a host set on this call: the call's own context metadata first, then the context
    set around the call with ``with AirlockContext(metadata={...})``.

    The budget and amplification checks read ``airlock_tier``, ``input_tokens`` and
    ``model_id`` here and nowhere else, the token-audience check its claims and the
    deserialization guard its transport declaration. The model cannot write either context:
    the call's own comes only from a run wrapper model JSON cannot build
    (``ContextExtractor.run_wrapper``); until 0.10.28 a tool's own model with a ``context``
    field passed first supplied it.
    """
    value = context.metadata.get(key)
    if value is not None:
        return value
    ambient = get_current_context()
    return ambient.metadata.get(key) if ambient is not None else None


def _token_count_tag(value: Any) -> int | None:
    """The ``input_tokens`` tag as a count, or None when it is not one.

    A count is an integer of zero or more: any ``numbers.Integral`` (numpy's included),
    never a bool. Until 0.10.28 anything but an ``int`` (a float, a string, a numpy
    integer) was priced as 0 tokens, and a negative ``int`` raised out of the call.
    """
    if isinstance(value, bool) or not isinstance(value, numbers.Integral):
        return None
    count = int(value)
    return count if count >= 0 else None


def _text_tag(value: Any) -> str | None:
    """A tag's text when it is a string, a str enum by its value; else None."""
    return str.__str__(value) if isinstance(value, str) else None


def _model_id_tag(value: Any) -> str | None:
    """The ``model_id`` step 6 prices the call's worst case by, or None when untagged.

    A string, a str enum by its value, is the model id. Any other value names no row of
    the pricing table, so it is priced as an unlisted model is, at the table's dearest row.
    Until 0.10.28 a bytes or enum ``model_id`` was priced at the tracker's own row.
    """
    if value is None:
        return None
    text = _text_tag(value)
    return text if text is not None else f"<unreadable model_id: {type(value).__name__}>"


#: What each step-6 tag must be, for the refusal that names an unreadable one.
_BUDGET_TAG_SHAPES = {
    "airlock_tier": "a string naming one of the budget's tiers",
    "input_tokens": "an integer count of zero or more",
}


#: The ``AirlockContext`` metadata key the host puts an OAuth access token's claims under:
#: the decoded claims of a token whose signature, expiry and issuer the host has verified.
#: ``AirlockConfig.expected_token_audience`` checks their ``aud``. Like every key
#: ``_call_metadata`` reads, it is the host's to set; a tool argument of the same name is
#: the model's, and is never read for it.
ACCESS_TOKEN_CLAIMS_KEY = "access_token_claims"  # nosec B105 - a metadata key, not a secret


def _token_audience_problem(claims: Any, expected_audience: str) -> tuple[str, str] | None:
    """Why ``claims`` do not show a token issued for ``expected_audience``, or None.

    Returns:
        ``(code, detail)``: ``no_claims`` when the host attached none, ``claims_unreadable``
        when they are not a mapping, ``audience_mismatch`` when
        ``validate_access_token_audience`` refuses them; ``detail`` is for the operator.
    """
    from .mcp_spec.oauth import (
        ResourceURIError,
        TokenAudienceError,
        validate_access_token_audience,
    )

    if claims is None:
        return (
            "no_claims",
            f"the call carries no access token claims (AirlockContext metadata "
            f"{ACCESS_TOKEN_CLAIMS_KEY!r})",
        )
    if not isinstance(claims, Mapping):
        return (
            "claims_unreadable",
            f"the access token claims are a {type(claims).__name__}, not a mapping",
        )
    try:
        validate_access_token_audience(dict(claims), expected_audience=expected_audience)
    except (TokenAudienceError, ResourceURIError) as exc:
        return "audience_mismatch", str(exc)
    return None


def _warn_on_retired_control_arguments(func_name: str, kwargs: dict[str, Any]) -> None:
    """Point a router still passing ``_airlock_tier`` / ``_airlock_input_tokens`` at metadata.

    Until 0.10.14 those keyword arguments were popped and read as the call's tier and token
    count. In every framework that passes the model's arguments as keywords the model writes
    them, so a model could lower its own budget estimate or pick its tier. They are now
    ordinary arguments, stripped or refused as ghosts unless the tool declares them.
    """
    present = [name for name in _RETIRED_CONTROL_ARGUMENTS if name in kwargs]
    if present:
        logger.warning(
            "airlock_control_arguments_ignored",
            function=func_name,
            arguments=present,
            hint="tag the call with AirlockContext(metadata={'airlock_tier': ..., "
            "'input_tokens': ...}); tool arguments are the model's to write",
        )


def _model_safe_policy_reason(func_name: str, violation: PolicyViolation) -> str:
    """The reason a policy refusal gives the model: the violation's message, minus any deny glob.

    A ``tool_denied`` message quotes the ``denied_tools`` pattern that matched. The refusal
    reaches a model whose context may be attacker-influenced, and a deny list is incomplete
    by nature: quoting the entry that matched helps a search for a tool name it misses.
    Until 0.10.25 the model read it. The other messages ``SecurityPolicy`` raises name no
    deny pattern: a time window and the roles a tool requires describe what is allowed.
    """
    if violation.violation_type == ViolationType.TOOL_DENIED.value:
        return f"Tool '{func_name}' is denied by policy"
    return violation.message


class Airlock:
    """Decorator that secures function calls with validation, sandboxing, and policies.

    Example:
        @Airlock()
        def read_file(filename: str) -> str:
            with open(filename) as f:
                return f.read()

        @Airlock(sandbox=True)
        def run_code(code: str) -> str:
            exec(code)
            return "executed"

        @Airlock(config=AirlockConfig(strict_mode=True))
        def delete_record(id: int) -> bool:
            ...
    """

    def __init__(
        self,
        _func: Callable[..., Any] | None = None,
        /,
        *,
        sandbox: bool = False,
        sandbox_required: bool = False,
        config: AirlockConfig | None = None,
        policy: SecurityPolicy | PolicyResolver | None = None,
        return_dict: bool = False,
    ) -> None:
        """Initialize the Airlock decorator.

        ``Airlock`` takes its options first, so it is written ``@Airlock()`` with the
        parentheses. The lowercase ``@airlock`` also works without them.

        Args:
            _func: Not an option. Bare ``@Airlock`` passes the function here, and it is
                refused with a TypeError that says to add the parentheses; until 0.10.19
                the TypeError only said too many positional arguments were given.
            sandbox: If True, execute the function in an E2B sandbox. When E2B is
                    missing or the sandbox fails, the call is refused with a
                    ``sandbox_error`` response; it is not run here instead.
            sandbox_required: If True and sandbox=True, refuse the call even in the one
                            case sandbox=True alone runs it locally: the
                            ``agent_airlock.sandbox`` module failing to import.
                            SECURITY: Always set this to True for dangerous operations
                            like exec() to prevent accidental local execution.
            config: Configuration options. Uses DEFAULT_CONFIG if not provided.
            policy: Security policy to enforce (RBAC, rate limits, time restrictions).
                   Can be a SecurityPolicy instance or a callable that takes an
                   AirlockContext and returns a SecurityPolicy (for dynamic resolution).
            return_dict: If True, always return AirlockResponse as dict.
                        If False (default), return the raw result on success,
                        and AirlockResponse dict on error.
        """
        if _func is not None:
            raise TypeError(
                "Airlock takes its options first: write @Airlock() with parentheses, "
                "or use @airlock, which also works without them"
            )
        self.sandbox = sandbox
        self.sandbox_required = sandbox_required
        self.config = config or DEFAULT_CONFIG
        self.policy = policy
        self.return_dict = return_dict

    @overload
    def __call__(self, func: Callable[P, R]) -> Callable[P, R | dict[str, Any]]: ...

    @overload
    def __call__(
        self, func: None = None
    ) -> Callable[[Callable[P, R]], Callable[P, R | dict[str, Any]]]: ...

    def __call__(
        self,
        func: Callable[P, R] | None = None,
    ) -> (
        Callable[P, R | dict[str, Any]]
        | Callable[[Callable[P, R]], Callable[P, R | dict[str, Any]]]
    ):
        """Apply the Airlock decorator to a function.

        ``@Airlock(...)`` builds the decorator and calls this with the decorated function.
        Called with no function, it returns the decorator itself.
        """
        if func is None:
            return self._decorator

        return self._decorator(func)

    def _decorator(self, func: Callable[P, R]) -> Callable[P, R | dict[str, Any]]:
        """The actual decorator implementation.

        Detects if the function is async and creates the appropriate wrapper.
        Both sync and async wrappers share the same validation logic.
        """
        # Create strict validator wrapper
        validated_func = create_strict_validator(func)
        # The same contract, in a form the sandbox dispatch can use (V0.10.6).
        # `validated_func` validates on the way into a call, which is no help on a path
        # that never calls it: `sandbox=True` ships the *undecorated* `func` into the
        # micro-VM, so every `Annotated` validator was silently skipped there. Built once
        # here, next to the wrapper it mirrors, rather than per call.
        validate_sandbox_args = create_argument_validator(func)
        # Positional arguments are named against this signature for the gates that read
        # argument values (`_arg_walk.bind_arguments`); built once, not per call.
        call_signature = signature_of(func)
        is_async = asyncio.iscoroutinefunction(func)
        # The wrapper this decorator returns: assigned below, read by the capability gate
        # at call time, because ``@requires`` applied above ``@Airlock`` sets its attribute
        # on this object (until 0.10.26 the gate read ``func`` and never saw it).
        wrapper: Callable[..., Any]

        # Initialize audit logger
        audit_logger = AuditLogger(
            self.config.audit_log_path if self.config.enable_audit_log else None,
            self.config.enable_audit_log,
        )

        def _audit_honeypot(
            func_name: str,
            block_reason: str,
            start_time: float,
            args: dict[str, Any],
            context: AirlockContext[Any],
        ) -> None:
            """Record a refusal the caller was answered with honeypot data for.

            The caller sees fake success; the operator's audit log must still see the
            refusal. Until 0.10.24 a honeypot reply wrote no record at all.
            """
            audit_logger.log(
                tool_name=func_name,
                blocked=True,
                block_reason=block_reason,
                duration_ms=(time.time() - start_time) * 1000,
                args=args,
                agent_id=context.agent_id,
                session_id=context.session_id,
                honeypot=True,
            )

        def _pre_execution(
            func_name: str,
            args: tuple[Any, ...],
            kwargs: dict[str, Any],
        ) -> Generator[
            _ApprovalAsk,
            _ApproverOutcome,
            tuple[
                dict[str, Any],
                float,
                AirlockContext[Any],
                AirlockResponse | None,
                BudgetEstimate | None,
                SecurityPolicy | None,
            ],
        ]:
            """Shared pre-execution logic for sync and async wrappers.

            A generator: when step 2 escalates to an approver it yields an
            :class:`_ApprovalAsk` and resumes with the answer. The sync wrapper runs it
            with :func:`_drive`, the async one with :func:`_drive_async`.

            Runs the gates in the order the ``# Step N`` comments below number them: the
            kill switch (0), the startup-hook self-check (0.5), the OAuth token audience
            (0.6), ghost arguments (1), policy resolution and check (2), the
            sequence guard (2.5), the action-contradiction gate (2.6), the deserialization
            guard (2.7), the amplification budget (2.8), filesystem paths (3), capabilities
            (4), endpoint policies (5) and the per-model-tier budget (6). The first gate that
            refuses ends the call.

            Returns:
                Tuple of (cleaned_kwargs, start_time, context, error_response or None,
                          budget_estimate or None, resolved_policy or None). The estimate
                and the resolved policy are threaded to ``_post_execution``, which marks
                untrusted output and reconciles the tier budget against the policy the
                gates used, a resolver's included.
            """
            start_time = time.time()

            # Until 0.10.14 `_airlock_tier` and `_airlock_input_tokens` were popped here and
            # read as a router's tags. The model writes the keyword arguments in every
            # framework that passes its arguments as keywords, so they are now ordinary
            # arguments, stripped or refused as ghosts; a router tags the call through
            # AirlockContext metadata (`_call_metadata`).
            _warn_on_retired_control_arguments(func_name, kwargs)

            # Extract context from function arguments
            context = ContextExtractor.extract_from_args(args, kwargs)
            _inherit_ambient_identity(context)
            run_context = _share_run_state(context)

            logger.debug(
                "airlock_intercept",
                function=func_name,
                args_count=len(args),
                kwargs_keys=_filter_sensitive_keys(list(kwargs.keys())),
                is_async=is_async,
                agent_id=context.agent_id,
                session_id=context.session_id,
            )

            # Step 0: the kill switch, ahead of every other gate (V0.8.86).
            # A freeze means stop, not "stop after checking whether the arguments were
            # well-formed", so this runs before ghost-argument validation. No-op unless a
            # listener was installed via kill_switch.registry.install(); polling is bounded
            # by the listener's poll_interval_seconds so it is not a per-call transport read.
            if _kill_switch_frozen():
                listener = _kill_switch_get()
                reason = listener.last_reason if listener else ""
                logger.warning("airlock_kill_switch_block", function=func_name, reason=reason)
                frozen_error = AirlockResponse.blocked_response(
                    reason=BlockReason.KILL_SWITCH,
                    error=(
                        f"AIRLOCK_BLOCK: kill switch engaged; '{func_name}' refused."
                        + (f" Operator reason: {reason}" if reason else "")
                    ),
                    fix_hints=[
                        "An operator has frozen all tool calls for this fleet",
                        "This is not a per-call denial: retrying or changing arguments "
                        "will not help until the switch is reset",
                        "Resetting requires the configured multi-key quorum",
                    ],
                    metadata={"function": func_name, "operator_reason": reason},
                )
                self._safe_invoke_callback(
                    self.config.on_blocked,
                    "on_blocked",
                    func_name,
                    "kill switch engaged",
                    {"violation_type": "kill_switch", "operator_reason": reason},
                )
                return kwargs, start_time, context, frozen_error, None, None

            # Step 0.5: the startup-hook self-check (V0.10.27). A condition of the process,
            # so it comes before anything about the call. Off by default; when on, the walk
            # runs once per process, on the first call admitted with it on, and `deny`
            # refuses the calls of tools guarded by this config, not every tool in the process.
            hook_error = self._check_startup_hooks(func_name)
            if hook_error is not None:
                return kwargs, start_time, context, hook_error, None, None

            # Step 0.6: the OAuth token audience (V0.10.27, CVE-2026-115413). The
            # credential before the arguments, as a server checks who calls before what is
            # asked. Inert until expected_token_audience is set.
            audience_error = self._check_token_audience(func_name, context)
            if audience_error is not None:
                return kwargs, start_time, context, audience_error, None, None

            # Step 1: Validate and handle ghost arguments
            cleaned_kwargs, _, ghost_error = self._validate_ghost_arguments(func, func_name, kwargs)
            if ghost_error is not None:
                return kwargs, start_time, context, ghost_error, None, None

            # Step 2: Resolve and check security policy (an escalation waits here on the
            # approver, through the driver: yield from)
            resolved_policy, policy_error = yield from self._resolve_and_check_policy(
                func_name, context, run_context=run_context
            )
            if policy_error is not None:
                return kwargs, start_time, context, policy_error, None, None

            # Step 2.5: Behavioral tool-call sequence guard (V0.8.12).
            # Runs after the standard policy check so a denied tool never
            # gets recorded in the sequence trace in the first place.
            seq_error = self._check_sequence_guard(
                func_name=func_name,
                resolved_policy=resolved_policy,
                args=args,
                kwargs=cleaned_kwargs,
                context=context,
            )
            if seq_error is not None:
                return kwargs, start_time, context, seq_error, None, None

            # Step 2.6: Action-time contradiction gate (V0.8.15,
            # arXiv:2605.27157). Runs after the sequence guard so a
            # transition-blocked tool never advances the contradiction
            # state. Inert when policy.action_contradiction_gate is None.
            acg_error = self._check_action_contradiction_gate(
                func_name=func_name,
                resolved_policy=resolved_policy,
                context=context,
            )
            if acg_error is not None:
                return kwargs, start_time, context, acg_error, None, None

            # Steps 2.7, 2.75, 3 and 5 read argument values. Until 0.10.24 they read only
            # keyword arguments, and only str values, so a positional argument, a list of
            # paths, a pathlib.Path or a URL object walked past all three. They now read
            # every argument the call passes (`_arg_walk`), bound once and only when one of
            # them is on. A refusal from them hands the honeypot the arguments by name.
            # The run wrapper the context came from is left out when model JSON cannot have
            # built it (`ContextExtractor.run_wrapper`, the predicate that admitted it); one
            # only its AirlockContext vouches for (a dataclass or model wrapper) is walked,
            # that AirlockContext aside. Until 0.10.28 any first argument with a `context` /
            # `ctx` attribute was left out, the tool author's own model included.
            # (Not named `wrapper`: step 4 reads the decorator's own `wrapper` below.)
            run_wrapper = (
                ContextExtractor.run_wrapper(context.user_context)
                if context.user_context is not None
                else None
            )
            # An agent framework's own model is walked where the tool's annotations name
            # its class, the only place pydantic builds one from the model's JSON
            # (`_arg_walk.NamedModels`); one in host-injected state is left alone.
            arguments = (
                bind_arguments(
                    call_signature,
                    args,
                    cleaned_kwargs,
                    skip_first=run_wrapper is not None and run_wrapper.host_object,
                    named=named_models(func),
                )
                if self._reads_argument_values(func_name, resolved_policy)
                else cleaned_kwargs
            )

            # Step 2.7: Unsafe-deserialization content guard (V0.8.19,
            # CVE-2026-25874). Inspects argument VALUES for pickle /
            # marshal / dill / jsonpickle payloads (and serialized-object
            # args over an unauthenticated channel, as the host declares it
            # on the call's context metadata). Inert when
            # policy.deserialization_guard is None.
            deser_error = self._check_deserialization_guard(
                func_name=func_name,
                resolved_policy=resolved_policy,
                arguments=arguments,
                context=context,
            )
            if deser_error is not None:
                return arguments, start_time, context, deser_error, None, None

            # Step 2.75: Shell syntax and package specs in string arguments (V0.10.28).
            # Nine MCP server CVEs of 27-28 Oct 2026 spliced an ordinary string argument
            # (`repo`, `target`, `args`, `version`) into a shell or `pnpm add` on the
            # server; nothing on the call path read it for that. Its `dispatch_args` refuse
            # an argument naming a function the tool must not call: CVE-2026-119050 (Agno
            # PandasTools) passed a model-chosen name such as `read_pickle` to `getattr`.
            # Inert when policy.tool_arg_sink_guard is None.
            sink_error = self._check_tool_arg_sinks(
                func_name=func_name,
                resolved_policy=resolved_policy,
                arguments=arguments,
            )
            if sink_error is not None:
                return arguments, start_time, context, sink_error, None, None

            # Step 2.8: Per-run resource-amplification budget (V0.8.74,
            # issue #142, arXiv:2608.12273). Counts calls against the run and
            # compares them to the budget the policy declares. Runs after the
            # gates above, so a call one of them refuses is never charged to the
            # run's ledger; one that steps 3-6 or validation refuse already has
            # been. Inert when
            # policy.amplification_budget is None; blocks when it is set but
            # carries no threshold.
            amp_error = self._check_amplification(
                func_name=func_name,
                resolved_policy=resolved_policy,
                context=context,
                input_tokens=_token_count_tag(_call_metadata(context, "input_tokens")),
            )
            if amp_error is not None:
                return kwargs, start_time, context, amp_error, None, None

            # Step 3: Validate filesystem paths
            fs_error = self._validate_filesystem_paths(func_name, arguments)
            if fs_error is not None:
                return arguments, start_time, context, fs_error, None, None

            # Step 4: Check capability requirements, read from the wrapper and the chain
            # beneath it so a ``@requires`` above or below ``@Airlock`` counts.
            cap_error = self._check_capabilities(wrapper, func_name, resolved_policy)
            if cap_error is not None:
                return kwargs, start_time, context, cap_error, None, None

            # Step 5: Validate endpoint policies (V0.4.1)
            ep_error = self._validate_endpoint_policies(func_name, arguments)
            if ep_error is not None:
                return arguments, start_time, context, ep_error, None, None

            # Step 6: Per-model-tier budget check (V0.8.7)
            budget_estimate, budget_error = self._check_model_tier_budget(
                func_name=func_name,
                resolved_policy=resolved_policy,
                context=context,
            )
            if budget_error is not None:
                return kwargs, start_time, context, budget_error, None, None

            return cleaned_kwargs, start_time, context, None, budget_estimate, resolved_policy

        def _post_execution(
            func_name: str,
            result: Any,
            start_time: float,
            kwargs: dict[str, Any],
            context: AirlockContext[Any] | None = None,
            budget_estimate: BudgetEstimate | None = None,
            resolved_policy: SecurityPolicy | None = None,
        ) -> tuple[Any, list[str], int, bool]:
            """Shared post-execution logic for sync and async wrappers.

            ``resolved_policy`` is the policy the gates checked this call against, so a
            resolver's policy marks untrusted output and reconciles its budget the way a
            static one does (until 0.10.23 both read ``self.policy`` and skipped a resolver).

            Returns:
                Tuple of (processed_result, warnings, sanitized_count, was_truncated)
            """

            def _refuse_after_run(error: Exception, reason: BlockReason) -> AirlockResponse:
                """Log and audit a refusal made after the tool ran, and return it."""
                if isinstance(error, NetworkBlockedError):
                    response = handle_network_blocked(
                        func_name,
                        operation=error.operation,
                        target=error.target,
                        details=error.details,
                    )
                elif isinstance(error, OutputUnreadableError):
                    response = AirlockResponse.blocked_response(
                        reason=reason,
                        error=f"AIRLOCK_BLOCK: {error}",
                        fix_hints=[
                            "The tool ran, but its result could not be checked for sensitive "
                            "data, so it was withheld. Arguments that return a smaller or "
                            "flatter result may succeed."
                        ],
                    )
                else:
                    response = AirlockResponse.blocked_response(
                        reason=reason,
                        error=(
                            f"AIRLOCK_BLOCK: '{func_name}' was refused ({reason.value}) "
                            "while producing its result"
                        ),
                    )
                self._log_blocked(func_name, response, start_time)
                audit_logger.log(
                    tool_name=func_name,
                    blocked=True,
                    block_reason=reason.value,
                    duration_ms=(time.time() - start_time) * 1000,
                    args=kwargs,
                    error=response.error,
                    agent_id=context.agent_id if context else None,
                    session_id=context.session_id if context else None,
                    amplification=context._amplification if context else None,
                )
                return response

            def _audit_deferred_refusal(error: Exception) -> None:
                """Record a refusal a deferred result raised after the call returned.

                It reaches the consumer as the exception, mid-stream; until 0.10.28 it left
                no audit record of the block, only the call's own (not blocked) one.
                """
                reason = _refusal_reason(error)
                if reason is not None:
                    _refuse_after_run(error, reason)

            # A deferred result (a generator, a coroutine, a lazy iterator), or one held in
            # a returned container, runs after this call returns, so its values are guarded
            # and sanitized as they are produced, and this call's audit record counts none
            # of them. A result that cannot be read to be masked is refused, not returned.
            try:
                result, warnings, sanitized_count, was_truncated = _guard_result(
                    result, self.config, func_name, context, _audit_deferred_refusal
                )
            except OutputUnreadableError as error:
                refusal = _refuse_after_run(error, BlockReason.OUTPUT_UNREADABLE)
                raise _ResultRefused(refusal.to_dict()) from error

            elapsed = time.time() - start_time
            logger.info(
                "airlock_success",
                function=func_name,
                elapsed_ms=round(elapsed * 1000, 2),
                is_async=is_async,
            )

            # Audit log successful call
            audit_logger.log(
                tool_name=func_name,
                blocked=False,
                duration_ms=(time.time() - start_time) * 1000,
                sanitized_count=sanitized_count,
                truncated=was_truncated,
                args=kwargs,
                result=result,
                agent_id=context.agent_id if context else None,
                session_id=context.session_id if context else None,
                amplification=context._amplification if context else None,
            )

            # V0.8.6 camouflage-resistant guard: tool output flowing back
            # into the model context is treated as potentially untrusted.
            # Increment the counter so a SecurityPolicy with
            # reauth_on_untrusted_reinvocation=True can require a fresh
            # authorize_once() grant on the next call (arXiv:2605.22001).
            # The count lands on the run's context (_share_run_state).
            if (
                context is not None
                and resolved_policy is not None
                and resolved_policy.reauth_on_untrusted_reinvocation
            ):
                context.mark_untrusted_output(func_name)

            # V0.8.7: reconcile actual vs estimated cost for the tier
            # budget. Never raises — reconciliation is observability, not
            # a second gate, and it records nothing on the CostTracker. A hard
            # session cap needs the host to record each call's usage on a tracker
            # whose ``BudgetConfig.max_cost_per_session`` is set.
            if budget_estimate is not None and resolved_policy is not None:
                self._reconcile_tier_budget(
                    func_name=func_name,
                    result=result,
                    budget_estimate=budget_estimate,
                    policy=resolved_policy,
                )

            return result, warnings, sanitized_count, was_truncated

        def _handle_error(
            func_name: str,
            error: Exception,
            start_time: float,
            kwargs: dict[str, Any],
            context: AirlockContext[Any] | None = None,
        ) -> dict[str, Any]:
            """Handle execution errors and return appropriate response.

            ``context`` is optional and defaults to ``None`` so no existing caller changes
            shape; when supplied, the audit record carries the run identity. That matters for
            the V0.8.77 capability-handle rejections, which arrive on this path: "a handle
            was replayed across scopes" is not actionable without knowing *which run* did it.
            """
            if isinstance(error, ValidationError):
                response = handle_validation_error(error, func_name)
                self._safe_invoke_callback(
                    self.config.on_validation_error,
                    "on_validation_error",
                    func_name,
                    error,
                )
            elif isinstance(error, SandboxError):
                # The sandbox failed, not the tool: E2B was missing, no sandbox could be
                # created, or no result came back. Until 0.10.17 this got the generic
                # answer below, tagged validation_error.
                logger.error("sandbox_failed", function=func_name, error=str(error))
                response = AirlockResponse.blocked_response(
                    reason=BlockReason.SANDBOX_ERROR,
                    error=f"AIRLOCK_BLOCK: '{func_name}' could not run in its sandbox",
                    fix_hints=[
                        "The sandbox this tool runs in failed or is unavailable, so the "
                        "tool returned no result. Retrying may not help; tell the user if "
                        "it keeps failing."
                    ],
                )
            else:
                logger.exception("unexpected_error", function=func_name, error=str(error))
                response = AirlockResponse.blocked_response(
                    reason=BlockReason.VALIDATION_ERROR,
                    error=f"AIRLOCK_BLOCK: Unexpected error in '{func_name}'",
                    fix_hints=["An internal error occurred. Please try again."],
                )

            self._log_blocked(func_name, response, start_time)

            # Audit log blocked call
            audit_logger.log(
                tool_name=func_name,
                blocked=True,
                block_reason=response.block_reason.value if response.block_reason else "unknown",
                duration_ms=(time.time() - start_time) * 1000,
                args=kwargs,
                error=response.error,
                agent_id=context.agent_id if context else None,
                session_id=context.session_id if context else None,
            )

            return response.to_dict()

        if is_async:
            # Async wrapper for async functions
            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> R | dict[str, Any]:
                func_name = func.__name__
                (
                    cleaned_kwargs,
                    start_time,
                    context,
                    error_response,
                    budget_estimate,
                    resolved_policy,
                ) = await _drive_async(_pre_execution(func_name, args, dict(kwargs)))

                if error_response is not None:
                    # Check for honeypot response before returning error
                    if should_use_honeypot(self.config.honeypot_config):
                        block_reason = (
                            error_response.block_reason.value
                            if error_response.block_reason
                            else "unknown"
                        )
                        # Use async version to avoid blocking event loop
                        honeypot_result = await create_honeypot_response_async(
                            func_name,
                            cleaned_kwargs,
                            self.config.honeypot_config,
                            block_reason=block_reason,
                        )
                        if honeypot_result is not None:
                            _audit_honeypot(
                                func_name, block_reason, start_time, dict(kwargs), context
                            )
                            return honeypot_result  # type: ignore[no-any-return]

                    self._log_blocked(func_name, error_response, start_time)
                    audit_logger.log(
                        tool_name=func_name,
                        blocked=True,
                        block_reason=error_response.block_reason.value
                        if error_response.block_reason
                        else "unknown",
                        duration_ms=(time.time() - start_time) * 1000,
                        args=dict(kwargs),
                        error=error_response.error,
                        agent_id=context.agent_id,
                        session_id=context.session_id,
                        amplification=context._amplification,
                    )
                    return error_response.to_dict()

                # Set context as current for the duration of execution
                token = set_current_context(context)
                try:
                    # V0.3.0: Apply network airgap if configured
                    # Note: For async, we still use the sync context manager
                    # as socket operations are fundamentally sync. The airgap is per task
                    # (a ContextVar), so it holds across awaits without touching the
                    # host's other coroutines. Any NetworkPolicy is applied: until 0.10.28
                    # only one with allow_egress=False was, so allowlists were ignored.
                    if self.config.network_policy is not None:
                        with network_airgap(self.config.network_policy):
                            if self.sandbox:
                                # V0.10.6: validate in the parent before dispatching. On failure the
                                # ValidationError propagates to the shared `except Exception` below,
                                # which routes to _handle_error and returns the same AirlockResponse,
                                # BlockReason and fix_hints the non-sandbox path returns.
                                v_args, v_kwargs = validate_sandbox_args(args, cleaned_kwargs)
                                result = await self._execute_in_sandbox_async(
                                    func, *v_args, **v_kwargs
                                )
                            else:
                                result = await validated_func(*args, **cleaned_kwargs)  # type: ignore[misc]
                    else:
                        if self.sandbox:
                            # V0.10.6: validate in the parent before dispatching. On failure the
                            # ValidationError propagates to the shared `except Exception` below,
                            # which routes to _handle_error and returns the same AirlockResponse,
                            # BlockReason and fix_hints the non-sandbox path returns.
                            v_args, v_kwargs = validate_sandbox_args(args, cleaned_kwargs)
                            result = await self._execute_in_sandbox_async(func, *v_args, **v_kwargs)
                        else:
                            # Await the async validated function
                            # Type ignore: validated_func preserves async nature of func
                            result = await validated_func(*args, **cleaned_kwargs)  # type: ignore[misc]

                except NetworkBlockedError as e:
                    # Handle network blocking with potential honeypot
                    if should_use_honeypot(self.config.honeypot_config):
                        # Use async version to avoid blocking event loop
                        honeypot_result = await create_honeypot_response_async(
                            func_name,
                            cleaned_kwargs,
                            self.config.honeypot_config,
                            block_reason="network_blocked",
                        )
                        if honeypot_result is not None:
                            _audit_honeypot(
                                func_name, "network_blocked", start_time, cleaned_kwargs, context
                            )
                            return honeypot_result  # type: ignore[no-any-return]

                    response = handle_network_blocked(
                        func_name,
                        operation=e.operation,
                        target=e.target,
                        details=e.details,
                    )
                    self._log_blocked(func_name, response, start_time)
                    # The caller's identity, as every other refusal records it (until
                    # 0.10.28 a network refusal's record named no agent or session).
                    audit_logger.log(
                        tool_name=func_name,
                        blocked=True,
                        block_reason="network_blocked",
                        duration_ms=(time.time() - start_time) * 1000,
                        args=cleaned_kwargs,
                        error=response.error,
                        agent_id=context.agent_id,
                        session_id=context.session_id,
                        amplification=context._amplification,
                    )
                    return response.to_dict()
                except Exception as e:
                    return _handle_error(func_name, e, start_time, cleaned_kwargs, context)
                finally:
                    reset_context(token)

                try:
                    result, warnings, _, _ = _post_execution(
                        func_name,
                        result,
                        start_time,
                        cleaned_kwargs,
                        context,
                        budget_estimate,
                        resolved_policy,
                    )
                except _ResultRefused as refused:
                    return refused.response

                if self.return_dict:
                    return AirlockResponse.success_response(
                        result, warnings=warnings or None
                    ).to_dict()

                return result

            wrapper = async_wrapper
        else:
            # Sync wrapper for sync functions
            @functools.wraps(func)
            def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> R | dict[str, Any]:
                func_name = func.__name__
                (
                    cleaned_kwargs,
                    start_time,
                    context,
                    error_response,
                    budget_estimate,
                    resolved_policy,
                ) = _drive(_pre_execution(func_name, args, dict(kwargs)))

                if error_response is not None:
                    # Check for honeypot response before returning error
                    if should_use_honeypot(self.config.honeypot_config):
                        block_reason = (
                            error_response.block_reason.value
                            if error_response.block_reason
                            else "unknown"
                        )
                        honeypot_result = create_honeypot_response(
                            func_name,
                            cleaned_kwargs,
                            self.config.honeypot_config,
                            block_reason=block_reason,
                        )
                        if honeypot_result is not None:
                            _audit_honeypot(
                                func_name, block_reason, start_time, dict(kwargs), context
                            )
                            return honeypot_result  # type: ignore[no-any-return]

                    self._log_blocked(func_name, error_response, start_time)
                    audit_logger.log(
                        tool_name=func_name,
                        blocked=True,
                        block_reason=error_response.block_reason.value
                        if error_response.block_reason
                        else "unknown",
                        duration_ms=(time.time() - start_time) * 1000,
                        args=dict(kwargs),
                        error=error_response.error,
                        agent_id=context.agent_id,
                        session_id=context.session_id,
                        amplification=context._amplification,
                    )
                    return error_response.to_dict()

                # Set context as current for the duration of execution
                token = set_current_context(context)
                try:
                    # V0.3.0: Apply network airgap if configured. Any NetworkPolicy is
                    # applied: until 0.10.28 only one with allow_egress=False was, so
                    # allowlists were ignored.
                    if self.config.network_policy is not None:
                        with network_airgap(self.config.network_policy):
                            if self.sandbox:
                                # V0.10.6: validate in the parent before dispatching. On failure the
                                # ValidationError propagates to the shared `except Exception` below,
                                # which routes to _handle_error and returns the same AirlockResponse,
                                # BlockReason and fix_hints the non-sandbox path returns.
                                v_args, v_kwargs = validate_sandbox_args(args, cleaned_kwargs)
                                result = self._execute_in_sandbox(func, *v_args, **v_kwargs)
                            else:
                                result = validated_func(*args, **cleaned_kwargs)
                    else:
                        if self.sandbox:
                            # V0.10.6: validate in the parent before dispatching. On failure the
                            # ValidationError propagates to the shared `except Exception` below,
                            # which routes to _handle_error and returns the same AirlockResponse,
                            # BlockReason and fix_hints the non-sandbox path returns.
                            v_args, v_kwargs = validate_sandbox_args(args, cleaned_kwargs)
                            result = self._execute_in_sandbox(func, *v_args, **v_kwargs)
                        else:
                            result = validated_func(*args, **cleaned_kwargs)

                except NetworkBlockedError as e:
                    # Handle network blocking with potential honeypot
                    if should_use_honeypot(self.config.honeypot_config):
                        honeypot_result = create_honeypot_response(
                            func_name,
                            cleaned_kwargs,
                            self.config.honeypot_config,
                            block_reason="network_blocked",
                        )
                        if honeypot_result is not None:
                            _audit_honeypot(
                                func_name, "network_blocked", start_time, cleaned_kwargs, context
                            )
                            return honeypot_result  # type: ignore[no-any-return]

                    response = handle_network_blocked(
                        func_name,
                        operation=e.operation,
                        target=e.target,
                        details=e.details,
                    )
                    self._log_blocked(func_name, response, start_time)
                    # The caller's identity, as every other refusal records it (until
                    # 0.10.28 a network refusal's record named no agent or session).
                    audit_logger.log(
                        tool_name=func_name,
                        blocked=True,
                        block_reason="network_blocked",
                        duration_ms=(time.time() - start_time) * 1000,
                        args=cleaned_kwargs,
                        error=response.error,
                        agent_id=context.agent_id,
                        session_id=context.session_id,
                        amplification=context._amplification,
                    )
                    return response.to_dict()
                except Exception as e:
                    return _handle_error(func_name, e, start_time, cleaned_kwargs, context)
                finally:
                    reset_context(token)

                try:
                    result, warnings, _, _ = _post_execution(
                        func_name,
                        result,
                        start_time,
                        cleaned_kwargs,
                        context,
                        budget_estimate,
                        resolved_policy,
                    )
                except _ResultRefused as refused:
                    return refused.response

                if self.return_dict:
                    return AirlockResponse.success_response(
                        result, warnings=warnings or None
                    ).to_dict()

                return result

            wrapper = sync_wrapper

        # CRITICAL: Preserve function signature for framework introspection
        # LangChain, CrewAI, AutoGen, PydanticAI use inspect.signature() to
        # generate JSON schemas for LLM tool calls. Without this, the LLM
        # sees "empty arguments" and tool calls fail.
        with contextlib.suppress(ValueError, TypeError):
            wrapper.__signature__ = inspect.signature(func)  # type: ignore[union-attr]

        # Copy annotations for type-aware frameworks
        wrapper.__annotations__ = getattr(func, "__annotations__", {})

        # Names this wrapper as the one the capability gate reads. A decorator stacked above
        # copies the attribute (``functools.wraps``), so a ``@requires`` above both can find
        # this wrapper and add its requirement here (``capabilities.requires``).
        wrapper.__airlock_wrapper__ = wrapper  # type: ignore[union-attr]

        # Pydantic V2 pass-through: Copy validator attributes if they exist
        for attr in (
            "__pydantic_complete__",
            "__pydantic_config__",
            "__pydantic_decorators__",
            "__pydantic_fields__",
            "__pydantic_validator__",
            "__get_pydantic_core_schema__",
        ):
            if hasattr(func, attr):
                setattr(wrapper, attr, getattr(func, attr))

        return wrapper  # type: ignore[return-value]

    def _execute_in_sandbox(
        self,
        func: Callable[P, R],
        *args: P.args,
        **kwargs: P.kwargs,
    ) -> R:
        """Execute function in E2B sandbox (sync version).

        Serializes the function and arguments, executes in an isolated
        E2B Firecracker MicroVM, and returns the result.

        When E2B is missing or the sandbox fails, this raises ``SandboxExecutionError``
        and the call is refused; the function is not run here. The one local fallback is
        for ``agent_airlock.sandbox`` failing to import (see ``_without_sandbox_module``).
        """
        try:
            from .sandbox import execute_in_sandbox
        except ImportError:
            return self._without_sandbox_module(func)(*args, **kwargs)

        result = execute_in_sandbox(
            func,
            args=args,
            kwargs=dict(kwargs),
            config=self.config,
        )
        return self._sandbox_outcome(func, result, is_async=False)  # type: ignore[no-any-return]

    async def _execute_in_sandbox_async(
        self,
        func: Callable[P, R],
        *args: P.args,
        **kwargs: P.kwargs,
    ) -> R:
        """Execute function in E2B sandbox (async version).

        Uses asyncio to run the sandbox execution without blocking. An async function's
        coroutine is awaited inside the sandbox. Failures are handled as in the sync
        version.
        """
        try:
            from .sandbox import execute_in_sandbox_async
        except ImportError:
            validated_func = self._without_sandbox_module(func)
            if inspect.iscoroutinefunction(func):
                return await validated_func(*args, **kwargs)  # type: ignore[misc, no-any-return]
            return validated_func(*args, **kwargs)  # pragma: no cover - defensive code

        result = await execute_in_sandbox_async(
            func,
            args=args,
            kwargs=dict(kwargs),
            config=self.config,
        )
        return self._sandbox_outcome(func, result, is_async=True)  # type: ignore[no-any-return]

    @staticmethod
    def _sandbox_outcome(func: Callable[..., Any], result: Any, *, is_async: bool) -> Any:
        """Return a sandboxed call's result, or raise what its failure means.

        A tool that raised in the sandbox raises ``_SandboxedToolError``, which the
        decorator answers exactly as it answers a tool that raised in-process. Any other
        failure is the sandbox's own and raises ``SandboxExecutionError``, answered with a
        ``sandbox_error`` refusal.
        """
        if result.success:
            logger.info(
                "sandbox_execution_success",
                function=func.__name__,
                sandbox_id=result.sandbox_id,
                execution_time_ms=result.execution_time_ms,
                is_async=is_async,
            )
            return result.result
        if result.tool_failed:
            raise _SandboxedToolError(result.error or "the tool failed in the sandbox")
        raise SandboxExecutionError(
            f"Sandbox execution failed: {result.error}",
            details=result.to_dict(),
        )

    def _without_sandbox_module(self, func: Callable[P, R]) -> Callable[P, R]:
        """``agent_airlock.sandbox`` could not be imported: refuse, or run in-process.

        This is the only case ``sandbox=True`` runs a function locally, and only with
        ``sandbox_required=False``. The fallback used to wrap the whole sandbox call, so an
        ImportError raised while running it also sent the function here.
        """
        if self.sandbox_required:
            raise SandboxUnavailableError(
                f"Sandbox required for '{func.__name__}' but agent_airlock.sandbox could "
                "not be imported. SECURITY WARNING: This function was marked "
                "sandbox_required=True to prevent accidental local execution of dangerous "
                "code."
            ) from None
        logger.warning(
            "sandbox_fallback_local",
            function=func.__name__,
            message=(
                "agent_airlock.sandbox could not be imported; running in-process because "
                "sandbox_required=False"
            ),
        )
        return create_strict_validator(func)

    def _check_startup_hooks(self, func_name: str) -> AirlockResponse | None:
        """Refuse this config's calls in an interpreter running startup hooks it does not allow.

        Off unless this decorator's ``AirlockConfig.startup_hook_check`` is ``warn`` or
        ``deny``. The walk (``runtime.startup_hooks``) runs once per process, on the first
        call admitted with the check on, and each hook it finds is logged once; each config
        judges that one walk against its own ``startup_hook_allowlist``. ``deny`` then
        refuses every call to a tool guarded by this config, naming the files. A tool
        guarded by a config that does not set ``deny`` still runs in the same process. The
        hooks ran before this did; the check reports them and keeps the tools this config
        guards from running beside them, nothing more.

        Args:
            func_name: Name of the tool being called.

        Returns:
            A ``startup_hook`` refusal under ``deny`` while a hook is not allowlisted,
            otherwise ``None``.
        """
        mode = self.config.startup_hook_check
        if mode == "off":
            return None
        from .runtime.startup_hooks import (
            announce_startup_hook_findings,
            process_startup_hook_report,
        )

        report = process_startup_hook_report(self.config.startup_hook_allowlist)
        if report.clean:
            return None
        announce_startup_hook_findings(report, mode=mode)
        if mode == "warn":
            return None

        names = list(dict.fromkeys(finding.name for finding in report.findings))
        hooks = [finding.to_dict() for finding in report.findings]
        response = AirlockResponse.blocked_response(
            reason=BlockReason.STARTUP_HOOK,
            error=(
                f"AIRLOCK_BLOCK: '{func_name}' refused: this interpreter runs startup hooks "
                f"no allowlist covers ({', '.join(names)})"
            ),
            fix_hints=[
                "The process this tool runs in started with code its allowlist does not "
                "cover, so this tool, and every tool guarded the same way, does not run in it",
                "This is not a per-call denial: retrying or changing arguments will not "
                "help; tell the user the tool host needs attention",
            ],
            metadata={"function": func_name, "startup_hooks": hooks},
        )
        self._safe_invoke_callback(
            self.config.on_blocked,
            "on_blocked",
            func_name,
            "startup hooks not allowlisted: "
            + ", ".join(finding.path for finding in report.findings),
            {"violation_type": "startup_hook", "startup_hooks": hooks},
        )
        return response

    def _check_token_audience(
        self, func_name: str, context: AirlockContext[Any]
    ) -> AirlockResponse | None:
        """Check the call's OAuth access token was issued for this server (CVE-2026-115413).

        Inert until ``AirlockConfig.expected_token_audience`` is set. The claims are the
        ones the host verified and put on the call's context metadata under
        ``access_token_claims`` (``_call_metadata``), never a tool argument. Under
        ``token_audience_mode="warn"``, the default, a wrong or missing audience is logged
        and the call runs; under ``"deny"`` it is refused, and so is a call that carries
        no claims at all.

        Args:
            func_name: Name of the tool being called.
            context: The call's context, read for the claims and the run identity.

        Returns:
            A ``token_audience`` refusal under ``deny``, otherwise ``None``.
        """
        expected = self.config.expected_token_audience
        mode = self.config.token_audience_mode
        if expected is None or mode == "off":
            return None
        problem = _token_audience_problem(
            _call_metadata(context, ACCESS_TOKEN_CLAIMS_KEY), expected
        )
        if problem is None:
            return None
        code, detail = problem
        if mode == "warn":
            logger.warning(
                "airlock_token_audience_warn_only",
                function=func_name,
                violation=code,
                reason=detail,
                expected_audience=expected,
                agent_id=context.agent_id,
                session_id=context.session_id,
            )
            return None

        logger.warning(
            "airlock_token_audience_block",
            function=func_name,
            violation=code,
            reason=detail,
            expected_audience=expected,
            agent_id=context.agent_id,
            session_id=context.session_id,
        )
        refused = (
            "the access token on this call was not issued for this server"
            if code == "audience_mismatch"
            else "the call carries no access token claims this server can check"
        )
        response = AirlockResponse.blocked_response(
            reason=BlockReason.TOKEN_AUDIENCE,
            error=f"AIRLOCK_BLOCK: '{func_name}' refused: {refused}",
            fix_hints=[
                "The credential behind this call is not valid for this tool server; "
                "retrying or changing arguments will not help",
                "Tell the user the tool server refused the credential, so they can sign in to it",
            ],
            metadata={"function": func_name, "violation": code, "expected_audience": expected},
        )
        self._safe_invoke_callback(
            self.config.on_blocked,
            "on_blocked",
            func_name,
            detail,
            {"violation_type": "token_audience", "violation": code, "expected_audience": expected},
        )
        return response

    def _validate_ghost_arguments(
        self,
        func: Callable[..., Any],
        func_name: str,
        kwargs: dict[str, Any],
    ) -> tuple[dict[str, Any], set[str] | None, AirlockResponse | None]:
        """Validate and strip ghost (hallucinated) arguments.

        Args:
            func: The function being called.
            func_name: Name of the function.
            kwargs: Keyword arguments to validate.

        Returns:
            Tuple of (cleaned_kwargs, stripped_args, error_response).
            If error_response is not None, validation failed.
        """
        mode = self.config.unknown_args
        try:
            cleaned_kwargs, stripped = strip_ghost_arguments(
                func,
                dict(kwargs),
                strict=mode == UnknownArgsMode.BLOCK,
                log=False,
            )

            if stripped:
                # The mode decides how a strip is logged (``handle_unknown_args``): one
                # structured warning under STRIP_AND_LOG, a debug line under STRIP_SILENT.
                # Until 0.10.28 the validator also warned and this method logged at info, so
                # STRIP_SILENT was not silent and STRIP_AND_LOG logged each strip three times.
                handle_unknown_args(
                    mode=mode,
                    func_name=func_name,
                    stripped_args=stripped,
                    audit_logger=None,
                )

            return cleaned_kwargs, stripped, None

        except GhostArgumentError as e:
            response = handle_ghost_argument_error(e)
            self._safe_invoke_callback(
                self.config.on_blocked,
                "on_blocked",
                func_name,
                f"Ghost arguments rejected: {e.ghost_args}",
                {"ghost_args": list(e.ghost_args)},
            )
            return kwargs, None, response

    def _resolve_and_check_policy(
        self,
        func_name: str,
        context: AirlockContext[Any],
        *,
        run_context: AirlockContext[Any] | None,
    ) -> Generator[
        _ApprovalAsk, _ApproverOutcome, tuple[SecurityPolicy | None, AirlockResponse | None]
    ]:
        """Resolve and check security policy.

        A generator, like ``_pre_execution``: an escalation yields its
        :class:`_ApprovalAsk` (``_resolve_escalation``). A policy that cannot be resolved,
        or a frozen one that changed, is refused and logged as ``policy_indeterminate``.

        Args:
            func_name: Name of the function being called.
            context: The current airlock context.
            run_context: The run's context the call's guard state is shared with, or None
                when the call has no run (see ``_share_run_state``). A policy with
                ``reauth_on_untrusted_reinvocation`` refuses a call that has none: it counts
                untrusted outputs across a run's calls, and with no run the count would
                never pass one, which is how the guard did nothing until 0.10.23.

        Returns:
            Tuple of (resolved_policy, error_response).
            If error_response is not None, policy check failed.
        """
        if self.policy is None:
            return None, None

        resolved_policy: SecurityPolicy | None = None

        # Support dynamic policy resolution via callable
        if callable(self.policy) and not isinstance(self.policy, SecurityPolicy):
            try:
                resolved_policy = self.policy(context)
            except Exception as e:
                logger.error(
                    "policy_resolver_error",
                    function=func_name,
                    error=str(e),
                )
                logger.warning(
                    "policy_indeterminate",
                    function=func_name,
                    source="policy_resolver",
                    error_type=type(e).__name__,
                )
                response = handle_policy_violation(
                    func_name,
                    policy_name="PolicyResolver",
                    reason=f"Policy resolution failed: {e}",
                )
                return None, response
            if resolved_policy is None:
                # Until 0.10.24 a resolver that returned None ran the call with no policy
                # at all, so any tenant or workspace the resolver did not know was allowed
                # everything. A resolver allows on purpose by returning PERMISSIVE_POLICY.
                logger.warning(
                    "policy_resolver_returned_none",
                    function=func_name,
                    agent_id=context.agent_id,
                    workspace_id=context.workspace_id,
                )
                logger.warning(
                    "policy_indeterminate", function=func_name, source="policy_resolver_none"
                )
                self._safe_invoke_callback(
                    self.config.on_blocked,
                    "on_blocked",
                    func_name,
                    "policy resolver returned no policy",
                    {"violation_type": "no_policy_resolved"},
                )
                return None, handle_policy_violation(
                    func_name,
                    policy_name="PolicyResolver",
                    reason=(
                        "the policy resolver returned no policy for this call; return "
                        "PERMISSIVE_POLICY to allow it on purpose"
                    ),
                )
        else:
            resolved_policy = self.policy

        if resolved_policy is not None:
            # v0.5.5: verify frozen policy has not drifted mid-session
            # (CVE-2026-41349 consent-bypass guard). Runs before check()
            # so a mutated policy never reaches the allow/deny logic.
            if resolved_policy.is_frozen():
                try:
                    resolved_policy.verify_frozen()
                except PolicyMutationError as e:
                    logger.warning(
                        "policy_indeterminate", function=func_name, source="frozen_policy_digest"
                    )
                    response = handle_policy_violation(
                        func_name,
                        policy_name="FrozenSecurityPolicy",
                        reason=str(e),
                    )
                    self._safe_invoke_callback(
                        self.config.on_blocked,
                        "on_blocked",
                        func_name,
                        str(e),
                        {
                            "violation_type": "policy_mutation",
                            "stored_digest": e.stored_digest,
                            "actual_digest": e.actual_digest,
                        },
                    )
                    return resolved_policy, response

            try:
                if resolved_policy.reauth_on_untrusted_reinvocation and run_context is None:
                    raise PolicyViolation(
                        f"Tool '{func_name}' is under reauth_on_untrusted_reinvocation, "
                        "which counts a run's untrusted tool outputs across its calls, and "
                        "this call belongs to no run. Make the agent's calls inside "
                        "`with AirlockContext(agent_id=...)`, or pass an AirlockContext as "
                        "the run wrapper's `context`.",
                        violation_type=ViolationType.REAUTH_REQUIRED.value,
                        details={"tool": func_name, "reason": "no_run_context"},
                    )
                resolved_policy.check_reauthorization(func_name, context)
                resolved_policy.check(func_name, agent=_caller_identity(context))
            except PolicyEscalation as e:
                # V0.8.74 (issue #143): the third verdict. This clause MUST stay above
                # the PolicyViolation handler below — PolicyEscalation subclasses it,
                # so ordering is what makes escalation distinguishable from denial.
                # If this clause is ever removed, the subclass relationship means the
                # call still BLOCKS via the generic handler. That is the intended
                # failure mode: losing the approver path must not open the gate.
                escalation_response = yield from self._resolve_escalation(
                    resolved_policy, func_name, e
                )
                if escalation_response is not None:
                    return resolved_policy, escalation_response
            except PolicyViolation as e:
                if e.violation_type == ViolationType.RATE_LIMITED.value:
                    reset_seconds = int(e.details.get("reset_seconds", 60))
                    response = handle_rate_limit(
                        func_name,
                        limit=e.details.get("limit", "unknown"),
                        reset_seconds=reset_seconds,
                    )
                    self._safe_invoke_callback(
                        self.config.on_rate_limit,
                        "on_rate_limit",
                        func_name,
                        reset_seconds,
                    )
                else:
                    # The refusal reaches the model, so it reads a reason that names no
                    # deny glob; the operator keeps the full message here and in
                    # on_blocked below.
                    logger.warning(
                        "policy_violation",
                        function=func_name,
                        violation_type=e.violation_type,
                        reason=e.message,
                    )
                    response = handle_policy_violation(
                        func_name,
                        policy_name="SecurityPolicy",
                        reason=_model_safe_policy_reason(func_name, e),
                        violation_type=e.violation_type,
                    )
                    self._safe_invoke_callback(
                        self.config.on_blocked,
                        "on_blocked",
                        func_name,
                        e.message,
                        {"violation_type": e.violation_type, **e.details},
                    )
                return resolved_policy, response

        return resolved_policy, None

    def _check_amplification(
        self,
        *,
        func_name: str,
        resolved_policy: SecurityPolicy | None,
        context: AirlockContext[Any],
        input_tokens: int | None,
    ) -> AirlockResponse | None:
        """Record this call against the run and enforce the amplification budget.

        Closes issue #142: before v0.8.74 every recruited call of a Convergent Detour
        Hijacking run reached the audit log, but nothing in the layer said the calls were
        *extra*. The decision produced here is stashed on the context so every audit call
        site writes the run's counters onto the record — making the amplification
        detectable, not merely visible.

        Args:
            func_name: Name of the tool being called.
            resolved_policy: The resolved policy, or None.
            context: Current context; supplies the run identity and receives the decision.
            input_tokens: The ``input_tokens`` metadata tag the harness set on the call's
                context, when it set one. Never estimated — a run whose harness supplies
                none simply carries no token figure rather than a guessed one.

        Returns:
            An :class:`AirlockResponse` when the run is over budget under a ``block``
            action, otherwise ``None``.
        """
        if resolved_policy is None:
            return None
        guard = resolved_policy._amplification_guard
        if guard is None:
            return None

        decision = guard.record_and_check(
            session_key=context.session_id,
            tool_name=func_name,
            input_tokens=input_tokens,
        )
        # Stashed even when OK: the counters are the point, and an operator
        # establishing a baseline needs the numbers from passing runs too.
        context._amplification = decision

        if not decision.is_over:
            return None

        if guard.budget.action == "warn":
            logger.warning(
                "amplification_over_budget_warn_only",
                function=func_name,
                run_call_count=decision.run_call_count,
                reason=decision.reason,
            )
            return None

        logger.warning(
            "amplification_blocked",
            function=func_name,
            run_call_count=decision.run_call_count,
            verdict=decision.verdict.value,
            reason=decision.reason,
        )
        response = handle_amplification_exceeded(
            func_name,
            reason=decision.reason,
            run_call_count=decision.run_call_count,
            baseline_calls=decision.baseline_calls,
            amplification_ratio=decision.amplification_ratio,
            verdict=decision.verdict.value,
        )
        self._safe_invoke_callback(
            self.config.on_blocked,
            "on_blocked",
            func_name,
            decision.reason,
            {
                "violation_type": "amplification",
                "verdict": decision.verdict.value,
                "run_call_count": decision.run_call_count,
            },
        )
        return response

    def _resolve_escalation(
        self,
        policy: SecurityPolicy,
        func_name: str,
        escalation: PolicyEscalation,
    ) -> Generator[_ApprovalAsk, _ApproverOutcome, AirlockResponse | None]:
        """Route a :class:`PolicyEscalation` to the operator-supplied approver.

        Reuses the v0.8.4 :mod:`agent_airlock.oversight` primitive rather than inventing
        a second approval surface: the same :class:`~agent_airlock.oversight.Approver`
        callable, the same :class:`~agent_airlock.oversight.OversightRequest` /
        ``OversightResponse`` shapes, the same ``request_id`` echo contract.

        A generator: it yields an :class:`_ApprovalAsk` and resumes with what the
        approver did within ``escalation_timeout_seconds`` (the driver runs it in a worker
        thread, so the deadline holds and the async path's loop is not blocked; until
        0.10.29 it ran inline and the timeout was only echoed on the request).

        Args:
            policy: The resolved policy that escalated.
            func_name: Name of the tool being called.
            escalation: The raised escalation, carrying ``reason`` and ``rule``.

        Returns:
            ``None`` if the approver granted and the call may proceed. An
            :class:`AirlockResponse` in **every** other case: no approver registered,
            explicit denial, timeout, or an answer that is not an approval
            (``policy_indeterminate``: an approver that raised, returned something other
            than an ``OversightResponse``, or a verdict outside ``OversightVerdict``, such
            as the string ``"grant"``). There is exactly one path that returns ``None``,
            and it requires an affirmative ``OversightVerdict.GRANT``.
        """
        from .oversight import OversightRequest

        approver = policy.approver

        # 1c bullet 4 — the case this feature exists for. A policy that escalates
        # with nothing to escalate to blocks, loudly, naming the configuration gap.
        if approver is None:
            logger.warning(
                "escalation_no_approver",
                tool=func_name,
                rule=escalation.rule,
                reason=escalation.reason,
            )
            response = handle_escalation(
                func_name,
                reason=escalation.reason,
                rule=escalation.rule,
                outcome="no_approver",
            )
            self._safe_invoke_callback(
                self.config.on_blocked,
                "on_blocked",
                func_name,
                escalation.message,
                {"violation_type": escalation.violation_type, **escalation.details},
            )
            return response

        request = OversightRequest(
            request_id=str(uuid.uuid4()),
            tool_name=func_name,
            args={"escalation_reason": escalation.reason, "escalation_rule": escalation.rule},
            channel=policy.escalation_channel,
            timeout_seconds=float(policy.escalation_timeout_seconds),
            requested_at=datetime.now(timezone.utc).isoformat(),
        )
        outcome = yield _ApprovalAsk(approver, request, request.timeout_seconds)
        refusal = self._read_approval(func_name, escalation, request, outcome)
        if refusal is not None:
            self._safe_invoke_callback(
                self.config.on_blocked,
                "on_blocked",
                func_name,
                escalation.message,
                {"violation_type": escalation.violation_type, **escalation.details},
            )
        return refusal

    def _read_approval(
        self,
        func_name: str,
        escalation: PolicyEscalation,
        request: Any,
        outcome: _ApproverOutcome,
    ) -> AirlockResponse | None:
        """The refusal for what the approver did, or None for a readable ``GRANT``."""
        from .oversight import OversightResponse, OversightVerdict

        if outcome.kind == "timeout":
            logger.info("escalation_timeout", tool=func_name, rule=escalation.rule)
            logger.warning("policy_indeterminate", function=func_name, source="approver_timeout")
            return handle_escalation(
                func_name,
                reason=escalation.reason,
                rule=escalation.rule,
                outcome="timeout",
                detail=f"no answer within {request.timeout_seconds:g}s",
            )
        if outcome.kind == "raised":
            exc = outcome.error
            # An approver that raises is an approval that did not happen.
            logger.warning(
                "escalation_approver_raised", tool=func_name, rule=escalation.rule, error=str(exc)
            )
            return self._indeterminate(
                func_name,
                escalation,
                returned=type(exc).__name__,
                detail=f"approver raised {type(exc).__name__}: {exc}",
            )
        answer = outcome.value
        if not isinstance(answer, OversightResponse) or not isinstance(
            answer.verdict, OversightVerdict
        ):
            verdict = answer.verdict if isinstance(answer, OversightResponse) else None
            return self._indeterminate(
                func_name,
                escalation,
                returned=type(answer).__name__,
                verdict_type=type(verdict).__name__,
                detail="the approver's answer is not an OversightResponse with an "
                "OversightVerdict verdict",
            )
        return self._read_verdict(func_name, escalation, request, answer)

    def _indeterminate(
        self,
        func_name: str,
        escalation: PolicyEscalation,
        *,
        detail: str,
        **shape: str,
    ) -> AirlockResponse:
        """Refuse an approval that cannot be read, logging only the type names of what
        came back (``shape``), never its content."""
        logger.warning(
            "policy_indeterminate",
            function=func_name,
            source="approver",
            rule=escalation.rule,
            **shape,
        )
        return handle_escalation(
            func_name,
            reason=escalation.reason,
            rule=escalation.rule,
            outcome="indeterminate",
            detail=detail,
        )

    def _read_verdict(
        self,
        func_name: str,
        escalation: PolicyEscalation,
        request: Any,
        answer: Any,
    ) -> AirlockResponse | None:
        """The refusal for a readable ``OversightResponse``, or None when it grants."""
        from .oversight import OversightVerdict

        # Same protocol fault the oversight decorator enforces: an approver that does
        # not echo the request_id is not answering *this* request, so it cannot grant it.
        if answer.request_id != request.request_id:
            logger.warning(
                "escalation_request_id_mismatch",
                tool=func_name,
                expected=request.request_id,
                got=answer.request_id,
            )
            return handle_escalation(
                func_name,
                reason=escalation.reason,
                rule=escalation.rule,
                outcome="denied",
                detail=(
                    "approver returned a mismatched request_id "
                    f"(expected {request.request_id!r}, got {answer.request_id!r})"
                ),
                approver=answer.approver,
            )

        if answer.verdict is OversightVerdict.GRANT:
            logger.info(
                "escalation_granted",
                tool=func_name,
                rule=escalation.rule,
                approver=answer.approver,
            )
            return None

        outcome: Literal["denied", "timeout"] = (
            "timeout" if answer.verdict is OversightVerdict.TIMEOUT else "denied"
        )
        # Literal event names, so a search of the source finds the line that logs each.
        if outcome == "timeout":
            logger.info(
                "escalation_timeout",
                tool=func_name,
                rule=escalation.rule,
                approver=answer.approver,
            )
        else:
            logger.info(
                "escalation_denied",
                tool=func_name,
                rule=escalation.rule,
                approver=answer.approver,
            )
        return handle_escalation(
            func_name,
            reason=escalation.reason,
            rule=escalation.rule,
            outcome=outcome,
            detail=answer.detail,
            approver=answer.approver,
        )

    def _reads_argument_values(self, func_name: str, resolved_policy: Any) -> bool:
        """Whether a gate that reads argument values (steps 2.7, 2.75, 3, 5) is on."""
        return (
            self.config.filesystem_policy is not None
            or func_name in self.config.endpoint_policies
            or getattr(resolved_policy, "deserialization_guard", None) is not None
            or getattr(resolved_policy, "tool_arg_sink_guard", None) is not None
        )

    def _validate_filesystem_paths(
        self,
        func_name: str,
        arguments: dict[str, Any],
    ) -> AirlockResponse | None:
        """Validate every filesystem path the call's arguments carry.

        Reads every argument (``_arg_walk``): positional and keyword, down through
        mappings, lists, tuples and sets. :func:`_filesystem_path` decides which values
        are paths. Input the walk cannot read (too deep, self-containing) is refused.

        A violation is refused under the honeypot strategy too: the wrapper turns the
        refusal into the honeypot's fake response. Until 0.10.24 the honeypot branch here
        was a bare ``pass``, so the real tool ran on the forbidden path. Only
        ``SOFT_BLOCK`` (log, then proceed) lets the call through.

        Args:
            func_name: Name of the function being called.
            arguments: Every argument of the call, by name (``bind_arguments``).

        Returns:
            Error response if validation failed, None otherwise.
        """
        policy = self.config.filesystem_policy
        if policy is None:
            return None

        try:
            for item in iter_argument_values(arguments):
                path = _filesystem_path(item)
                if path is None:
                    continue
                try:
                    validate_path(path, policy)
                except PathValidationError as e:
                    logger.warning(
                        "path_validation_failed",
                        function=func_name,
                        argument=item.path,
                        path=e.path,
                        violation_type=e.violation_type,
                    )
                    if should_soft_block(self.config.honeypot_config):
                        continue
                    return self._refuse_path(
                        func_name, e.path, e.violation_type, e.details, e.message
                    )
        except ArgumentNestingError as e:
            logger.warning(
                "path_validation_failed",
                function=func_name,
                argument=e.path,
                violation_type="uninspectable_argument",
            )
            return self._refuse_path(
                func_name, e.path, "uninspectable_argument", {"reason": e.reason}, str(e)
            )
        return None

    def _refuse_path(
        self,
        func_name: str,
        path: str,
        violation_type: str,
        details: dict[str, Any] | None,
        message: str,
    ) -> AirlockResponse:
        """The refusal for a path violation, after telling ``on_blocked``."""
        response = handle_path_violation(
            func_name,
            path=path,
            violation_type=violation_type,
            details=details,
        )
        self._safe_invoke_callback(
            self.config.on_blocked,
            "on_blocked",
            func_name,
            f"Path violation: {message}",
            {"path": path, "violation_type": violation_type},
        )
        return response

    def _check_sequence_guard(
        self,
        *,
        func_name: str,
        resolved_policy: SecurityPolicy | None,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        context: AirlockContext[Any],
    ) -> AirlockResponse | None:
        """Behavioral tool-call sequence guard (V0.8.12, arXiv:2605.27901).

        Calls ``policy.sequence_guard.record_and_check(...)`` if configured.
        Per-session ordered transitions are flagged against either a
        declared DAG or a learned Markov baseline. See
        :mod:`agent_airlock.sequence_guard` for the contract.

        Args:
            func_name: Name of the function being called.
            resolved_policy: The resolved :class:`SecurityPolicy` (or None).
            args: Positional args — used only for the shape hash; values
                never leave the guard's memory.
            kwargs: Cleaned keyword args — same shape-only treatment.
            context: Current :class:`AirlockContext`. Used to derive the
                session key (``agent_id`` or ``session_id``).

        Returns:
            Error response if the transition is blocked, None otherwise.
            Returns None on warn-mode flags too — the guard already
            logged + emitted the OTel attribute.
        """
        if resolved_policy is None or resolved_policy.sequence_guard is None:
            return None

        guard = resolved_policy.sequence_guard

        # Resolve the session key from context per the guard's preference.
        # Falls back to '__anonymous__' if both ids are absent — the
        # guard logs a warning in that case but does not error, so
        # deployments without identity still record (just all into one
        # bucket).
        if guard.session_key_kind == "session_id":
            session_key = context.session_id or context.agent_id or "__anonymous__"
        else:
            session_key = context.agent_id or context.session_id or "__anonymous__"
        if session_key == "__anonymous__":
            logger.warning(
                "sequence_guard.anonymous_session_key",
                function=func_name,
                hint=(
                    "AirlockContext has no agent_id or session_id; all "
                    "calls without identity collapse into a single "
                    "'__anonymous__' bucket and the guard's "
                    "per-session semantics degrade."
                ),
            )

        # Lazy import to avoid the module-level cycle (sequence_guard
        # imports PolicyViolation from policy.py).
        from .sequence_guard import SequenceViolation

        try:
            guard.record_and_check(
                session_key=session_key,
                tool_name=func_name,
                args=args,
                kwargs=kwargs,
            )
        except SequenceViolation as e:
            response = handle_policy_violation(
                func_name,
                policy_name="SequenceGuard",
                reason=e.message,
            )
            self._safe_invoke_callback(
                self.config.on_blocked,
                "on_blocked",
                func_name,
                e.message,
                {
                    "violation_type": "sequence_violation",
                    "guard_mode": e.mode,
                    "from_tool": e.from_tool,
                    "to_tool": e.to_tool,
                    "session_key": e.session_key,
                    "observed_probability": e.observed_probability,
                },
            )
            return response

        return None

    def _check_action_contradiction_gate(
        self,
        *,
        func_name: str,
        resolved_policy: SecurityPolicy | None,
        context: AirlockContext[Any],
    ) -> AirlockResponse | None:
        """Action-time contradiction gate (V0.8.15, arXiv:2605.27157).

        Calls ``policy.action_contradiction_gate.check_action(...)`` if
        configured. The gate's pluggable detectors (signal field,
        marker regex, predicate) decide whether the session has
        signalled acknowledged-contradiction evidence; if so AND the
        dispatched tool is a privileged sink, the gate raises
        :class:`ActionContradictionViolation` unless the caller has
        issued :meth:`AirlockContext.authorize_once` for this tool.

        See :mod:`agent_airlock.action_contradiction_gate` for the
        full contract.

        Args:
            func_name: Name of the function being called.
            resolved_policy: The resolved :class:`SecurityPolicy` (or None).
            context: Current :class:`AirlockContext` — read for the
                detector inputs (``metadata``) and the explicit-allow
                grant (``_authorized_once``).

        Returns:
            Error response if the action is blocked, None otherwise.
            Returns None on warn-mode flags too — the gate has already
            logged the warn event.
        """
        if resolved_policy is None or resolved_policy.action_contradiction_gate is None:
            return None

        gate = resolved_policy.action_contradiction_gate

        # Resolve the session key the same way the sequence guard does:
        # caller-preferred id first, fall back, fall back to anonymous.
        if gate.session_key_kind == "session_id":
            session_key = context.session_id or context.agent_id or "__anonymous__"
        else:
            session_key = context.agent_id or context.session_id or "__anonymous__"

        # Lazy import to avoid the module-level cycle
        # (action_contradiction_gate imports PolicyViolation from
        # policy.py).
        from .action_contradiction_gate import ActionContradictionViolation

        try:
            gate.check_action(
                context=context,
                tool_name=func_name,
                session_key=session_key,
            )
        except ActionContradictionViolation as e:
            response = handle_policy_violation(
                func_name,
                policy_name="ActionContradictionGate",
                reason=e.message,
            )
            self._safe_invoke_callback(
                self.config.on_blocked,
                "on_blocked",
                func_name,
                e.message,
                {
                    "violation_type": "action_contradiction_violation",
                    "tool_name": e.tool_name,
                    "detector_kind": e.detector_kind,
                    "session_key": e.session_key,
                },
            )
            return response

        return None

    def _check_deserialization_guard(
        self,
        *,
        func_name: str,
        resolved_policy: SecurityPolicy | None,
        arguments: dict[str, Any],
        context: AirlockContext[Any],
    ) -> AirlockResponse | None:
        """Unsafe-deserialization content guard (V0.8.19, CVE-2026-25874).

        Calls ``policy.deserialization_guard.evaluate(arguments, transport=...)`` if
        configured. Inspects the call's argument values for serialized-
        object payloads (pickle magic bytes, base64-encoded pickle,
        serializer marker tokens) and, when the guard requires it,
        serialized-object args sent over an unauthenticated transport.
        See :class:`agent_airlock.safe_types.UnsafeDeserializationGuard`.

        The transport declaration is the host's: the value under the guard's
        ``transport_metadata_key`` on the call's context metadata (``_call_metadata``).
        A tool argument of that name is the model's, so it is scanned as ordinary content
        and declares nothing; until 0.10.28 the guard read it as the declaration.

        Args:
            func_name: Name of the function being called.
            resolved_policy: The resolved :class:`SecurityPolicy` (or None).
            arguments: Every argument of the call, by name, positional ones
                included (``bind_arguments``); the guard reads nested values.
            context: The call's context, read for the transport declaration.

        Returns:
            A blocked :class:`AirlockResponse` carrying the guard's
            ``fix_hints`` (which include the advisory / CVE reference)
            when a payload is detected, else None.
        """
        if resolved_policy is None or resolved_policy.deserialization_guard is None:
            return None

        guard = resolved_policy.deserialization_guard
        decision = guard.evaluate(
            arguments, transport=_call_metadata(context, guard.transport_metadata_key)
        )
        if decision.allowed:
            return None

        # The model sees which argument was refused and why in general terms, never the
        # detector that matched: ``decision.detail`` names the sink token or encoding it
        # caught, and ``matched_pattern`` is that token. Both stay in the log line the
        # guard writes and in ``on_blocked`` (0.10.25: refusals withhold deny lists).
        response = AirlockResponse.blocked_response(
            reason=BlockReason.POLICY_VIOLATION,
            error=(
                f"AIRLOCK_BLOCK: Tool '{func_name}' blocked by UnsafeDeserializationGuard: "
                + (
                    f"argument {decision.matched_field!r} could not be inspected (nested too "
                    f"deeply, self-containing, or an unreadable shape)"
                    if decision.verdict.value == "deny_uninspectable"
                    else f"argument {decision.matched_field!r} carries a serialized-object "
                    f"payload this tool does not accept"
                )
            ),
            fix_hints=decision.fix_hints,
            metadata={
                "function": func_name,
                "policy": "UnsafeDeserializationGuard",
                "verdict": decision.verdict.value,
                "matched_field": decision.matched_field,
            },
        )
        self._safe_invoke_callback(
            self.config.on_blocked,
            "on_blocked",
            func_name,
            decision.detail,
            {
                "violation_type": "unsafe_deserialization",
                "verdict": decision.verdict.value,
                "matched_field": decision.matched_field,
                "matched_pattern": decision.matched_pattern,
            },
        )
        return response

    def _check_tool_arg_sinks(
        self,
        *,
        func_name: str,
        resolved_policy: SecurityPolicy | None,
        arguments: dict[str, Any],
    ) -> AirlockResponse | None:
        """Shell syntax and package specs in string arguments (Step 2.75, V0.10.28).

        Calls ``policy.tool_arg_sink_guard.evaluate(arguments)`` if configured: named (or
        all) string arguments may carry no shell metacharacters, installer arguments must
        be a bare version, and a dispatch argument must name a function its allowlist (or,
        without one, the default denylist) admits, the shape of CVE-2026-119050, where a
        model-chosen ``read_pickle`` reached ``getattr(pandas, ...)``. See
        :class:`agent_airlock.tool_arg_sink_guard.ToolArgSinkGuard`.

        The refusal names the argument and the token that tripped it, never the whole
        value: the token is text the caller sent, so naming it tells a retry what to drop.

        Args:
            func_name: Name of the function being called.
            resolved_policy: The resolved :class:`SecurityPolicy` (or None).
            arguments: Every argument of the call, by name, positional ones included
                (``bind_arguments``); the guard reads nested values.

        Returns:
            A blocked :class:`AirlockResponse` (block reason ``tool_arg_sink``) when the
            guard finds something in ``deny`` mode, else None. In ``warn`` mode a finding
            is logged and the call runs.
        """
        guard = getattr(resolved_policy, "tool_arg_sink_guard", None)
        if guard is None:
            return None

        decision = guard.evaluate(arguments)
        if decision.allowed:
            return None

        if guard.mode == "warn":
            logger.warning(
                "airlock_tool_arg_sink_warn_only",
                function=func_name,
                verdict=decision.verdict.value,
                argument=decision.argument,
                token=decision.token,
            )
            return None

        logger.warning(
            "airlock_tool_arg_sink_block",
            function=func_name,
            verdict=decision.verdict.value,
            argument=decision.argument,
            token=decision.token,
        )
        response = AirlockResponse.blocked_response(
            reason=BlockReason.TOOL_ARG_SINK,
            error=f"AIRLOCK_BLOCK: Tool '{func_name}' blocked by ToolArgSinkGuard: "
            + decision.detail,
            fix_hints=list(decision.fix_hints),
            metadata={
                "function": func_name,
                "policy": "ToolArgSinkGuard",
                "verdict": decision.verdict.value,
                "argument": decision.argument,
                "token": decision.token,
            },
        )
        self._safe_invoke_callback(
            self.config.on_blocked,
            "on_blocked",
            func_name,
            decision.detail,
            {
                "violation_type": "tool_arg_sink",
                "verdict": decision.verdict.value,
                "argument": decision.argument,
                "token": decision.token,
            },
        )
        return response

    def _validate_endpoint_policies(
        self,
        func_name: str,
        arguments: dict[str, Any],
    ) -> AirlockResponse | None:
        """Validate every URL the call's arguments carry against the tool's endpoint policy.

        Reads every argument (``_arg_walk``): positional and keyword, down through
        mappings, lists, tuples and sets. :func:`_endpoint_url` decides which values are
        URLs. Input the walk cannot read (too deep, self-containing) is refused.

        Args:
            func_name: Name of the function being called.
            arguments: Every argument of the call, by name (``bind_arguments``).

        Returns:
            Error response if validation failed, None otherwise.
        """
        if not self.config.endpoint_policies:
            return None

        policy = self.config.endpoint_policies.get(func_name)
        if policy is None:
            return None

        from .network import NetworkBlockedError as _NetworkBlockedError
        from .network import validate_endpoint

        allowed = policy.allowed_endpoints or None
        try:
            for item in iter_argument_values(arguments):
                url = _endpoint_url(item)
                if url is None:
                    continue
                try:
                    validate_endpoint(url, policy)
                except _NetworkBlockedError as e:
                    reason = e.details.get("reason", "unknown")
                    logger.warning(
                        "endpoint_policy_violation",
                        function=func_name,
                        argument=item.path,
                        url=url,
                        reason=reason,
                    )
                    return handle_endpoint_violation(
                        func_name,
                        url=url,
                        hostname=e.details.get("hostname", "unknown"),
                        reason=reason,
                        allowed_endpoints=allowed,
                    )
        except ArgumentNestingError as e:
            logger.warning(
                "endpoint_policy_violation",
                function=func_name,
                argument=e.path,
                reason="uninspectable_argument",
            )
            # Until 0.10.26 this went through ``handle_endpoint_violation`` with the
            # hostname "unknown", so the model read "Endpoint blocked: unknown" and a hint
            # about a URL that was never found. Say what the other value gates say.
            return AirlockResponse.blocked_response(
                reason=BlockReason.ENDPOINT_BLOCKED,
                error=(
                    f"AIRLOCK_BLOCK: Endpoint policy for '{func_name}' could not check "
                    f"argument {e.path!r}: {e.reason}"
                ),
                fix_hints=[
                    f"Argument {e.path!r} is nested too deeply or contains itself, so the "
                    "URLs in it cannot be read",
                    "Pass URLs as strings, or in containers nested no deeper than "
                    f"{MAX_DEPTH} levels with no self-references",
                    *(
                        [f"Allowed endpoints for this tool: {', '.join(allowed)}"]
                        if allowed
                        else []
                    ),
                ],
                metadata={
                    "function": func_name,
                    "argument": e.path,
                    "block_reason": f"uninspectable_argument: {e.reason}",
                    "allowed_endpoints": list(allowed) if allowed else [],
                },
            )
        return None

    def _check_model_tier_budget(
        self,
        *,
        func_name: str,
        resolved_policy: SecurityPolicy | None,
        context: AirlockContext[Any],
    ) -> tuple[BudgetEstimate | None, AirlockResponse | None]:
        """Run the per-model-tier budget pre-execute check (v0.8.7).

        No-op when ``resolved_policy.model_tier_budget`` is None. When set,
        resolves the tier (priority: the ``airlock_tier`` metadata tag >
        ``tier_resolver(model_id)`` > ``strict_tier``) and computes a
        worst-case cost estimate via the global :class:`CostTracker`. On cap
        breach, returns a structured blocked response with
        ``block_reason=BUDGET_EXCEEDED``.

        The ``airlock_tier``, ``input_tokens`` and ``model_id`` tags are read
        with :func:`_call_metadata`, never from the tool's arguments. A tier or token tag
        the host set that cannot be read (a tier that is not a string; a token count that
        is not an integer of zero or more) refuses the call: until 0.10.28 it was priced
        as 0 tokens, or a negative count raised out of the call. A ``model_id`` that is
        not a string is priced at the table's dearest row, as an unlisted model is; a str
        enum is read by its value.

        Args:
            func_name: Tool being invoked (for telemetry).
            resolved_policy: The resolved SecurityPolicy (may be None or
                a non-SecurityPolicy if the caller wired in a stub).
            context: The current AirlockContext.

        Returns:
            ``(BudgetEstimate, None)`` on pass, ``(None, AirlockResponse)``
            on block, ``(None, None)`` when no budget is configured.
        """
        if not isinstance(resolved_policy, SecurityPolicy):
            return None, None
        if resolved_policy.model_tier_budget is None:
            return None, None

        tier_tag = _call_metadata(context, "airlock_tier")
        explicit_tier = _text_tag(tier_tag)
        tokens_tag = _call_metadata(context, "input_tokens")
        input_tokens = 0 if tokens_tag is None else _token_count_tag(tokens_tag)
        unreadable = {
            name: tag
            for name, tag, read in (
                ("airlock_tier", tier_tag, explicit_tier),
                ("input_tokens", tokens_tag, input_tokens),
            )
            if tag is not None and read is None
        }
        if unreadable or input_tokens is None:
            return None, self._refuse_unreadable_budget_tags(func_name, unreadable)
        model_id = _model_id_tag(_call_metadata(context, "model_id"))

        cost_tracker = get_global_tracker()
        try:
            estimate = resolved_policy.check_model_tier_budget(
                tier_label=explicit_tier,
                input_tokens=input_tokens,
                cost_tracker=cost_tracker,
                model_id=model_id,
            )
        except AirlockBudgetExceeded as exc:
            logger.info(
                "tier_budget_blocked",
                function=func_name,
                tier=exc.tier,
                estimated_cost_cents=exc.estimated_cost_cents,
                cap_cents=exc.cap.max_cost_cents,
                budget_type=exc.budget_type,
                model_id=exc.model_id,
            )
            return None, handle_budget_exceeded(
                func_name,
                tier=exc.tier,
                cap_cost_cents=exc.cap.max_cost_cents,
                cap_output_tokens=exc.cap.max_output_tokens,
                estimated_cost_cents=exc.estimated_cost_cents,
                estimated_output_tokens=exc.estimated_output_tokens,
                budget_type=exc.budget_type,
                model_id=exc.model_id,
                priced_as=exc.priced_as,
            )
        except UnknownTierError as exc:
            logger.warning(
                "tier_budget_unknown_tier",
                function=func_name,
                tier_label=exc.tier_label,
                known=exc.known,
            )
            return None, handle_policy_violation(
                func_name,
                policy_name="ModelTierBudget",
                reason=str(exc),
            )
        return estimate, None

    def _refuse_unreadable_budget_tags(
        self, func_name: str, tags: dict[str, Any]
    ) -> AirlockResponse:
        """The ``budget_exceeded`` refusal for step-6 tags the host set but that cannot be read.

        A budget that cannot read its inputs refuses, as every other gate does: pricing a
        float or string token count as 0 let any call under the cap. The hints name the
        tag and the type it had, never its value.

        Args:
            func_name: Tool being invoked.
            tags: Each unreadable tag's name and the value the host set.

        Returns:
            The refusal.
        """
        shapes = {name: type(tag).__name__ for name, tag in tags.items()}
        logger.warning("tier_budget_tags_unreadable", function=func_name, tags=shapes)
        return AirlockResponse.blocked_response(
            reason=BlockReason.BUDGET_EXCEEDED,
            error=(
                f"AIRLOCK_BLOCK: '{func_name}' refused: its budget cannot be checked, because "
                f"the call's {', '.join(repr(name) for name in tags)} tag could not be read"
            ),
            fix_hints=[
                *(
                    f"The {name!r} tag on this call is a {shape}; it must be "
                    f"{_BUDGET_TAG_SHAPES[name]}"
                    for name, shape in shapes.items()
                ),
                "The host sets these tags on the call's AirlockContext metadata; retrying or "
                "changing arguments will not help",
            ],
            metadata={"function": func_name, "unreadable_tags": shapes},
        )

    def _reconcile_tier_budget(
        self,
        *,
        func_name: str,
        result: Any,
        budget_estimate: BudgetEstimate,
        policy: SecurityPolicy,
    ) -> None:
        """Reconcile actual vs estimated cost for a tier budget (v0.8.7).

        Best-effort extraction of :class:`TokenUsage` from the tool result:
        looks for ``result.token_usage`` (attribute), ``result["token_usage"]``
        (dict key), or the LLM-SDK-style ``result.usage`` with
        ``input_tokens`` / ``output_tokens`` fields. If none of those are
        present, reconciliation is a no-op (the budget was a pre-execute
        gate only — observability of actuals is opt-in via the convention).

        Never raises; failures log a structlog warning. Reconciliation is
        observability, not a second gate.

        Args:
            func_name: Name of the tool, for logging.
            result: The tool's return value, read for its token usage.
            budget_estimate: The pre-execute estimate to reconcile.
            policy: The policy the call was checked against — the resolved one, so a
                policy resolver's budget is reconciled too.
        """
        if policy.model_tier_budget is None:
            return

        usage = _extract_token_usage(result)
        if usage is None:
            logger.debug(
                "tier_budget_no_usage_to_reconcile",
                function=func_name,
                tier=budget_estimate.tier,
            )
            return

        try:
            policy.model_tier_budget.reconcile_post_execute(
                estimate=budget_estimate,
                actual=usage,
                cost_tracker=get_global_tracker(),
            )
        except Exception:
            logger.exception(
                "tier_budget_reconcile_error",
                function=func_name,
                tier=budget_estimate.tier,
            )

    def _check_capabilities(
        self,
        func: Callable[..., Any],
        func_name: str,
        resolved_policy: SecurityPolicy | None,
    ) -> AirlockResponse | None:
        """Check capability requirements for the function.

        Args:
            func: The callable whose requirement is read: the wrapper ``@Airlock``
                returned, so a ``@requires`` applied above it (which adds its requirement
                to that wrapper, through any decorators between them that keep
                ``__wrapped__`` or copy its attributes) counts as well as one applied below
                it, which ``get_required_capabilities`` finds down the ``__wrapped__`` chain.
                Until 0.10.26 the undecorated tool was read and a ``@requires`` above
                ``@Airlock`` enforced nothing; until 0.10.28 one counted only when adjacent.
            func_name: Name of the function.
            resolved_policy: The resolved security policy (may have capability_policy).

        Returns:
            Error response if capability check failed, None otherwise.
        """
        # Determine which capability policy to use
        capability_policy = self.config.capability_policy
        if resolved_policy is not None and resolved_policy.capability_policy is not None:
            capability_policy = resolved_policy.capability_policy

        if capability_policy is None:
            return None

        required_caps = get_required_capabilities(func)
        if required_caps == Capability.NONE:
            return None

        try:
            capability_policy.check(required_caps, func_name)
            logger.debug(
                "capability_check_passed",
                function=func_name,
                required=capabilities_to_list(required_caps),
            )
        except CapabilityDeniedError as e:
            logger.warning(
                "capability_denied",
                function=func_name,
                required=str(e.required),
                missing=str(e.missing) if e.missing else None,
                denied=str(e.denied) if e.denied else None,
            )
            # Until 0.10.25 this refusal carried no fix_hints and no AIRLOCK_BLOCK prefix.
            response = handle_capability_denied(
                func_name,
                missing=capabilities_to_list(e.missing),
                denied=capabilities_to_list(e.denied),
            )
            self._safe_invoke_callback(
                self.config.on_blocked,
                "on_blocked",
                func_name,
                e.message,
                {"required": str(e.required), "denied": str(e.denied)},
            )
            return response

        return None

    def _safe_invoke_callback(
        self,
        callback: Callable[..., Any] | None,
        callback_name: str,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """Safely invoke a callback, logging any errors.

        Args:
            callback: The callback function to invoke (may be None).
            callback_name: Name of the callback for logging.
            *args: Positional arguments to pass to the callback.
            **kwargs: Keyword arguments to pass to the callback.
        """
        if callback is None:
            return
        try:
            callback(*args, **kwargs)
        except Exception as e:
            logger.warning("callback_error", callback=callback_name, error=str(e))

    def _log_blocked(
        self,
        func_name: str,
        response: AirlockResponse,
        start_time: float,
    ) -> None:
        """Log a blocked tool call."""
        elapsed = time.time() - start_time
        logger.warning(
            "airlock_blocked",
            function=func_name,
            reason=response.block_reason.value if response.block_reason else "unknown",
            error=response.error,
            elapsed_ms=round(elapsed * 1000, 2),
        )


class _SandboxedToolError(RuntimeError):
    """The tool raised inside the sandbox.

    Deliberately not a ``SandboxError``: the decorator answers it exactly as it answers a
    tool that raised in-process, so a tool fails the same way on both paths.
    """


# Convenience alias for common use case
def airlock(
    func: Callable[P, R] | None = None,
    *,
    sandbox: bool = False,
    sandbox_required: bool = False,
    config: AirlockConfig | None = None,
    policy: SecurityPolicy | PolicyResolver | None = None,
    return_dict: bool = False,
) -> Callable[P, R | dict[str, Any]] | Callable[[Callable[P, R]], Callable[P, R | dict[str, Any]]]:
    """Functional interface for the Airlock decorator.

    Example:
        @airlock
        def my_tool(x: int) -> int:
            return x * 2

        @airlock(sandbox=True, sandbox_required=True)
        def dangerous_tool(code: str) -> str:
            # SECURITY: sandbox_required=True ensures this never runs locally
            exec(code)
            return "ok"
    """
    decorator = Airlock(
        sandbox=sandbox,
        sandbox_required=sandbox_required,
        config=config,
        policy=policy,
        return_dict=return_dict,
    )

    if func is None:
        return decorator
    return decorator(func)
