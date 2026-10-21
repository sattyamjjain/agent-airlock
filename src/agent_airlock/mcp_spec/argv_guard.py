"""Argv-array enforcement guard — CVE-2026-39884 ``mcp-server-kubernetes`` (v0.5.6+).

Motivation
----------
SentinelOne disclosed 2026-04-14 that ``flux159/mcp-server-kubernetes``
(versions ≤ 3.4.x) built kubectl invocations by *string-concatenating*
caller-supplied fields like ``localPort``, ``targetPort``, and
``namespace`` into a single argv element. A single field like
``8080 --kubeconfig=/etc/shadow`` therefore became extra flags rather
than data, granting trivial argument-injection RCE on the kubectl side
even though no shell metacharacters were present.

The v0.5.5 ``codebase_mcp_cve_2026_5023_defaults()`` preset blocks
shell metacharacters but accepts the space-injected variant (no
``;``, ``&&``, ``|``, ``$()``, etc.). This module covers the gap by
demanding each argv element be *one* shell-safe token — no embedded
spaces, no shell-significant characters.

Two surfaces are exported:

1. :func:`enforce_argv_array` — generic guard. Pass the argv array a
   handler is about to hand to ``subprocess.run(args, shell=False)``;
   any element that ``shlex.quote`` has to wrap is rejected.
2. :class:`ArgvStringConcatenationError` — the raised error.

The companion preset
``policy_presets.flux159_mcp_kubernetes_cve_2026_39884_defaults()``
specialises this for the four kubectl-flag-injection-prone fields
that the SentinelOne advisory called out.

Primary source
--------------
- SentinelOne CVE-2026-39884 (2026-04-14):
  <https://www.sentinelone.com/vulnerability-database/cve-2026-39884/>
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-39884>
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Sequence

from .._log import structlog
from ..exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.mcp_spec.argv_guard")


class ArgvStringConcatenationError(AirlockError):
    """Raised when an argv element fails the ``shlex.quote`` round-trip.

    Indicates that user-controlled input was concatenated into a single
    argv element rather than passed as its own array slot — the
    CVE-2026-39884 regression class.

    Attributes:
        argv_index: 0-based index of the offending element.
        offending_value: The raw value that failed the check.
        field_name: Optional human-readable field name (e.g.
            ``"localPort"``) when the caller knew which named field the
            element corresponded to.
    """

    def __init__(
        self,
        *,
        argv_index: int,
        offending_value: str,
        field_name: str | None = None,
    ) -> None:
        self.argv_index = argv_index
        self.offending_value = offending_value
        self.field_name = field_name
        location = f"argv[{argv_index}]"
        if field_name is not None:
            location = f"{location} ({field_name!r})"
        super().__init__(
            f"{location} carries an unsafe value {offending_value!r} — "
            "shlex round-trip failed, the value must be a single shell-safe "
            "token (CVE-2026-39884 regression class)"
        )


class ArgvNonStringSlotError(ArgvStringConcatenationError):
    """Raised when an argv slot is not a string (``bytes``, a nested list, a number).

    Every check in :func:`enforce_argv_array` reads a ``str``, so a slot of any other type
    passed them unexamined until 0.10.26, when it was skipped as "the caller's bug" — and
    ``subprocess`` spawns a ``bytes`` element as written. It is refused, like the
    non-string element ``validate_stdio_command`` refuses. A subclass of the concatenation
    error, so a caller that already refuses on that refuses on this.

    Attributes:
        argv_index: 0-based index of the offending element.
        offending_type: The element's type name.
        field_name: Optional human-readable field name.
    """

    def __init__(
        self,
        *,
        argv_index: int,
        offending_type: str,
        field_name: str | None = None,
    ) -> None:
        self.argv_index = argv_index
        self.offending_value = f"<{offending_type}>"
        self.offending_type = offending_type
        self.field_name = field_name
        location = f"argv[{argv_index}]"
        if field_name is not None:
            location = f"{location} ({field_name!r})"
        AirlockError.__init__(
            self,
            f"{location} is a {offending_type}, not a string — a slot the argv checks "
            "cannot read is refused, not skipped (until 0.10.26 it passed unexamined)",
        )


class ArgvOptionInjectionError(AirlockError):
    """Raised when a user-controlled argv slot is an option-like token.

    Under ``shell=False`` each argv element is its own slot, so a shell-safe token like
    ``--kubeconfig=/etc/shadow`` needs no space to inject: a user-controlled value that IS a
    flag becomes an extra flag to the spawned program directly — the CVE-2026-39884 argument
    injection the shlex round-trip alone does not catch. Only raised for slots the caller
    marks user-controlled via ``reject_option_values``.

    Attributes:
        argv_index: 0-based index of the offending element.
        offending_value: The raw option-like value.
        field_name: Optional human-readable field name.
    """

    def __init__(
        self,
        *,
        argv_index: int,
        offending_value: str,
        field_name: str | None = None,
    ) -> None:
        self.argv_index = argv_index
        self.offending_value = offending_value
        self.field_name = field_name
        location = f"argv[{argv_index}]"
        if field_name is not None:
            location = f"{location} ({field_name!r})"
        super().__init__(
            f"{location} is the option-like value {offending_value!r} — a user-controlled "
            "slot must not be a flag (CVE-2026-39884 argument injection). Pass it after a "
            "'--' end-of-options separator, or validate it against a per-field grammar."
        )


# An option-like token: a single or double dash immediately followed by a letter
# (``-o``, ``--kubeconfig``, ``--as=x``). A bare ``-`` (stdin) and a negative number
# (``-5``) are deliberately NOT option-like.
_OPTION_LIKE = re.compile(r"^--?[A-Za-z]")


def _is_option_like(value: str) -> bool:
    return _OPTION_LIKE.match(value) is not None


def _is_safe_token(value: str) -> bool:
    """Whether ``value`` survives ``shlex.quote`` unwrapped.

    A safe token contains no whitespace, no shell metacharacters, and
    no characters that ``shlex.quote`` would need to escape.
    """
    return shlex.quote(value) == value


def enforce_argv_array(
    args: Sequence[str],
    *,
    field_names: Sequence[str] | None = None,
    allow_spaces: bool = False,
    reject_option_values: bool = False,
) -> None:
    """Validate that every element of ``args`` is a single shell-safe token.

    Args:
        args: The argv array a handler is about to spawn (with
            ``shell=False``). Every element must be a string.
        field_names: Optional parallel list naming each argv slot.
            When supplied, error messages cite the field name.
        allow_spaces: If True, plain spaces are allowed in arg values.
            Shell metacharacters are still rejected. Off by default —
            the CVE-2026-39884 attack pattern is space-injection of
            additional flags.
        reject_option_values: If True, an option-like element (``-o``,
            ``--kubeconfig=…``) is refused. OPT-IN and off by default,
            because a legitimate operator-fixed argv contains flags; turn
            it on only for argv whose slots are user-controlled, where a
            flag-shaped value is argument injection (CVE-2026-39884) that
            needs no space and so passes the shlex round-trip. A bare
            ``-`` and a negative number are not option-like.

    Raises:
        ArgvNonStringSlotError: First element that is not a string wins
            (checked before anything else; a subclass of the error below).
        ArgvStringConcatenationError: First shlex-unsafe element wins.
        ArgvOptionInjectionError: Under ``reject_option_values``, first
            option-like element wins (checked before the shlex round-trip).
    """
    for idx, value in enumerate(args):
        field_name = (
            field_names[idx] if field_names is not None and idx < len(field_names) else None
        )
        if not isinstance(value, str):
            # Until 0.10.26 a non-string slot was skipped as "the caller's bug". Nothing
            # below reads it, ``subprocess`` spawns a ``bytes`` element as written, and a
            # nested list or a number reaches the spawner unexamined: refused.
            raise ArgvNonStringSlotError(
                argv_index=idx,
                offending_type=type(value).__name__,
                field_name=field_name,
            )
        if reject_option_values and _is_option_like(value):
            raise ArgvOptionInjectionError(
                argv_index=idx,
                offending_value=value,
                field_name=field_name,
            )
        if allow_spaces and _is_safe_modulo_space(value):
            continue
        if _is_safe_token(value):
            continue
        raise ArgvStringConcatenationError(
            argv_index=idx,
            offending_value=value,
            field_name=field_name,
        )


def _is_safe_modulo_space(value: str) -> bool:
    """Same as :func:`_is_safe_token` but tolerates plain ASCII spaces.

    Used when callers know spaces are part of legitimate values (e.g.
    a free-form note field) but still want to reject shell-metachar
    injection. Tabs / newlines / shell metachars remain rejected.
    """
    if any(ch in value for ch in ("\t", "\n", "\r", "\x00")):
        return False
    # Cheap whitelist: alnum + a small set of safe punctuation, plus
    # plain space. Everything else is rejected.
    safe_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./:=+@, ")
    return all(ch in safe_chars for ch in value)


__all__ = [
    "ArgvNonStringSlotError",
    "ArgvOptionInjectionError",
    "ArgvStringConcatenationError",
    "enforce_argv_array",
]
