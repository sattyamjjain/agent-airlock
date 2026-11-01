"""Screen tool arguments for secrets and personal data (V0.10.29, step 2.76).

A tool call's arguments are model output, and they can carry what an output guardrail
exists to catch: a key the model read earlier, a password a user typed, a whole
environment dump. A memory-write tool then stores it where every later run can read it
(BerriAI/litellm#46454, mem0ai/mem0#7283). Nothing on the call path read argument values
for secrets: ``ToolArgSinkGuard`` screens shell syntax only, and the audit previews are
masked after the fact.

``SecurityPolicy(argument_secret_guard=ArgumentSecretGuard())`` runs the sanitizer's secret
and PII detectors over every string argument, nested ones included, before the tool runs:

* ``mode="block"`` (the default) refuses the call (``argument_secret``), naming the
  argument and the kind of data, never the value;
* ``mode="mask"`` masks a top-level string argument passed by keyword, where the masked
  value keeps the argument's type and JSON shape, and refuses anything else it finds.

``free_text_args`` are left unscreened, ``tools`` limits the guard to tool-name patterns,
and the preset :func:`agent_airlock.policy_presets.argument_secret_defaults` covers
memory-write tools.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from ._arg_walk import (
    ArgumentName,
    ArgumentNestingError,
    BoundArguments,
    iter_argument_values,
)
from .sanitizer import SensitiveDataType, detect_sensitive_data, mask_sensitive_data

__all__ = [
    "DEFAULT_ARGUMENT_SECRET_TYPES",
    "ArgumentSecretDecision",
    "ArgumentSecretGuard",
    "ArgumentSecretMode",
]

ArgumentSecretMode = Literal["block", "mask"]

#: The detectors the guard runs by default: every secret detector, and the PII ones a tool
#: argument rarely needs. IP addresses are left out, since hosts are ordinary arguments.
DEFAULT_ARGUMENT_SECRET_TYPES: tuple[SensitiveDataType, ...] = (
    SensitiveDataType.API_KEY,
    SensitiveDataType.PASSWORD,
    SensitiveDataType.AWS_KEY,
    SensitiveDataType.PRIVATE_KEY,
    SensitiveDataType.JWT,
    SensitiveDataType.CONNECTION_STRING,
    SensitiveDataType.ENV_DUMP,
    SensitiveDataType.EMAIL,
    SensitiveDataType.PHONE,
    SensitiveDataType.SSN,
    SensitiveDataType.CREDIT_CARD,
)


@dataclass(frozen=True)
class ArgumentSecretDecision:
    """What the guard found in one call's arguments.

    Attributes:
        allowed: Whether the call may run, with ``masked`` applied when it is non-empty.
        argument: The argument (or its nested place) that carried the data, when refused.
        kinds: The kinds of data found there, e.g. ``("api_key",)``; never the value.
        masked: Replacement values by keyword argument, in ``mask`` mode.
        detail: Why the call is refused, in words that name no value.
    """

    allowed: bool
    argument: str | None = None
    kinds: tuple[str, ...] = ()
    masked: Mapping[str, str] = field(default_factory=dict)
    detail: str = ""


_ALLOW = ArgumentSecretDecision(allowed=True)


@dataclass(frozen=True)
class ArgumentSecretGuard:
    """Refuse, or mask, secrets and personal data in a tool's arguments.

    Attributes:
        mode: ``"block"`` refuses the call; ``"mask"`` masks a top-level keyword string
            argument and refuses anything it cannot mask in place.
        detectors: The sanitizer detectors to run.
        free_text_args: Arguments left unscreened.
        tools: Tool-name patterns (``fnmatch``) the guard applies to; every tool when empty.
        pii_locales: Locale tags for the PII detectors, as ``sanitize_output`` takes them.
    """

    mode: ArgumentSecretMode = "block"
    detectors: tuple[SensitiveDataType, ...] = DEFAULT_ARGUMENT_SECRET_TYPES
    free_text_args: frozenset[str] = frozenset()
    tools: tuple[str, ...] = ()
    pii_locales: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.mode not in ("block", "mask"):
            raise ValueError(
                f"ArgumentSecretGuard.mode must be 'block' or 'mask'; got {self.mode!r}"
            )
        object.__setattr__(self, "free_text_args", _names(self.free_text_args, "free_text_args"))
        object.__setattr__(self, "tools", tuple(_names(self.tools, "tools")))
        object.__setattr__(self, "pii_locales", tuple(self.pii_locales))
        if not self.detectors or not all(
            isinstance(kind, SensitiveDataType) for kind in self.detectors
        ):
            raise TypeError("ArgumentSecretGuard.detectors must name SensitiveDataType members")
        object.__setattr__(self, "detectors", tuple(self.detectors))

    def applies_to(self, tool_name: str) -> bool:
        """Whether this guard screens calls of ``tool_name``."""
        return not self.tools or any(fnmatch.fnmatchcase(tool_name, p) for p in self.tools)

    def evaluate(
        self, arguments: Mapping[str, Any], *, keywords: Iterable[str] = ()
    ) -> ArgumentSecretDecision:
        """Screen every string argument the call passes, one argument at a time.

        Args:
            arguments: The call's arguments by name (``bind_arguments``).
            keywords: The names the call passed by keyword: only those can be masked in
                place, since a masked positional value would be passed twice.

        Returns:
            The decision. Arguments too deep or self-containing to read are refused.
        """
        masked: dict[str, str] = {}
        maskable = frozenset(keywords) if self.mode == "mask" else frozenset()
        named = getattr(arguments, "named_models", None)
        for name, value in arguments.items():
            key = name.key if isinstance(name, ArgumentName) else str(name)
            if key in self.free_text_args:
                continue
            argument = BoundArguments({name: value})
            argument.named_models = named
            try:
                refusal = self._screen(name, argument, masked, maskable)
            except ArgumentNestingError as error:
                return ArgumentSecretDecision(
                    allowed=False,
                    argument=error.path,
                    detail=f"argument {error.path!r} cannot be screened: {error.reason}",
                )
            if refusal is not None:
                return refusal
        return ArgumentSecretDecision(allowed=True, masked=masked) if masked else _ALLOW

    def _screen(
        self,
        name: Any,
        argument: BoundArguments,
        masked: dict[str, str],
        maskable: frozenset[str],
    ) -> ArgumentSecretDecision | None:
        """The refusal for one argument, or None; a maskable value lands in ``masked``."""
        for leaf in iter_argument_values(argument):
            text = _text_of(leaf.value)
            if text is None:
                continue
            kinds = self._kinds_in(text)
            if not kinds:
                continue
            in_place = (
                leaf.depth == 0
                and not leaf.is_key
                and isinstance(leaf.value, str)
                and not isinstance(name, ArgumentName)
                and str(name) in maskable
            )
            if in_place:
                masked[str(name)] = self._masked(text)
                continue
            place = str(name) if leaf.is_key else leaf.path
            return ArgumentSecretDecision(
                allowed=False,
                argument=place,
                kinds=kinds,
                detail=f"argument {place!r} carries {', '.join(kinds)}",
            )
        return None

    def _kinds_in(self, text: str) -> tuple[str, ...]:
        found = detect_sensitive_data(
            text, list(self.detectors), pii_locales=list(self.pii_locales)
        )
        return tuple(sorted({detection["type"] for detection in found}))

    def _masked(self, text: str) -> str:
        return mask_sensitive_data(text, list(self.detectors), pii_locales=list(self.pii_locales))[
            0
        ]


def _text_of(value: Any) -> str | None:
    """The text a leaf holds: a string, or an integer's digits (a card number sent bare)."""
    if isinstance(value, str):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    return None


def _names(values: Iterable[str], what: str) -> frozenset[str]:
    if isinstance(values, str) or not all(isinstance(value, str) for value in values):
        raise TypeError(f"ArgumentSecretGuard.{what} must be a collection of names, not a string")
    return frozenset(values)
