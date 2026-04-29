"""``Capability`` enum.

Named enum values are reserved for *cross-agent primitives* — actions
whose budget needs to be tracked at the agent level. Any tool
invocation that does not fit one of the named primitives is grouped
under ``INVOKE_TOOL`` to keep the enum from sprawling.
"""

from __future__ import annotations

from enum import Enum


class Capability(str, Enum):
    """Programmatic capabilities tracked by the cap engine."""

    SIGN_CONTRACT = "sign_contract"
    """Authorise the agent to commit to a contract on the principal's behalf."""

    DELEGATE_TO_AGENT = "delegate_to_agent"
    """Authorise the agent to spawn / call another agent."""

    INVOKE_TOOL = "invoke_tool"
    """Default capability for any non-cross-agent tool call."""

    WRITE_FILE = "write_file"
    """Authorise the agent to write any file outside its sandbox."""

    NETWORK_EGRESS = "network_egress"
    """Authorise the agent to emit any non-loopback network traffic."""

    @classmethod
    def from_str(cls, value: str) -> Capability:
        normalised = value.strip().lower()
        for member in cls:
            if member.value == normalised:
                return member
        raise ValueError(f"unknown capability: {value!r}")


__all__ = ["Capability"]
