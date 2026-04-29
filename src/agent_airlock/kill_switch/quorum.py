"""``ResetQuorum`` — multi-key gate for kill-switch reset."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from ..exceptions import AirlockError


class QuorumError(AirlockError):
    """Raised when a quorum requirement is not satisfied."""


@dataclass
class ResetQuorum:
    """Track a set of presented keyids until a quorum is met."""

    threshold: int
    """Minimum distinct keyids required to authorise a reset."""

    total: int
    """Total keys eligible to vote (the M-of-N denominator)."""

    _votes: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        if self.threshold < 1:
            raise QuorumError("quorum threshold must be at least 1")
        if self.total < self.threshold:
            raise QuorumError(
                f"quorum threshold {self.threshold} cannot exceed total {self.total}"
            )

    def submit(self, keyid: str) -> bool:
        """Record one keyid's vote. Returns ``True`` once threshold reached."""
        self._votes.add(keyid)
        return len(self._votes) >= self.threshold

    @property
    def satisfied(self) -> bool:
        return len(self._votes) >= self.threshold

    @property
    def votes(self) -> tuple[str, ...]:
        return tuple(sorted(self._votes))

    def reset(self) -> None:
        self._votes.clear()

    @classmethod
    def from_iterable(
        cls,
        keyids: Iterable[str],
        *,
        threshold: int,
        total: int,
    ) -> ResetQuorum:
        q = cls(threshold=threshold, total=total)
        for k in keyids:
            q.submit(k)
        return q


__all__ = ["QuorumError", "ResetQuorum"]
