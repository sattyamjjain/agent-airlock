"""Append-only, hash-chained, restart-surviving decision log (v0.8.40+).

Every airlock policy decision — one per ``validate → policy → execute →
sanitize`` stage — can be appended to a tamper-evident JSON Lines log. Each
record carries the SHA-256 of the *previous* record folded into its own hash
(``prev_hash → record_hash``), so any edit, reorder, or deletion of an earlier
line breaks every hash after it. The chain is re-derivable and verifiable with
nothing but this file and the stdlib — no key, no service, no network.

This is the record-keeping substrate behind the EU AI Act Art. 12 evidence
bundle (see :mod:`agent_airlock.conformance.art12`). It is deliberately small
and offline: it stores decision *metadata* (stage, tool name, decision, reason,
identity), never raw tool arguments or results.

Hashing reuses the canonical-JSON convention already used by
``attest/receipt.py`` (``json.dumps(..., sort_keys=True,
separators=(",", ":"))`` then SHA-256) so verifiers see one consistent scheme.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from ..exceptions import AirlockError

if TYPE_CHECKING:
    from ..audit import AuditRecord

DECISION_LOG_SCHEMA_VERSION = 1

# The genesis prev_hash: 64 zero hex chars (the "before the first record" state).
GENESIS_HASH = "0" * 64

# The four airlock decision stages, in flow order.
DecisionStage = Literal["validate", "policy", "execute", "sanitize"]
DecisionKind = Literal["allow", "warn", "block", "error"]


class DecisionLogError(AirlockError):
    """Raised on a malformed decision-log file or a broken hash chain."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _canonical(payload: dict[str, object]) -> bytes:
    """Canonical JSON bytes for hashing (matches attest/receipt.py)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class DecisionRecord:
    """One tamper-evident decision-log line.

    The ``record_hash`` is SHA-256 over the canonical JSON of every other field
    (including ``prev_hash``), so the record is bound to its position in the
    chain. ``seq`` starts at 0 for the first record.

    Attributes:
        seq: Monotonic 0-based sequence number.
        ts: ISO-8601 UTC timestamp.
        stage: The airlock stage that produced the decision.
        tool_name: The tool the decision is about.
        decision: allow / warn / block / error.
        reason: Short, non-sensitive explanation (e.g. a policy/guard name).
        agent_id: Optional agent identity.
        session_id: Optional session/run identity.
        prev_hash: ``record_hash`` of the previous record (GENESIS for the first).
        record_hash: SHA-256 over the canonical form of all fields above.
    """

    seq: int
    ts: str
    stage: DecisionStage
    tool_name: str
    decision: DecisionKind
    reason: str
    prev_hash: str
    record_hash: str
    agent_id: str | None = None
    session_id: str | None = None

    def body(self) -> dict[str, object]:
        """The hashed portion — every field except ``record_hash``."""
        d = asdict(self)
        d.pop("record_hash", None)
        return d

    @staticmethod
    def compute_hash(body: dict[str, object]) -> str:
        return hashlib.sha256(_canonical(body)).hexdigest()

    def recompute_hash(self) -> str:
        return self.compute_hash(self.body())

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    @classmethod
    def from_json(cls, line: str) -> DecisionRecord:
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:  # noqa: TRY003
            raise DecisionLogError(f"malformed decision-log line: {exc}") from exc
        allowed = set(DecisionRecord.__dataclass_fields__)
        missing = {
            "seq",
            "ts",
            "stage",
            "tool_name",
            "decision",
            "reason",
            "prev_hash",
            "record_hash",
        } - raw.keys()
        if missing:
            raise DecisionLogError(f"decision-log line missing fields: {sorted(missing)}")
        return cls(**{k: v for k, v in raw.items() if k in allowed})


@dataclass(frozen=True)
class ChainVerification:
    """Result of verifying a decision-log chain.

    Attributes:
        ok: True iff every record's hash and prev-linkage re-derive exactly.
        record_count: Number of records walked.
        head_hash: ``record_hash`` of the last record (or GENESIS if empty).
        first_bad_seq: Sequence number of the first broken record, or None.
        detail: Human-readable explanation.
    """

    ok: bool
    record_count: int
    head_hash: str
    first_bad_seq: int | None = None
    detail: str = ""


def verify_chain(records: Iterable[DecisionRecord]) -> ChainVerification:
    """Re-derive and check the whole chain from a record sequence."""
    prev = GENESIS_HASH
    # ``expected_seq`` is the count of records verified so far (0-based next seq).
    expected_seq = 0
    for expected_seq, rec in enumerate(records):  # noqa: B007
        if rec.seq != expected_seq:
            return ChainVerification(
                ok=False,
                record_count=expected_seq,
                head_hash=prev,
                first_bad_seq=rec.seq,
                detail=f"non-contiguous seq: expected {expected_seq}, got {rec.seq}",
            )
        if rec.prev_hash != prev:
            return ChainVerification(
                ok=False,
                record_count=expected_seq,
                head_hash=prev,
                first_bad_seq=rec.seq,
                detail=f"prev_hash mismatch at seq {rec.seq} (record removed or reordered)",
            )
        if rec.recompute_hash() != rec.record_hash:
            return ChainVerification(
                ok=False,
                record_count=expected_seq,
                head_hash=prev,
                first_bad_seq=rec.seq,
                detail=f"record_hash mismatch at seq {rec.seq} (record was edited)",
            )
        prev = rec.record_hash
    count = expected_seq + 1 if prev != GENESIS_HASH else 0
    return ChainVerification(ok=True, record_count=count, head_hash=prev, detail="chain verified")


class DecisionLog:
    """Append-only, hash-chained decision log backed by a JSONL file.

    On construction against an existing file the chain is loaded and verified;
    a broken chain raises :class:`DecisionLogError` (fail-closed — a log that
    can't prove its own integrity is not silently trusted). Appends are durable
    (flushed + ``fsync``) so a decision recorded before a crash survives the
    restart.

    Args:
        path: JSONL file path. Created on first append if absent.
        verify_on_load: Verify the existing chain when constructing (default
            True). Set False only for large-log fast paths where a separate
            ``verify()`` runs out of band.

    Raises:
        DecisionLogError: The existing file's chain does not verify.
    """

    def __init__(self, path: str | Path, *, verify_on_load: bool = True) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self._head_hash = GENESIS_HASH
        self._next_seq = 0
        if self._path.exists():
            self._load(verify_on_load)

    @property
    def path(self) -> Path:
        return self._path

    @property
    def head_hash(self) -> str:
        return self._head_hash

    @property
    def record_count(self) -> int:
        return self._next_seq

    def _load(self, verify: bool) -> None:
        records = self.records()
        if verify:
            result = verify_chain(records)
            if not result.ok:
                raise DecisionLogError(
                    f"decision log {self._path} failed integrity check: {result.detail}"
                )
        if records:
            self._head_hash = records[-1].record_hash
            self._next_seq = records[-1].seq + 1

    def records(self) -> list[DecisionRecord]:
        """Read every record from disk (source of truth for verification)."""
        if not self._path.exists():
            return []
        out: list[DecisionRecord] = []
        with self._path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(DecisionRecord.from_json(line))
        return out

    def append(
        self,
        *,
        stage: DecisionStage,
        tool_name: str,
        decision: DecisionKind,
        reason: str = "",
        agent_id: str | None = None,
        session_id: str | None = None,
        ts: str | None = None,
    ) -> DecisionRecord:
        """Append one decision, returning the sealed record.

        The write is atomic per line and ``fsync``-durable so the record
        survives a process crash immediately after this returns.
        """
        with self._lock:
            body: dict[str, object] = {
                "seq": self._next_seq,
                "ts": ts or _now_iso(),
                "stage": stage,
                "tool_name": tool_name,
                "decision": decision,
                "reason": reason,
                "agent_id": agent_id,
                "session_id": session_id,
                "prev_hash": self._head_hash,
            }
            record_hash = DecisionRecord.compute_hash(body)
            record = DecisionRecord(record_hash=record_hash, **body)  # type: ignore[arg-type]
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(record.to_json() + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._head_hash = record_hash
            self._next_seq += 1
            return record

    def append_audit_record(
        self, record: AuditRecord, *, stage: DecisionStage = "policy"
    ) -> DecisionRecord:
        """Fold an existing :class:`~agent_airlock.audit.AuditRecord` into the chain.

        This is the bridge from airlock's live decision surface: ``@Airlock``
        already emits one ``AuditRecord`` per intercepted call. Only metadata is
        carried over — never raw args or results.
        """
        return self.append(
            stage=stage,
            tool_name=record.tool_name,
            decision="block" if record.blocked else "allow",
            reason=(record.block_reason or "") if record.blocked else "",
            agent_id=record.agent_id,
            session_id=record.session_id,
            ts=record.timestamp,
        )

    def verify(self) -> ChainVerification:
        """Re-read the file from disk and verify the full chain."""
        return verify_chain(self.records())
