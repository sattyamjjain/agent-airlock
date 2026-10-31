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
identity, and since 0.10.29 ``details``: digests and argument names), never raw
tool arguments or results. ``AirlockConfig(decision_log=...)`` has ``@Airlock``
write each call's decision before the tool runs (V0.10.29); :meth:`DecisionLog.checkpoint`
and :meth:`DecisionLog.prune` keep a pruned log verifiable.

Hashing reuses the canonical-JSON convention already used by
``attest/receipt.py`` (``json.dumps(..., sort_keys=True,
separators=(",", ":"))`` then SHA-256) so verifiers see one consistent scheme.
"""

from __future__ import annotations

import hashlib
import hmac
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
        details: V0.10.29. What ``@Airlock`` decided and on what: a ``decision`` entry
            written before the tool runs (digests of the policy, the arguments and the
            decision context, the verdict, rule and layer) or an ``outcome`` entry that
            names its decision's ``record_hash``. Hashed when present; absent from records
            written before it existed, so their hashes still verify.
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
    details: dict[str, object] | None = None

    def body(self) -> dict[str, object]:
        """The hashed portion — every field except ``record_hash``, and ``details`` only
        when there are some."""
        d = asdict(self)
        d.pop("record_hash", None)
        if d.get("details") is None:
            d.pop("details", None)
        return d

    @staticmethod
    def compute_hash(body: dict[str, object]) -> str:
        return hashlib.sha256(_canonical(body)).hexdigest()

    def recompute_hash(self) -> str:
        return self.compute_hash(self.body())

    def to_json(self) -> str:
        d = asdict(self)
        if d.get("details") is None:
            d.pop("details", None)
        return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

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


def verify_chain(
    records: Iterable[DecisionRecord],
    *,
    start_seq: int = 0,
    start_hash: str = GENESIS_HASH,
) -> ChainVerification:
    """Re-derive and check the whole chain from a record sequence.

    Args:
        records: The records, in order.
        start_seq: The seq of the first record: 0, or one past a checkpoint (V0.10.29).
        start_hash: The ``prev_hash`` the first record must carry: GENESIS, or the
            checkpointed head of the records pruned before it.
    """
    prev = start_hash
    # ``expected_seq`` is the count of records verified so far (0-based next seq).
    expected_seq = start_seq
    for expected_seq, rec in enumerate(records, start=start_seq):  # noqa: B007
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
    count = expected_seq + 1 - start_seq if prev != start_hash else 0
    return ChainVerification(ok=True, record_count=count, head_hash=prev, detail="chain verified")


def _broken(seq: int, detail: str) -> ChainVerification:
    """A failed verification at ``seq``: a checkpoint, or the records it should vouch for."""
    return ChainVerification(
        ok=False, record_count=0, head_hash=GENESIS_HASH, first_bad_seq=seq, detail=detail
    )


@dataclass(frozen=True)
class Checkpoint:
    """A chain head recorded so the records it covers can be pruned (V0.10.29).

    Attributes:
        seq: The seq of the last record the head covers.
        head_hash: That record's ``record_hash``.
        ts: When the checkpoint was taken.
        mac: HMAC-SHA256 of ``seq``, ``head_hash`` and ``ts`` under the log's
            ``checkpoint_key``, or None for a checkpoint taken without one.
    """

    seq: int
    head_hash: str
    ts: str
    mac: str | None = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, line: str) -> Checkpoint:
        try:
            raw = json.loads(line)
            return cls(int(raw["seq"]), str(raw["head_hash"]), str(raw["ts"]), raw.get("mac"))
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise DecisionLogError(f"malformed checkpoint line: {exc}") from exc


def _checkpoint_mac(key: bytes, seq: int, head_hash: str, ts: str) -> str:
    return hmac.new(key, f"{seq}:{head_hash}:{ts}".encode(), hashlib.sha256).hexdigest()


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
        checkpoint_key: V0.10.29. The key :meth:`checkpoint` signs chain heads with
            (HMAC-SHA256), and :meth:`verify` authenticates them with. Without one a
            checkpoint is recorded unsigned.

    Raises:
        DecisionLogError: The existing file's chain does not verify.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        verify_on_load: bool = True,
        checkpoint_key: bytes | None = None,
    ) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self._head_hash = GENESIS_HASH
        self._next_seq = 0
        self._checkpoint_key = checkpoint_key
        if self._path.exists() or self.checkpoint_path.exists():
            self._load(verify_on_load)

    @property
    def checkpoint_path(self) -> Path:
        """Where :meth:`checkpoint` records chain heads: beside the log."""
        return self._path.with_name(self._path.name + ".checkpoints")

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
            result = self.verify()
            if not result.ok:
                raise DecisionLogError(
                    f"decision log {self._path} failed integrity check: {result.detail}"
                )
        if records:
            self._head_hash = records[-1].record_hash
            self._next_seq = records[-1].seq + 1
        elif checkpoints := self.checkpoints():
            # Pruned through its head: the chain goes on from the last checkpoint rather
            # than starting again at seq 0, which no checkpoint would vouch for.
            last = max(checkpoints, key=lambda c: c.seq)
            self._head_hash = last.head_hash
            self._next_seq = last.seq + 1

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
        details: dict[str, object] | None = None,
    ) -> DecisionRecord:
        """Append one decision, returning the sealed record.

        The write is atomic per line and ``fsync``-durable so the record
        survives a process crash immediately after this returns. ``details``
        (V0.10.29) is a JSON object folded into the hash.
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
            if details is not None:
                body["details"] = details
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
        """Re-read the file from disk and verify the full chain.

        A log pruned with :meth:`prune` starts after seq 0: it verifies from the
        checkpoint whose head is the record just before its first, authenticated with
        ``checkpoint_key`` when the log has one. Without such a checkpoint, a log missing
        its first records fails. Every checkpoint the remaining records cover must match
        the record at its seq, and one past the last record means records were removed
        from the end (V0.10.29).
        """
        records, checkpoints = self.records(), self.checkpoints()
        last_pruned = max((c.seq for c in checkpoints), default=-1)
        start = records[0].seq if records else last_pruned + 1
        start_hash = GENESIS_HASH
        if start > 0:
            anchor = next((c for c in checkpoints if c.seq == start - 1), None)
            if anchor is None:
                return _broken(
                    start, f"records before seq {start} are missing and no checkpoint covers them"
                )
            problem = self._checkpoint_problem(anchor, anchoring=True)
            if problem:
                return _broken(start, problem)
            start_hash = anchor.head_hash
        result = verify_chain(records, start_seq=start, start_hash=start_hash)
        if not result.ok:
            return result
        return self._covered_checkpoints_problem(records, checkpoints, start) or result

    def _covered_checkpoints_problem(
        self, records: list[DecisionRecord], checkpoints: list[Checkpoint], start: int
    ) -> ChainVerification | None:
        """The first checkpoint at or after ``start`` that its record does not bear out."""
        by_seq = {record.seq: record for record in records}
        for checkpoint in checkpoints:
            if checkpoint.seq < start:
                continue  # covers records pruned before this log's first
            record = by_seq.get(checkpoint.seq)
            if record is None:
                return _broken(
                    checkpoint.seq,
                    f"checkpoint at seq {checkpoint.seq} is past the last record: "
                    "records were removed from the end of the log",
                )
            problem = self._checkpoint_problem(checkpoint, anchoring=False)
            if record.record_hash != checkpoint.head_hash:
                problem = f"record at seq {checkpoint.seq} does not match its checkpoint"
            if problem:
                return _broken(checkpoint.seq, problem)
        return None

    def _checkpoint_problem(self, checkpoint: Checkpoint, *, anchoring: bool) -> str:
        """Why ``checkpoint`` cannot be trusted, or "" when it can.

        With a ``checkpoint_key`` every checkpoint must carry its MAC: an unsigned one is
        not this log's. Without a key only an anchoring checkpoint (one standing in for
        pruned records) needs it, and a signed anchor cannot be read.
        """
        if self._checkpoint_key is None:
            if anchoring and checkpoint.mac is not None:
                return (
                    f"checkpoint at seq {checkpoint.seq} is signed; pass its checkpoint_key "
                    "to verify"
                )
            return ""
        if checkpoint.mac is None:
            return f"checkpoint at seq {checkpoint.seq} is unsigned, and this log signs them"
        expected = _checkpoint_mac(
            self._checkpoint_key, checkpoint.seq, checkpoint.head_hash, checkpoint.ts
        )
        if not hmac.compare_digest(expected, checkpoint.mac):
            return f"checkpoint at seq {checkpoint.seq} does not authenticate (edited or wrong key)"
        return ""

    def checkpoints(self) -> list[Checkpoint]:
        """Every recorded checkpoint, oldest first."""
        if not self.checkpoint_path.exists():
            return []
        lines = self.checkpoint_path.read_text(encoding="utf-8").splitlines()
        return [Checkpoint.from_json(line) for line in lines if line.strip()]

    def checkpoint(self) -> Checkpoint:
        """Record the chain head, signed with ``checkpoint_key`` when one was given.

        The records it covers can then be removed with :meth:`prune` and the rest of the
        log still verifies.

        Raises:
            DecisionLogError: The log has no records yet.
        """
        with self._lock:
            if self._next_seq == 0:
                raise DecisionLogError("a decision log with no records has no head to checkpoint")
            seq, head, ts = self._next_seq - 1, self._head_hash, _now_iso()
            mac = (
                _checkpoint_mac(self._checkpoint_key, seq, head, ts)
                if self._checkpoint_key is not None
                else None
            )
            checkpoint = Checkpoint(seq=seq, head_hash=head, ts=ts, mac=mac)
            self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
            with self.checkpoint_path.open("a", encoding="utf-8") as fh:
                fh.write(checkpoint.to_json() + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            return checkpoint

    def prune(self, through: Checkpoint) -> int:
        """Remove the records ``through`` covers, keeping the checkpoint that vouches for them.

        Returns:
            How many records were removed.

        Raises:
            DecisionLogError: ``through`` is not a checkpoint of this log, or the log does
                not verify: pruning a broken chain would drop the evidence that it broke.
        """
        with self._lock:
            if through not in self.checkpoints():
                raise DecisionLogError("prune takes a checkpoint this log recorded")
            result = self.verify()
            if not result.ok:
                raise DecisionLogError(
                    f"refusing to prune a log that does not verify: {result.detail}"
                )
            records = self.records()
            kept = [record for record in records if record.seq > through.seq]
            staging = self._path.with_name(self._path.name + ".pruning")
            with staging.open("w", encoding="utf-8") as fh:
                fh.writelines(record.to_json() + "\n" for record in kept)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(staging, self._path)
            return len(records) - len(kept)
