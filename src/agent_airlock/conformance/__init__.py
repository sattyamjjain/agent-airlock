"""EU AI Act Art. 12-style record-keeping for the tool-call decision layer (v0.8.40+).

An append-only, hash-chained, restart-surviving decision log plus an offline
Art. 12 record-keeping evidence bundle. 100% OSS, offline, no cloud, no network.
"""

from __future__ import annotations

from .art12 import (
    ART12_COVERAGE,
    ART12_OUT_OF_SCOPE,
    export_evidence_bundle,
    render_coverage_table,
)
from .decision_log import (
    DECISION_LOG_SCHEMA_VERSION,
    GENESIS_HASH,
    ChainVerification,
    DecisionLog,
    DecisionLogError,
    DecisionRecord,
    verify_chain,
)

__all__ = [
    "ART12_COVERAGE",
    "ART12_OUT_OF_SCOPE",
    "DECISION_LOG_SCHEMA_VERSION",
    "GENESIS_HASH",
    "ChainVerification",
    "DecisionLog",
    "DecisionLogError",
    "DecisionRecord",
    "export_evidence_bundle",
    "render_coverage_table",
    "verify_chain",
]
