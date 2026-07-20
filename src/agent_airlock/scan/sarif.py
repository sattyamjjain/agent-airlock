"""SARIF 2.1.0 serialization for ``airlock scan-tools`` reports.

Emits the graded contract-check report (:class:`~agent_airlock.scan.contract.ScanReport`)
as a `SARIF 2.1.0 <https://sarifweb.azurewebsites.net/>`_ log so ``scan-tools`` output
flows into the **GitHub Security tab** (code scanning) and any other SARIF consumer —
the same format ``agent-audit-kit`` and other scanners speak, so both layers surface in
one place.

scan-tools analyses tool *declarations*, not source lines. Each finding's precise
locator is therefore a **logical location** (the tool name); a physical location is
attached best-effort (the scanned artifact, at line 1) so GitHub can ingest and display
it. No line numbers are fabricated.
"""

from __future__ import annotations

from typing import Any

from .contract import Grade, ScanReport

__all__ = ["to_sarif", "SARIF_SCHEMA_URI"]

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"

_INFO_URI = "https://github.com/sattyamjjain/agent-airlock"

# Static rule catalog: code -> (short name, description, default level). The default
# level mirrors the grade the check emits (a FAIL code defaults to "error", a WARN code
# to "warning"); the per-result level always reflects the actual violation grade.
_RULES: dict[str, tuple[str, str, str]] = {
    "SCAN001": ("tool-not-allowlisted", "Tool is denied by the least-privilege policy.", "error"),
    "SCAN002": (
        "server-card-trust-boundary",
        "Tool description carries injected instructions (server-card trust boundary).",
        "error",
    ),
    "SCAN003": (
        "destructive-open-argument-surface",
        "Destructive tool declares an open argument surface (ghost-argument vector).",
        "error",
    ),
    "SCAN004": (
        "open-argument-surface",
        "Tool declares an open argument surface; hallucinated arguments would be accepted.",
        "warning",
    ),
    "SCAN005": (
        "under-specified-type",
        "Declared property is under-specified (missing type / value constraint).",
        "warning",
    ),
    "SCAN006": (
        "capability-exceeds-policy",
        "Tool requires a capability the policy does not grant.",
        "error",
    ),
    "SCAN007": (
        "sandbox-gated-capability",
        "Tool requires a sandbox-gated capability.",
        "warning",
    ),
    "SCAN008": ("malformed-issuer", "Declared OAuth issuer identifier is malformed.", "warning"),
    "SCAN009": (
        "external-schema-ref",
        "Tool schema dereferences an external $ref (attacker-controlled contract; SEP-2106).",
        "error",
    ),
    "SCAN010": (
        "composition-ambiguity",
        "Tool schema is ambiguous under composition (deny-by-default).",
        "error",
    ),
    "SCAN011": (
        "unsupported-schema-keyword",
        "Tool schema uses a construct the contract checker cannot soundly bound.",
        "error",
    ),
}


def _level_for(grade: Grade) -> str:
    return "error" if grade is Grade.FAIL else "warning"


def to_sarif(
    report: ScanReport,
    *,
    version: str,
    sources: list[str] | None = None,
    scanned_path: str | None = None,
) -> dict[str, Any]:
    """Render a :class:`ScanReport` as a SARIF 2.1.0 log dict.

    Args:
        report: The graded scan report to serialize.
        version: The airlock version to stamp on the SARIF tool driver.
        sources: The source files the tools were loaded from (used, best-effort, as
            the physical-location artifact URI).
        scanned_path: The path argument that was scanned (fallback artifact URI).

    Returns:
        A SARIF 2.1.0 log as a plain dict (JSON-serializable).
    """
    artifact_uri = (sources[0] if sources else None) or scanned_path or "mcp-tools"

    results: list[dict[str, Any]] = []
    seen_rule_ids: list[str] = []
    for tool_result in report.results:
        for violation in tool_result.violations:
            if violation.code not in seen_rule_ids:
                seen_rule_ids.append(violation.code)
            text = f"[{tool_result.tool_name}] {violation.message}"
            if violation.suggestion:
                text += f" Suggestion: {violation.suggestion}"
            result: dict[str, Any] = {
                "ruleId": violation.code,
                "level": _level_for(violation.grade),
                "message": {"text": text},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": artifact_uri},
                            "region": {"startLine": 1},
                        },
                        "logicalLocations": [
                            {
                                "name": tool_result.tool_name,
                                "fullyQualifiedName": tool_result.tool_name,
                                "kind": "function",
                            }
                        ],
                    }
                ],
                "properties": {
                    "tool": tool_result.tool_name,
                    "capability": tool_result.inferred_capability,
                },
            }
            if violation.arg:
                result["properties"]["arg"] = violation.arg
            results.append(result)

    rules: list[dict[str, Any]] = []
    for code in seen_rule_ids:
        name, description, level = _RULES.get(
            code, (code.lower(), "Contract violation.", "warning")
        )
        rules.append(
            {
                "id": code,
                "name": name,
                "shortDescription": {"text": description},
                "defaultConfiguration": {"level": level},
            }
        )

    artifacts = [{"location": {"uri": s}} for s in (sources or [])]

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "agent-airlock scan-tools",
                "informationUri": _INFO_URI,
                "version": version,
                "rules": rules,
            }
        },
        "results": results,
        "properties": {"policy": report.policy_name},
    }
    if artifacts:
        run["artifacts"] = artifacts

    return {"$schema": SARIF_SCHEMA_URI, "version": "2.1.0", "runs": [run]}
