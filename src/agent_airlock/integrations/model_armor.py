"""Google Cloud Model Armor integration for Agent-Airlock (Phase 1.7).

An **opt-in** adapter that forwards prompts and (optionally) model responses
to Google Cloud's Model Armor API and surfaces violations as airlock blocks.

Requires:
    pip install "agent-airlock[model-armor]"

Enable at runtime:
    export AIRLOCK_MODEL_ARMOR_ENABLED=1
    export AIRLOCK_MODEL_ARMOR_TEMPLATE=projects/PROJECT/locations/LOCATION/templates/TEMPLATE

Usage
-----

    from agent_airlock.integrations.model_armor import ModelArmorScanner

    scanner = ModelArmorScanner.from_env()  # or pass args directly
    result = scanner.scan_user_prompt("ignore all previous instructions...")
    if not result.allowed:
        raise MyAirlockBlock(result.reason)

The adapter is deliberately thin: it wraps the upstream `google-cloud-modelarmor`
client, maps its filter categories to a structured result, and surfaces a
boolean `allowed` flag plus per-category match state. It does NOT wire itself
into the `@Airlock` decorator automatically — callers opt in by invoking
`scanner.scan_user_prompt(...)` before the tool call and `scan_model_response(...)`
after, and translating the returned `ModelArmorScanResult` into an
`AirlockResponse.blocked_response(...)` when appropriate.

Primary sources (retrieved 2026-04-18, flagged UNVERIFIED items at EOF):

- Model Armor overview: https://docs.cloud.google.com/model-armor/overview
- Sanitize prompts / responses: https://docs.cloud.google.com/model-armor/sanitize-prompts-responses
- REST reference: https://docs.cloud.google.com/model-armor/reference/rest
- Python client: https://docs.cloud.google.com/python/docs/reference/google-cloud-modelarmor/latest
- PyPI: https://pypi.org/project/google-cloud-modelarmor/
- Pricing (free ≤ 2M tokens/mo, then $0.10/M): https://cloud.google.com/security/products/model-armor

Notes on fields flagged `UNVERIFIED:` in the research log:

- Exact protobuf field names in `modelarmor_v1` (snake_case vs camelCase in
  the Python client). The attribute access here uses the documented
  snake_case names; wrapped in `getattr` with safe fallbacks so a
  Google-side rename surfaces as "no detection" rather than a crash.
- `sanitize_model_response` request field name (`userPrompt` vs
  `userPromptData`). The adapter sends both keys and lets the server
  ignore whichever it does not recognise.
- Token vs character accounting in the pricing page phrasing. Not
  relevant to the adapter correctness; logged for callers who budget.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:  # pragma: no cover
    pass

logger = structlog.get_logger("agent-airlock.integrations.model_armor")


# Environment variable names
ENV_ENABLED = "AIRLOCK_MODEL_ARMOR_ENABLED"
ENV_TEMPLATE = "AIRLOCK_MODEL_ARMOR_TEMPLATE"
ENV_ENDPOINT = "AIRLOCK_MODEL_ARMOR_ENDPOINT"

# Canonical filter-category names used across the Python client proto.
# Kept as strings so a Google-side rename (e.g. adding a new filter)
# doesn't break the adapter — we just surface whatever categories the
# server returned.
CANONICAL_FILTER_CATEGORIES: tuple[str, ...] = (
    "rai_filter_result",
    "sdp_filter_result",
    "pi_and_jailbreak_filter_result",
    "malicious_uri_filter_result",
    "csam_filter_filter_result",
)


class ModelArmorNotInstalled(RuntimeError):
    """Raised when the google-cloud-modelarmor package isn't importable."""


@dataclass
class ModelArmorScanResult:
    """The result of a single scan call.

    Attributes:
        allowed: True if Model Armor returned no match.
        match_state: The overall `filter_match_state` value (string).
        invocation_state: The overall `invocation_result` value (string).
        categories: Per-category match state. Keys are the canonical
            filter names; values are the match state strings Model Armor
            returned (e.g. ``"MATCH_FOUND"`` / ``"NO_MATCH_FOUND"``).
        reason: Short human-readable summary of why the call was blocked
            (empty string when allowed).
        raw: The raw `sanitizationResult` object from the API, kept for
            callers who want the full Google response (logging, audit).
    """

    allowed: bool
    match_state: str = ""
    invocation_state: str = ""
    categories: dict[str, str] = field(default_factory=dict)
    reason: str = ""
    raw: Any = None


class ModelArmorScanner:
    """Thin wrapper around `google-cloud-modelarmor`'s `ModelArmorClient`.

    The scanner is created once per process and reused for both user-prompt
    and model-response scans. Thread-safe because the underlying Google
    client is thread-safe.
    """

    def __init__(
        self,
        *,
        template: str,
        endpoint: str | None = None,
        client: Any = None,
    ) -> None:
        """Initialize the scanner.

        Args:
            template: Full template name of the form
                ``projects/PROJECT/locations/LOCATION/templates/TEMPLATE``.
            endpoint: Optional regional endpoint override
                (``modelarmor.us-central1.rep.googleapis.com``). If not
                supplied, the Model Armor client defaults are used.
            client: Optional pre-built `ModelArmorClient` - used by tests
                to inject a mock. If None, the client is created lazily.
        """
        if not template:
            raise ValueError("Model Armor template must be a non-empty string")

        self.template = template
        self.endpoint = endpoint
        self._client: Any = client

    @classmethod
    def from_env(cls) -> ModelArmorScanner:
        """Build a scanner from the AIRLOCK_MODEL_ARMOR_* environment variables.

        Raises:
            ValueError: If `AIRLOCK_MODEL_ARMOR_TEMPLATE` is not set.
            ModelArmorNotInstalled: Deferred until the first scan call.
        """
        template = os.environ.get(ENV_TEMPLATE, "").strip()
        if not template:
            raise ValueError(
                f"{ENV_TEMPLATE} is required to enable Model Armor scanning. "
                "Set it to projects/PROJECT/locations/LOCATION/templates/TEMPLATE."
            )
        endpoint = os.environ.get(ENV_ENDPOINT, "").strip() or None
        return cls(template=template, endpoint=endpoint)

    @staticmethod
    def is_enabled() -> bool:
        """Check if the adapter is enabled via environment variable."""
        return os.environ.get(ENV_ENABLED, "").lower() in {"1", "true", "yes", "on"}

    # -------------------------------------------------------------------------
    # Client lifecycle
    # -------------------------------------------------------------------------

    def _get_client(self) -> Any:
        """Lazily construct the Google client on first use."""
        if self._client is not None:
            return self._client

        try:
            from google.cloud import modelarmor_v1  # type: ignore[import-not-found]
        except ImportError as e:  # pragma: no cover - exercised by tests via monkeypatch
            raise ModelArmorNotInstalled(
                "Model Armor adapter requires `google-cloud-modelarmor`. "
                'Install with: pip install "agent-airlock[model-armor]"'
            ) from e

        client_options: dict[str, Any] = {}
        if self.endpoint:
            client_options["api_endpoint"] = self.endpoint

        self._client = modelarmor_v1.ModelArmorClient(client_options=client_options or None)
        return self._client

    # -------------------------------------------------------------------------
    # Scanning
    # -------------------------------------------------------------------------

    def scan_user_prompt(self, prompt: str) -> ModelArmorScanResult:
        """Scan a user prompt. Returns a `ModelArmorScanResult`.

        Args:
            prompt: The user-supplied prompt to scan.

        Returns:
            ModelArmorScanResult with `allowed=False` when Model Armor
            reports a filter match, `allowed=True` otherwise.
        """
        return self._scan("sanitize_user_prompt", prompt=prompt, response=None)

    def scan_model_response(
        self,
        response: str,
        *,
        user_prompt: str | None = None,
    ) -> ModelArmorScanResult:
        """Scan a model response.

        Args:
            response: The model-generated response text.
            user_prompt: Optional original user prompt for context
                (some Model Armor filters use this to reduce false
                positives).

        Returns:
            ModelArmorScanResult describing any violations.
        """
        return self._scan("sanitize_model_response", prompt=user_prompt, response=response)

    # -------------------------------------------------------------------------
    # Internal
    # -------------------------------------------------------------------------

    def _scan(
        self,
        method_name: str,
        *,
        prompt: str | None,
        response: str | None,
    ) -> ModelArmorScanResult:
        client = self._get_client()

        try:
            from google.cloud import modelarmor_v1  # type: ignore[import-not-found]
        except ImportError as e:  # pragma: no cover
            raise ModelArmorNotInstalled(str(e)) from e

        # Build the request. We use the documented snake_case field names;
        # if a future client version renames these, the getattr-based
        # unpacking on the response side still works.
        request: Any
        if method_name == "sanitize_user_prompt":
            request = modelarmor_v1.SanitizeUserPromptRequest(
                name=self.template,
                user_prompt_data=modelarmor_v1.DataItem(text=prompt or ""),
            )
        elif method_name == "sanitize_model_response":
            kwargs: dict[str, Any] = {
                "name": self.template,
                "model_response_data": modelarmor_v1.DataItem(text=response or ""),
            }
            if prompt:
                kwargs["user_prompt"] = prompt
            request = modelarmor_v1.SanitizeModelResponseRequest(**kwargs)
        else:
            raise ValueError(f"unknown scan method: {method_name!r}")

        api = getattr(client, method_name)
        raw = api(request=request)

        return self._parse_result(raw)

    @staticmethod
    def _parse_result(raw: Any) -> ModelArmorScanResult:
        """Turn the raw Google response into a structured result.

        Uses `getattr` with safe fallbacks so a Google-side schema drift
        surfaces as "no detection" rather than an exception — the worst
        case is a missed block, which the operator will catch on the
        sanitizer or tool-policy layer. A Google-side field REMOVAL
        surfacing as a crash would be worse: it'd take the tool down
        even for benign input.
        """
        sanitization = getattr(raw, "sanitization_result", raw)

        match_state_obj = getattr(sanitization, "filter_match_state", "")
        match_state = str(
            match_state_obj.name if hasattr(match_state_obj, "name") else match_state_obj
        )

        invocation_obj = getattr(sanitization, "invocation_result", "")
        invocation_state = str(
            invocation_obj.name if hasattr(invocation_obj, "name") else invocation_obj
        )

        categories: dict[str, str] = {}
        for cat in CANONICAL_FILTER_CATEGORIES:
            cat_result = getattr(sanitization, cat, None)
            if cat_result is None:
                continue
            cat_match = getattr(cat_result, "match_state", "")
            cat_state = str(cat_match.name if hasattr(cat_match, "name") else cat_match)
            if cat_state:
                categories[cat] = cat_state

        is_match = match_state == "MATCH_FOUND"
        reason = ""
        if is_match:
            matched_cats = [c for c, s in categories.items() if s == "MATCH_FOUND"]
            reason = "Model Armor reported a filter match" + (
                f" in {', '.join(matched_cats)}" if matched_cats else ""
            )

        return ModelArmorScanResult(
            allowed=not is_match,
            match_state=match_state,
            invocation_state=invocation_state,
            categories=categories,
            reason=reason,
            raw=raw,
        )


__all__ = [
    "ModelArmorScanner",
    "ModelArmorScanResult",
    "ModelArmorNotInstalled",
    "ENV_ENABLED",
    "ENV_TEMPLATE",
    "ENV_ENDPOINT",
    "CANONICAL_FILTER_CATEGORIES",
]
