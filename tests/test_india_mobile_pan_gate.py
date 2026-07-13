"""v0.8.46 — India DPDP additions: INDIA_MOBILE detector + PAN entity-char gate.

Extends the existing opt-in Indic PII masking (Aadhaar Verhoeff gate, Devanagari
names) with two first-class additions on the SAME `SensitiveDataType` registry
(no parallel system):

1. ``SensitiveDataType.INDIA_MOBILE`` — a ``+91`` / ``91`` / trunk-``0`` prefixed
   10-digit number starting 6-9. Deliberately prefix-required: a *bare* 10-digit
   run is already covered by the US-shaped PHONE detector, so INDIA_MOBILE only
   claims the +91 forms PHONE misses (and never shares a span with it).
2. A PAN 4th-character entity-type gate, mirroring the Aadhaar Verhoeff gate:
   under ``pii_locales=["in"]`` a PAN-shaped match whose holder-type code is
   invalid is dropped. Off by default (backwards-compatible).

Both are wired into the existing ``india_dpdp_2023`` / ``"in"``-locale path — no
new preset.
"""

from __future__ import annotations

import pytest

from agent_airlock import apply_india_dpdp_2023
from agent_airlock.sanitizer import (
    _PAN_ENTITY_TYPES,
    MaskingStrategy,
    SensitiveDataType,
    _pan_entity_char_valid,
    detect_sensitive_data,
    mask_sensitive_data,
    sanitize_output,
)

# A Verhoeff-valid Aadhaar (reused from the existing indic-PII fixtures).
VALID_AADHAAR = "234567890124"
# A 12-digit order/reference number that is NOT an Aadhaar (fails Verhoeff) and
# must never be masked as a mobile either.
BENIGN_ORDER_NUMBER = "234567890123"


def _types(text: str, locale: tuple[str, ...] | None = ("in",)) -> list[tuple[str, str]]:
    loc = list(locale) if locale is not None else None
    return [(d["type"], d["value"]) for d in detect_sensitive_data(text, pii_locales=loc)]


# ---------------------------------------------------------------------------
# INDIA_MOBILE detection
# ---------------------------------------------------------------------------


class TestIndiaMobileDetection:
    @pytest.mark.parametrize(
        "text",
        [
            "call me on +919876543210",
            "call me on +91 9876543210",
            "call me on +91-9876543210",
            "number 919876543210 saved",
            "number 09876543210 saved",
        ],
    )
    def test_prefixed_forms_detected(self, text: str) -> None:
        mobiles = [v for (t, v) in _types(text) if t == "india_mobile"]
        assert len(mobiles) == 1, f"expected one mobile in {text!r}"

    def test_bare_10_digit_is_not_india_mobile(self) -> None:
        # A bare 10-digit run is already covered by the PHONE detector; requiring
        # the +91/0 prefix keeps INDIA_MOBILE from sharing that span.
        mobiles = [v for (t, v) in _types("call 9876543210 now") if t == "india_mobile"]
        assert mobiles == []

    def test_non_6_to_9_leading_digit_rejected(self) -> None:
        # Landline / invalid ranges (subscriber number must start 6-9).
        mobiles = [v for (t, v) in _types("dial +91 5876543210") if t == "india_mobile"]
        assert mobiles == []

    def test_benign_order_number_not_a_mobile(self) -> None:
        mobiles = [
            v for (t, v) in _types(f"order {BENIGN_ORDER_NUMBER} shipped") if t == "india_mobile"
        ]
        assert mobiles == []

    def test_mask_format_reveals_last_3(self) -> None:
        masked, detections = mask_sensitive_data(
            "reach me at +919876543210", types=[SensitiveDataType.INDIA_MOBILE]
        )
        assert masked == "reach me at +91-XXXXX-210"
        assert detections[0]["type"] == "india_mobile"

    def test_default_strategy_is_partial(self) -> None:
        from agent_airlock.sanitizer import DEFAULT_MASK_CONFIG

        assert DEFAULT_MASK_CONFIG[SensitiveDataType.INDIA_MOBILE] is MaskingStrategy.PARTIAL


# ---------------------------------------------------------------------------
# PAN entity-char gate
# ---------------------------------------------------------------------------


class TestPanEntityCharGate:
    @pytest.mark.parametrize("entity", sorted(_PAN_ENTITY_TYPES))
    def test_valid_entity_char_detected_under_locale(self, entity: str) -> None:
        pan = f"ABC{entity}E1234F"
        assert _pan_entity_char_valid(pan) is True
        detections = detect_sensitive_data(
            f"pan {pan}", [SensitiveDataType.PAN], pii_locales=["in"]
        )
        assert [d["value"] for d in detections] == [pan]

    @pytest.mark.parametrize("entity", ["D", "E", "I", "K", "Z"])
    def test_invalid_entity_char_dropped_under_locale(self, entity: str) -> None:
        pan = f"ABC{entity}E1234F"
        assert _pan_entity_char_valid(pan) is False
        detections = detect_sensitive_data(
            f"pan {pan}", [SensitiveDataType.PAN], pii_locales=["in"]
        )
        assert detections == []

    def test_no_locale_keeps_permissive_pan_behavior(self) -> None:
        # Backwards-compat: without the india locale, the bare regex still
        # matches any [A-Z]{5}[0-9]{4}[A-Z] shape (entity gate is opt-in).
        pan = "ABCZE1234F"  # invalid 4th char, but no locale => still matched
        detections = detect_sensitive_data(f"pan {pan}", [SensitiveDataType.PAN])
        assert [d["value"] for d in detections] == [pan]

    def test_entity_set_is_the_canonical_ten(self) -> None:
        assert frozenset("PCHFATBLJG") == _PAN_ENTITY_TYPES


# ---------------------------------------------------------------------------
# Wiring into the existing India DPDP path (no parallel preset)
# ---------------------------------------------------------------------------


class TestDpdpWiring:
    def test_mobile_in_india_locale_pii_set(self) -> None:
        from agent_airlock.sanitizer import _INDIA_LOCALE_PII_TYPES

        assert SensitiveDataType.INDIA_MOBILE in _INDIA_LOCALE_PII_TYPES

    def test_sanitize_output_masks_mobile_and_pan_under_in_locale(self) -> None:
        text = "phone +919876543210 pan ABCPE1234F"
        result = sanitize_output(text, pii_locales=["in"])
        assert "+919876543210" not in result.content
        assert "ABCPE1234F" not in result.content
        assert "+91-XXXXX-210" in result.content

    def test_apply_india_dpdp_bundle_enables_mobile(self) -> None:
        bundle = apply_india_dpdp_2023()
        assert "in" in bundle.config.pii_locales
        result = sanitize_output(
            "call +919876543210",
            mask_pii=bundle.config.mask_pii,
            pii_locales=bundle.config.pii_locales,
        )
        assert "+919876543210" not in result.content


# ---------------------------------------------------------------------------
# Step-10 smoke: Aadhaar masked, benign 12-digit order number untouched
# ---------------------------------------------------------------------------


class TestAadhaarVsOrderNumber:
    def test_valid_aadhaar_masked_benign_order_number_not(self) -> None:
        text = f"aadhaar {VALID_AADHAAR} order {BENIGN_ORDER_NUMBER}"
        result = sanitize_output(text, pii_locales=["in"])
        assert VALID_AADHAAR not in result.content  # Verhoeff-valid Aadhaar masked
        assert BENIGN_ORDER_NUMBER in result.content  # benign 12-digit untouched
