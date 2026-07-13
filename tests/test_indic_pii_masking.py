"""V0.8.9 — opt-in Indic PII masking (Verhoeff Aadhaar gate + Devanagari names).

The existing Aadhaar / PAN / UPI / IFSC detectors keep their permissive
default behavior. When ``pii_locales=["in"]`` is supplied, two new behaviors
activate:

1. Aadhaar regex matches are validated against the UIDAI Verhoeff checksum,
   so random 12-digit numbers no longer false-positive as Aadhaar.
2. A Devanagari personal-name detector (U+0900–U+097F) runs, with a small
   common-noun allowlist to keep ordinary Hindi prose from being masked.

The locale tag is additive — existing callers that don't pass it get
exactly the prior behavior (verified by ``tests/test_sanitizer.py``).
"""

from __future__ import annotations

import pytest

from agent_airlock import Airlock, AirlockConfig
from agent_airlock.sanitizer import (
    MaskingStrategy,
    SensitiveDataType,
    _verhoeff_check,
    detect_sensitive_data,
    mask_sensitive_data,
    sanitize_output,
)

# ---------------------------------------------------------------------------
# Fixtures: Verhoeff-valid and Verhoeff-invalid 12-digit numbers
# ---------------------------------------------------------------------------

# Synthetic Aadhaar-shaped numbers that pass the Verhoeff checksum. Computed
# by exhaustive last-digit search; do not match any real-world Aadhaar.
VALID_AADHAAR_NUMBERS = (
    "234567890124",
    "998877665548",
    "345678901238",
)

# 12-digit number that matches the Aadhaar regex (starts 2-9, all digits)
# but fails the Verhoeff checksum — exactly the kind of false positive
# the opt-in gate is designed to catch. This is the fixture used by
# the existing tests in test_sanitizer.py.
INVALID_AADHAAR_NUMBERS = (
    "234567890123",  # last digit one off from 234567890124
    "234567890125",
    "345678901230",
)


# ---------------------------------------------------------------------------
# Verhoeff helper
# ---------------------------------------------------------------------------


class TestVerhoeffHelper:
    """Direct tests of the Verhoeff implementation."""

    @pytest.mark.parametrize("num", VALID_AADHAAR_NUMBERS)
    def test_valid_aadhaar_passes(self, num: str) -> None:
        assert _verhoeff_check(num) is True

    @pytest.mark.parametrize("num", INVALID_AADHAAR_NUMBERS)
    def test_invalid_aadhaar_fails(self, num: str) -> None:
        assert _verhoeff_check(num) is False

    def test_non_digit_input_rejected(self) -> None:
        assert _verhoeff_check("12345abcdefg") is False
        assert _verhoeff_check("") is False

    def test_short_input_still_runs(self) -> None:
        # Verhoeff works on any length — the gate is whether the
        # composed checksum returns 0. A bare zero passes (trivial).
        assert _verhoeff_check("0") is True

    def test_known_pair_one_digit_apart_differ(self) -> None:
        """Sanity: changing any digit breaks the checksum."""
        for valid in VALID_AADHAAR_NUMBERS:
            mutated = valid[:-1] + str((int(valid[-1]) + 1) % 10)
            assert _verhoeff_check(mutated) is False


# ---------------------------------------------------------------------------
# Aadhaar locale gate
# ---------------------------------------------------------------------------


class TestAadhaarLocaleGate:
    """Aadhaar behavior with and without ``pii_locales=['in']``."""

    def test_no_locale_keeps_permissive_match(self) -> None:
        """Without opt-in, the existing permissive regex behavior holds —
        a Verhoeff-invalid 12-digit number still matches (backwards-compat)."""
        content = "Aadhaar: 234567890123"
        detections = detect_sensitive_data(content, [SensitiveDataType.AADHAAR])
        assert len(detections) == 1
        assert detections[0]["type"] == "aadhaar"

    def test_in_locale_keeps_verhoeff_valid_match(self) -> None:
        content = "Aadhaar: 234567890124"  # passes Verhoeff
        detections = detect_sensitive_data(
            content,
            [SensitiveDataType.AADHAAR],
            pii_locales=["in"],
        )
        assert len(detections) == 1
        assert detections[0]["value"] == "234567890124"

    def test_in_locale_drops_verhoeff_invalid_match(self) -> None:
        content = "Aadhaar: 234567890123"  # fails Verhoeff
        detections = detect_sensitive_data(
            content,
            [SensitiveDataType.AADHAAR],
            pii_locales=["in"],
        )
        assert detections == []

    def test_in_locale_handles_spaced_and_dashed_forms(self) -> None:
        """Verhoeff gate must ignore separators when re-parsing the digits."""
        for sep in (" ", "-", ""):
            content = f"Aadhaar: 2345{sep}6789{sep}0124"
            detections = detect_sensitive_data(
                content,
                [SensitiveDataType.AADHAAR],
                pii_locales=["in"],
            )
            assert len(detections) == 1, f"failed for separator {sep!r}"

    def test_in_locale_irrelevant_when_aadhaar_not_in_types(self) -> None:
        """The locale gate only affects types the caller asked for."""
        content = "user@example.com"
        detections = detect_sensitive_data(
            content,
            [SensitiveDataType.EMAIL],
            pii_locales=["in"],
        )
        assert len(detections) == 1
        assert detections[0]["type"] == "email"


# ---------------------------------------------------------------------------
# Devanagari personal-name detection
# ---------------------------------------------------------------------------


class TestDevanagariNameDetection:
    """Devanagari personal-name span heuristic + common-noun allowlist."""

    def test_two_word_name_detected(self) -> None:
        content = "Name: राम कुमार"
        detections = detect_sensitive_data(
            content,
            [SensitiveDataType.PERSONAL_NAME_DEVANAGARI],
            pii_locales=["in"],
        )
        assert len(detections) >= 1
        assert any("राम कुमार" in d["value"] for d in detections)

    def test_single_word_name_detected(self) -> None:
        content = "अमित"
        detections = detect_sensitive_data(
            content,
            [SensitiveDataType.PERSONAL_NAME_DEVANAGARI],
            pii_locales=["in"],
        )
        assert len(detections) == 1

    def test_common_noun_filtered_by_allowlist(self) -> None:
        """नमस्ते is a greeting, not a name — the allowlist must drop it."""
        content = "नमस्ते"
        detections = detect_sensitive_data(
            content,
            [SensitiveDataType.PERSONAL_NAME_DEVANAGARI],
            pii_locales=["in"],
        )
        assert detections == []

    def test_pronoun_string_filtered(self) -> None:
        """Sequence of allowlisted tokens — every word is a known non-name."""
        content = "मैं और आप"
        detections = detect_sensitive_data(
            content,
            [SensitiveDataType.PERSONAL_NAME_DEVANAGARI],
            pii_locales=["in"],
        )
        assert detections == []

    def test_mixed_sentence_keeps_name_span_only(self) -> None:
        """A real sentence with greeting + name should still flag the name part."""
        content = "नमस्ते राम कुमार"
        detections = detect_sensitive_data(
            content,
            [SensitiveDataType.PERSONAL_NAME_DEVANAGARI],
            pii_locales=["in"],
        )
        # The regex matches contiguous Devanagari words; the heuristic
        # may produce one or two spans. At least one detection must
        # include the actual name tokens.
        assert any("राम" in d["value"] and "कुमार" in d["value"] for d in detections)

    def test_no_opt_in_no_devanagari_detection_via_sanitize_output(self) -> None:
        """Without ``pii_locales=["in"]``, sanitize_output does NOT add
        Devanagari to its default PII set even when mask_pii=True."""
        content = "Hello राम कुमार"
        result = sanitize_output(content, mask_pii=True)
        # No Devanagari detection in the default surface
        assert not any(d["type"] == "personal_name_devanagari" for d in result.detections)


# ---------------------------------------------------------------------------
# sanitize_output end-to-end
# ---------------------------------------------------------------------------


class TestSanitizeOutputLocale:
    """End-to-end masking through sanitize_output with the locale opt-in."""

    def test_locale_in_extends_pii_set(self) -> None:
        """``mask_pii=True`` + ``pii_locales=["in"]`` masks Aadhaar/PAN/Devanagari."""
        content = "User: राम शर्मा, Aadhaar: 234567890124, PAN: ABCPE1234F, email: foo@example.com"
        result = sanitize_output(content, mask_pii=True, pii_locales=["in"])
        types_found = {d["type"] for d in result.detections}
        # Existing US-shape email still masked (unchanged)
        assert "email" in types_found
        # India-locale opt-in adds these three
        assert "aadhaar" in types_found
        assert "pan" in types_found
        assert "personal_name_devanagari" in types_found

    def test_locale_in_drops_verhoeff_invalid_aadhaar(self) -> None:
        """An invalid-checksum 12-digit number is NOT masked under in-locale."""
        content = "Random ID: 234567890123 belongs to nobody."
        result = sanitize_output(content, mask_pii=True, pii_locales=["in"])
        types_found = {d["type"] for d in result.detections}
        assert "aadhaar" not in types_found

    def test_no_locale_default_behavior_unchanged(self) -> None:
        """Without ``pii_locales``, the default PII surface is unchanged."""
        content = "User: राम शर्मा, Aadhaar: 234567890124"
        result = sanitize_output(content, mask_pii=True)
        # No India types added without explicit opt-in
        types_found = {d["type"] for d in result.detections}
        assert "aadhaar" not in types_found
        assert "personal_name_devanagari" not in types_found

    def test_explicit_types_param_still_works_without_locale(self) -> None:
        """A caller can still mask Aadhaar by passing ``types`` directly —
        opt-in is additive, not exclusive (backwards-compat)."""
        content = "Aadhaar: 234567890123"  # fails Verhoeff
        masked, detections = mask_sensitive_data(content, [SensitiveDataType.AADHAAR])
        assert len(detections) == 1  # permissive regex still matches


# ---------------------------------------------------------------------------
# AirlockConfig + @Airlock integration
# ---------------------------------------------------------------------------


class TestAirlockConfigIntegration:
    """The opt-in propagates from AirlockConfig through the decorator seam."""

    def test_default_config_has_empty_pii_locales(self) -> None:
        config = AirlockConfig()
        assert config.pii_locales == []

    def test_config_accepts_in_locale(self) -> None:
        config = AirlockConfig(pii_locales=["in"])
        assert "in" in config.pii_locales

    def test_decorator_threads_locale_to_sanitizer(self) -> None:
        config = AirlockConfig(pii_locales=["in"])

        @Airlock(config=config, return_dict=True)
        def lookup(query: str) -> str:
            # Return content that should be masked under in-locale
            return f"Result for {query}: Aadhaar 234567890124, PAN ABCPE1234F"

        result = lookup(query="who")
        assert isinstance(result, dict)
        assert result["success"] is True
        # Aadhaar should be masked (partial)
        assert "234567890124" not in result["result"]
        # PAN should be masked (partial)
        assert "ABCPE1234F" not in result["result"]

    def test_decorator_without_locale_does_not_mask_aadhaar(self) -> None:
        """Without ``pii_locales=["in"]``, Aadhaar pass-through still works
        (existing behavior preserved)."""
        config = AirlockConfig()  # default: pii_locales=[]

        @Airlock(config=config, return_dict=True)
        def lookup(query: str) -> str:
            return f"Aadhaar 234567890124 for {query}"

        result = lookup(query="who")
        assert isinstance(result, dict)
        assert result["success"] is True
        # Aadhaar is NOT masked by default
        assert "234567890124" in result["result"]


# ---------------------------------------------------------------------------
# Backwards compatibility (existing fixtures keep working)
# ---------------------------------------------------------------------------


class TestBackwardsCompat:
    """The new ``pii_locales`` arg is optional — old call shapes still work."""

    def test_detect_without_locale(self) -> None:
        # Existing call shape: just (content, types)
        detections = detect_sensitive_data("user@example.com", [SensitiveDataType.EMAIL])
        assert len(detections) == 1

    def test_mask_without_locale(self) -> None:
        masked, _ = mask_sensitive_data("user@example.com", [SensitiveDataType.EMAIL])
        assert "@" in masked  # PARTIAL strategy keeps domain

    def test_sanitize_output_without_locale(self) -> None:
        result = sanitize_output("user@example.com", mask_pii=True)
        assert result.detection_count >= 1

    def test_existing_aadhaar_tests_unaffected(self) -> None:
        """The existing test_sanitizer.py tests pass content like
        'Aadhaar: 2345 6789 0123' and expect 1 detection. The new
        opt-in must not change that default behavior."""
        content = "Aadhaar: 2345 6789 0123"  # this is the existing fixture
        detections = detect_sensitive_data(content, [SensitiveDataType.AADHAAR])
        # No locale → permissive match (the historical contract).
        assert len(detections) == 1


class TestIndiaPiiMaskOutput:
    """Pin the exact PARTIAL masked render for Aadhaar / PAN / UPI.

    Aadhaar follows the UIDAI masked-Aadhaar standard: only the last 4 digits
    are revealed (the first 8 are never shown), instead of the generic
    first-3 + last-3 fall-through that would leak 6 of 12 digits.
    """

    @pytest.mark.parametrize("aadhaar", VALID_AADHAAR_NUMBERS)
    def test_aadhaar_reveals_only_last_4(self, aadhaar: str) -> None:
        out = sanitize_output(f"Aadhaar: {aadhaar}", mask_pii=True, pii_locales=["in"]).content
        expected = "*" * 8 + aadhaar[-4:]  # UIDAI standard: 8 masked + last 4
        assert expected in out, f"{aadhaar} -> {out!r}, expected to contain {expected!r}"
        # the first 8 digits must NOT appear in the output
        assert aadhaar[:8] not in out

    def test_aadhaar_masks_spaced_form_by_digit_count(self) -> None:
        # Separators (spaces / hyphens) must not change the revealed count.
        out = sanitize_output("id 2345 6789 0124 ok", mask_pii=True, pii_locales=["in"]).content
        assert "********0124" in out
        assert "2345" not in out  # leading group fully masked

    def test_pan_reveals_first_2_and_last_2(self) -> None:
        out = sanitize_output("PAN: ABCPE1234F", mask_pii=True, pii_locales=["in"]).content
        assert "AB******4F" in out  # first 2 + 6 masked + last 2
        assert "ABCDE" not in out

    def test_upi_partial_keeps_bank_suffix(self) -> None:
        out = sanitize_output(
            "pay alice.kumar@oksbi now", mask_pii=True, pii_locales=["in"]
        ).content
        # The @bank handle is kept (semi-public); the VPA local part is masked.
        assert "@oksbi" in out
        assert "a***@oksbi" in out
        assert "alice.kumar" not in out

    def test_full_strategy_overrides_to_redacted(self) -> None:
        out, _ = mask_sensitive_data(
            f"Aadhaar: {VALID_AADHAAR_NUMBERS[0]}",
            [SensitiveDataType.AADHAAR],
            mask_config={SensitiveDataType.AADHAAR: MaskingStrategy.FULL},
            pii_locales=["in"],
        )
        assert "[REDACTED]" in out
        assert VALID_AADHAAR_NUMBERS[0][-4:] not in out

    def test_hash_strategy_emits_sha_prefix(self) -> None:
        out, _ = mask_sensitive_data(
            "PAN: ABCPE1234F",
            [SensitiveDataType.PAN],
            mask_config={SensitiveDataType.PAN: MaskingStrategy.HASH},
            pii_locales=["in"],
        )
        assert "[SHA256:" in out
        assert "ABCPE1234F" not in out


class TestUpiHandleCoverage:
    """v0.8.37 expanded the UPI handle allowlist to current NPCI handles."""

    @pytest.mark.parametrize(
        "vpa",
        [
            "alice@waicici",  # WhatsApp Pay
            "bob@axisbank",
            "cara@hdfcbank",
            "dev@idfcfirst",
            "eve@kotak",
            "fay@yesbank",
            "gita@fbl",  # Federal
            "hari@indusind",
            "ina@rbl",
            "jay@ptsbi",  # Paytm Payments Bank
            "kim@superyes",  # Slice
            "leo@cred",
            "max@paytm",  # existing handles still match
            "old@ybl",
        ],
    )
    def test_handle_detected(self, vpa: str) -> None:
        det = detect_sensitive_data(f"pay {vpa} now", pii_locales=["in"])
        assert any(x["type"] == SensitiveDataType.UPI_ID.value for x in det), vpa

    def test_longer_handle_wins_over_prefix(self) -> None:
        # @axisbank must match in full, not stop at a shorter alternative.
        det = detect_sensitive_data("pay bob@axisbank now", pii_locales=["in"])
        vals = [x["value"] for x in det if x["type"] == SensitiveDataType.UPI_ID.value]
        assert "bob@axisbank" in vals

    def test_non_upi_domain_not_flagged(self) -> None:
        det = detect_sensitive_data("mail alice@gmail.com", pii_locales=["in"])
        assert not any(x["type"] == SensitiveDataType.UPI_ID.value for x in det)
