"""Tests for the sanitizer module."""

import random

from agent_airlock import (
    Airlock,
    AirlockConfig,
    MaskingStrategy,
    SanitizationResult,
    SensitiveDataType,
    detect_sensitive_data,
    mask_sensitive_data,
    sanitize_output,
)
from agent_airlock.sanitizer import merge_overlapping_detections


class TestDetectSensitiveData:
    """Tests for sensitive data detection."""

    def test_detect_email(self) -> None:
        content = "Contact me at john.doe@example.com for more info."
        detections = detect_sensitive_data(content, [SensitiveDataType.EMAIL])

        assert len(detections) == 1
        assert detections[0]["type"] == "email"
        assert detections[0]["value"] == "john.doe@example.com"

    def test_detect_multiple_emails(self) -> None:
        content = "Email alice@test.com or bob@test.org for help."
        detections = detect_sensitive_data(content, [SensitiveDataType.EMAIL])

        assert len(detections) == 2
        assert detections[0]["value"] == "alice@test.com"
        assert detections[1]["value"] == "bob@test.org"

    def test_detect_phone_number(self) -> None:
        content = "Call me at (555) 123-4567 or 555.987.6543"
        detections = detect_sensitive_data(content, [SensitiveDataType.PHONE])

        assert len(detections) == 2

    def test_detect_ssn(self) -> None:
        content = "SSN: 123-45-6789"
        detections = detect_sensitive_data(content, [SensitiveDataType.SSN])

        assert len(detections) == 1
        assert detections[0]["type"] == "ssn"

    def test_detect_credit_card_visa(self) -> None:
        content = "Card: 4111111111111111"
        detections = detect_sensitive_data(content, [SensitiveDataType.CREDIT_CARD])

        assert len(detections) == 1
        assert detections[0]["type"] == "credit_card"

    def test_detect_credit_card_mastercard(self) -> None:
        content = "Card: 5500000000000004"
        detections = detect_sensitive_data(content, [SensitiveDataType.CREDIT_CARD])

        assert len(detections) == 1

    def test_detect_credit_card_amex(self) -> None:
        content = "Card: 340000000000009"
        detections = detect_sensitive_data(content, [SensitiveDataType.CREDIT_CARD])

        assert len(detections) == 1

    def test_detect_ip_address(self) -> None:
        content = "Server IP: 192.168.1.100"
        detections = detect_sensitive_data(content, [SensitiveDataType.IP_ADDRESS])

        assert len(detections) == 1
        assert detections[0]["value"] == "192.168.1.100"

    def test_detect_openai_api_key(self) -> None:
        content = "API key: sk-abcdefghijklmnopqrstuvwxyz"
        detections = detect_sensitive_data(content, [SensitiveDataType.API_KEY])

        assert len(detections) == 1
        assert detections[0]["type"] == "api_key"

    def test_detect_anthropic_api_key(self) -> None:
        content = "Key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz"
        detections = detect_sensitive_data(content, [SensitiveDataType.API_KEY])

        assert len(detections) == 1

    def test_detect_github_pat(self) -> None:
        content = "Token: ghp_abcdefghijklmnopqrstuvwxyz0123456789"
        detections = detect_sensitive_data(content, [SensitiveDataType.API_KEY])

        assert len(detections) == 1

    def test_detect_aws_key(self) -> None:
        content = "AWS Key: AKIAIOSFODNN7EXAMPLE"
        detections = detect_sensitive_data(content, [SensitiveDataType.AWS_KEY])

        assert len(detections) == 1
        assert detections[0]["type"] == "aws_key"

    def test_detect_password(self) -> None:
        content = "password = 'mysecretpassword123'"
        detections = detect_sensitive_data(content, [SensitiveDataType.PASSWORD])

        assert len(detections) == 1
        assert detections[0]["type"] == "password"
        assert detections[0]["value"] == "mysecretpassword123"

    def test_detect_private_key(self) -> None:
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."
        detections = detect_sensitive_data(content, [SensitiveDataType.PRIVATE_KEY])

        assert len(detections) == 1

    def test_detect_jwt(self) -> None:
        jwt_token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        )
        content = f"Token: {jwt_token}"
        detections = detect_sensitive_data(content, [SensitiveDataType.JWT])

        assert len(detections) == 1

    def test_detect_connection_string_postgres(self) -> None:
        content = "DB: postgres://user:pass@host:5432/db"
        detections = detect_sensitive_data(content, [SensitiveDataType.CONNECTION_STRING])

        assert len(detections) == 1

    def test_detect_connection_string_mongodb(self) -> None:
        # Assembled at runtime so secret scanning does not file the placeholder URI.
        content = "mongodb+srv://" + "user:pass" + "@cluster.mongodb.net/db"
        detections = detect_sensitive_data(content, [SensitiveDataType.CONNECTION_STRING])

        assert len(detections) == 1

    # India-specific PII tests
    def test_detect_aadhaar(self) -> None:
        """Test detection of Indian Aadhaar numbers."""
        content = "Aadhaar: 2345 6789 0123"
        detections = detect_sensitive_data(content, [SensitiveDataType.AADHAAR])

        assert len(detections) == 1
        assert detections[0]["type"] == "aadhaar"

    def test_detect_aadhaar_no_spaces(self) -> None:
        """Test detection of Aadhaar without spaces."""
        content = "ID: 234567890123"
        detections = detect_sensitive_data(content, [SensitiveDataType.AADHAAR])

        assert len(detections) == 1

    def test_detect_aadhaar_with_dashes(self) -> None:
        """Test detection of Aadhaar with dashes."""
        content = "Aadhaar: 2345-6789-0123"
        detections = detect_sensitive_data(content, [SensitiveDataType.AADHAAR])

        assert len(detections) == 1

    def test_detect_pan(self) -> None:
        """Test detection of Indian PAN card numbers."""
        content = "PAN: ABCDE1234F"
        detections = detect_sensitive_data(content, [SensitiveDataType.PAN])

        assert len(detections) == 1
        assert detections[0]["type"] == "pan"
        assert detections[0]["value"] == "ABCDE1234F"

    def test_detect_upi_id(self) -> None:
        """Test detection of UPI IDs."""
        content = "Pay to: user.name@okaxis"
        detections = detect_sensitive_data(content, [SensitiveDataType.UPI_ID])

        assert len(detections) == 1
        assert detections[0]["type"] == "upi_id"

    def test_detect_upi_id_variants(self) -> None:
        """Test detection of various UPI ID formats."""
        test_cases = [
            "john@ybl",
            "payment@paytm",
            "user123@oksbi",
            "shop@phonepe",
        ]
        for upi in test_cases:
            content = f"UPI: {upi}"
            detections = detect_sensitive_data(content, [SensitiveDataType.UPI_ID])
            assert len(detections) == 1, f"Failed to detect {upi}"

    def test_detect_ifsc(self) -> None:
        """Test detection of IFSC codes."""
        content = "IFSC: SBIN0001234"
        detections = detect_sensitive_data(content, [SensitiveDataType.IFSC])

        assert len(detections) == 1
        assert detections[0]["type"] == "ifsc"
        assert detections[0]["value"] == "SBIN0001234"

    def test_detect_ifsc_various_banks(self) -> None:
        """Test detection of IFSC codes from various banks."""
        test_cases = ["HDFC0001234", "ICIC0006789", "UTIB0002345", "PUNB0123400"]
        for ifsc in test_cases:
            content = f"Bank IFSC: {ifsc}"
            detections = detect_sensitive_data(content, [SensitiveDataType.IFSC])
            assert len(detections) == 1, f"Failed to detect {ifsc}"

    def test_detect_all_types(self) -> None:
        content = "Email: test@example.com, SSN: 123-45-6789"
        detections = detect_sensitive_data(content)  # All types

        assert len(detections) >= 2

    def test_no_detections(self) -> None:
        content = "This is a normal message with no sensitive data."
        detections = detect_sensitive_data(content)

        assert len(detections) == 0


class TestMaskSensitiveData:
    """Tests for sensitive data masking."""

    def test_mask_email_partial(self) -> None:
        content = "Email: john.doe@example.com"
        masked, detections = mask_sensitive_data(content, [SensitiveDataType.EMAIL])

        assert "john.doe@example.com" not in masked
        assert "@example.com" in masked  # Domain preserved
        assert len(detections) == 1

    def test_mask_ssn_full(self) -> None:
        content = "SSN: 123-45-6789"
        masked, detections = mask_sensitive_data(content, [SensitiveDataType.SSN])

        assert "123-45-6789" not in masked
        assert "[REDACTED]" in masked

    def test_mask_credit_card_partial(self) -> None:
        content = "Card: 4111111111111111"
        masked, detections = mask_sensitive_data(content, [SensitiveDataType.CREDIT_CARD])

        assert "4111111111111111" not in masked
        assert "1111" in masked  # Last 4 preserved

    def test_mask_api_key_partial(self) -> None:
        content = "Key: sk-abcdefghijklmnopqrstuvwxyz"
        masked, detections = mask_sensitive_data(content, [SensitiveDataType.API_KEY])

        assert "sk-abcdefghijklmnopqrstuvwxyz" not in masked
        assert "sk-abcd" in masked  # Prefix preserved

    def test_mask_password_full(self) -> None:
        content = "password=supersecret123"
        masked, detections = mask_sensitive_data(content, [SensitiveDataType.PASSWORD])

        assert "supersecret123" not in masked
        assert "[REDACTED]" in masked

    def test_custom_masking_strategy(self) -> None:
        content = "Email: test@example.com"
        custom_config = {SensitiveDataType.EMAIL: MaskingStrategy.TYPE_ONLY}
        masked, detections = mask_sensitive_data(
            content,
            [SensitiveDataType.EMAIL],
            mask_config=custom_config,
        )

        assert "[EMAIL]" in masked

    def test_mask_multiple_values(self) -> None:
        content = "Email: a@b.com, Phone: 555-123-4567, SSN: 123-45-6789"
        masked, detections = mask_sensitive_data(content)

        assert "a@b.com" not in masked
        assert "123-45-6789" not in masked
        assert len(detections) >= 3

    def test_no_changes_when_no_sensitive_data(self) -> None:
        content = "This is normal text."
        masked, detections = mask_sensitive_data(content)

        assert masked == content
        assert len(detections) == 0


class TestTruncateOutput:
    """Tests for output truncation."""

    def test_no_truncation_when_under_limit(self) -> None:
        result = sanitize_output("Short text", max_chars=100)

        assert result.was_truncated is False
        assert result.content == "Short text"

    def test_truncation_when_over_limit(self) -> None:
        long_text = "x" * 1000
        result = sanitize_output(long_text, max_chars=100)

        assert result.was_truncated is True
        assert len(result.content) <= 100
        assert "[OUTPUT TRUNCATED:" in result.content

    def test_truncation_preserves_newline_boundary(self) -> None:
        text = "Line 1\nLine 2\nLine 3\nLine 4\nLine 5"
        result = sanitize_output(text, max_chars=30)

        assert result.was_truncated is True
        # Should truncate at a newline boundary when possible

    def test_no_truncation_when_limit_is_none(self) -> None:
        long_text = "x" * 10000
        result = sanitize_output(long_text, max_chars=None)

        assert result.was_truncated is False


class TestSanitizeOutput:
    """Tests for the main sanitize_output function."""

    def test_sanitize_string(self) -> None:
        content = "Email: test@example.com"
        result = sanitize_output(content)

        assert isinstance(result, SanitizationResult)
        assert result.detection_count > 0

    def test_sanitize_dict(self) -> None:
        content = {"email": "test@example.com", "data": "normal"}
        result = sanitize_output(content)

        assert result.detection_count > 0
        assert "test@example.com" not in result.content

    def test_sanitize_list(self) -> None:
        content = ["test@example.com", "normal text"]
        result = sanitize_output(content)

        assert result.detection_count > 0

    def test_disable_pii_masking(self) -> None:
        content = "Email: test@example.com"
        result = sanitize_output(content, mask_pii=False, mask_secrets=True)

        # Email should not be masked when PII masking is disabled
        assert "test@example.com" in result.content

    def test_disable_secret_masking(self) -> None:
        content = "Key: sk-abcdefghijklmnopqrstuvwxyz"
        result = sanitize_output(content, mask_pii=True, mask_secrets=False)

        # API key should not be masked when secret masking is disabled
        assert "sk-abcdefghijklmnopqrstuvwxyz" in result.content

    def test_result_metadata(self) -> None:
        content = "SSN: 123-45-6789 " + ("x" * 1000)
        result = sanitize_output(content, max_chars=150)

        assert result.original_length > 150
        assert result.was_truncated is True
        assert result.detection_count > 0

    def test_to_dict(self) -> None:
        content = "Email: test@example.com"
        result = sanitize_output(content)
        result_dict = result.to_dict()

        assert "original_length" in result_dict
        assert "sanitized_length" in result_dict
        assert "detection_count" in result_dict
        assert "was_truncated" in result_dict


class TestAirlockSanitizationIntegration:
    """Tests for Airlock decorator with sanitization."""

    def test_sanitizes_string_output(self) -> None:
        config = AirlockConfig(sanitize_output=True, mask_pii=True)

        @Airlock(config=config)
        def get_user_info(user_id: int) -> str:
            return f"User {user_id}: john.doe@example.com, SSN: 123-45-6789"

        result = get_user_info(user_id=123)

        assert isinstance(result, str)
        assert "john.doe@example.com" not in result
        assert "123-45-6789" not in result

    def test_return_dict_includes_warnings(self) -> None:
        config = AirlockConfig(sanitize_output=True, mask_pii=True)

        @Airlock(config=config, return_dict=True)
        def get_email(_user_id: int) -> str:
            return "User email: test@example.com"

        result = get_email(_user_id=1)

        assert isinstance(result, dict)
        assert result["success"] is True
        assert "warnings" in result
        assert len(result["warnings"]) > 0

    def test_truncates_long_output(self) -> None:
        config = AirlockConfig(
            sanitize_output=True,
            max_output_chars=100,
        )

        @Airlock(config=config)
        def get_long_text() -> str:
            return "x" * 1000

        result = get_long_text()

        assert isinstance(result, str)
        assert len(result) <= 100

    def test_sanitization_disabled(self) -> None:
        config = AirlockConfig(sanitize_output=False)

        @Airlock(config=config)
        def get_email() -> str:
            return "Email: test@example.com"

        result = get_email()

        assert isinstance(result, str)
        assert "test@example.com" in result

    def test_complex_return_type_not_modified(self) -> None:
        config = AirlockConfig(sanitize_output=True, mask_pii=True)

        @Airlock(config=config)
        def get_data() -> dict[str, str]:
            return {"email": "test@example.com"}

        result = get_data()

        # Dict results are not modified (sanitization is for detection/logging)
        assert isinstance(result, dict)


class TestMaskingStrategies:
    """Tests for different masking strategies."""

    def test_full_strategy(self) -> None:
        config = {SensitiveDataType.EMAIL: MaskingStrategy.FULL}
        content = "Email: test@example.com"
        masked, _ = mask_sensitive_data(content, [SensitiveDataType.EMAIL], config)

        assert "[REDACTED]" in masked

    def test_type_only_strategy(self) -> None:
        config = {SensitiveDataType.SSN: MaskingStrategy.TYPE_ONLY}
        content = "SSN: 123-45-6789"
        masked, _ = mask_sensitive_data(content, [SensitiveDataType.SSN], config)

        assert "[SSN]" in masked

    def test_hash_strategy(self) -> None:
        config = {SensitiveDataType.EMAIL: MaskingStrategy.HASH}
        content = "Email: test@example.com"
        masked, _ = mask_sensitive_data(content, [SensitiveDataType.EMAIL], config)

        assert "[HMAC:" in masked  # 0.10.29: keyed, was "[SHA256:"


class TestSensitiveDataTypes:
    """Tests for SensitiveDataType enum."""

    def test_pii_types(self) -> None:
        pii_types = [
            SensitiveDataType.EMAIL,
            SensitiveDataType.PHONE,
            SensitiveDataType.SSN,
            SensitiveDataType.CREDIT_CARD,
            SensitiveDataType.IP_ADDRESS,
        ]

        for dt in pii_types:
            assert isinstance(dt.value, str)

    def test_secret_types(self) -> None:
        secret_types = [
            SensitiveDataType.API_KEY,
            SensitiveDataType.PASSWORD,
            SensitiveDataType.AWS_KEY,
            SensitiveDataType.PRIVATE_KEY,
            SensitiveDataType.JWT,
            SensitiveDataType.CONNECTION_STRING,
        ]

        for dt in secret_types:
            assert isinstance(dt.value, str)


class TestOverlappingSpansDoNotCorruptOutput:
    """Masking must not damage the text around a span it replaces.

    Patterns are matched per entity type independently, so the same characters
    are routinely claimed twice. The pre-v0.10.8 masker sorted the detections by
    start, walked them in reverse, and rebuilt the string with
    ``result[:start] + masked + result[end:]`` against the string it had already
    modified. Reverse order keeps *earlier* offsets valid, but both offsets of
    the current span are read against the mutated string, so any length change
    from a previous replacement shifted ``end``.

    The damage is silent and lands outside the masked region, which is why no
    test caught it: the secret still looks masked, and the corruption is one or
    two characters of ordinary prose next to it.
    """

    def test_a_shorter_mask_does_not_eat_the_following_character(self) -> None:
        """The reported repro. ``phone`` masks 1 char shorter, so the space vanished."""
        result, _ = mask_sensitive_data("+91-9876543210 is mine")
        assert result == "+91-XXXXX-210 is mine"
        assert "210is" not in result, "the space after the number was consumed"

    def test_three_spans_two_of_them_overlapping(self) -> None:
        result, _ = mask_sensitive_data("call +91-9876543210 or 415-555-2671, thanks")
        assert result == "call +91-XXXXX-210 or 415***671, thanks"

    def test_a_longer_mask_does_not_duplicate_the_following_characters(self) -> None:
        """The other direction. A mask longer than its span re-emitted trailing text.

        ``credit_card`` masks to three characters more than it matched, so the
        surviving tail was written twice: ``.com`` came out as ``.comcom``.
        """
        result, _ = mask_sensitive_data("a@4111111111111111.com")
        assert result.count("com") == 1, "trailing text was duplicated"

    def test_text_outside_every_span_survives_byte_for_byte(self) -> None:
        """Whatever the masking does, the unmatched text must be untouched."""
        content = "call +91-9876543210 or 415-555-2671, thanks"
        result, detections = mask_sensitive_data(content)
        cursor = 0
        for detection in sorted(detections, key=lambda d: d["start"]):
            assert content[cursor : detection["start"]] in result
            cursor = detection["end"]
        assert content[cursor:] in result

    def test_one_detection_survives_per_overlapping_region(self) -> None:
        _result, detections = mask_sensitive_data("+91-9876543210 is mine")
        assert len(detections) == 1
        assert detections[0]["type"] == "india_mobile"

    def test_the_longest_span_is_the_one_that_wins(self) -> None:
        _result, detections = mask_sensitive_data("+91-9876543210 is mine")
        winner = detections[0]
        assert winner["end"] - winner["start"] == 14

    def test_a_suppressed_match_is_still_recorded(self) -> None:
        """A dropped detection must not vanish: detection_count is an audit surface."""
        _result, detections = mask_sensitive_data("+91-9876543210 is mine")
        assert detections[0]["absorbed"] == ["phone"]

    def test_every_returned_detection_was_actually_applied(self) -> None:
        """``masked_as`` on a detection that never reached the output would be a lie."""
        result, detections = mask_sensitive_data("call +91-9876543210 or 415-555-2671, thanks")
        for detection in detections:
            assert "masked_as" in detection
            assert detection["masked_as"] in result

    def test_non_overlapping_spans_are_all_kept(self) -> None:
        """Resolution must only drop genuine overlaps."""
        _result, detections = mask_sensitive_data("mail a@b.co ip 10.0.0.1 done")
        assert {d["type"] for d in detections} == {"email", "ip_address"}


class TestOverlapResolutionItself:
    """Direct tests for the merge rule, including the cases a naive rule gets wrong."""

    @staticmethod
    def _span(type_: str, start: int, end: int) -> dict[str, object]:
        return {
            "type": type_,
            "value": "x" * (end - start),
            "start": start,
            "end": end,
            "full_match": "x" * (end - start),
        }

    def test_a_contained_span_is_absorbed_by_its_container(self) -> None:
        content = "+91-9876543210 is mine"
        merged = merge_overlapping_detections(
            content, [self._span("phone", 4, 14), self._span("india_mobile", 0, 14)]
        )
        assert len(merged) == 1
        assert merged[0]["type"] == "india_mobile"
        assert (merged[0]["start"], merged[0]["end"]) == (0, 14)
        assert merged[0]["absorbed"] == ["phone"]

    def test_a_partial_overlap_covers_the_union_not_the_longer_span(self) -> None:
        """The case that makes "keep the longest" unsafe rather than merely lossy.

        ``ssn`` at ``(0, 11)`` and ``aadhaar`` at ``(7, 21)`` overlap without
        either containing the other. Keeping the longer one masks ``(7, 21)``
        and leaves ``123-45-`` in the output, which is an unmasked SSN prefix.
        """
        content = "123-45-6789 4111-1111-1111-1111"
        merged = merge_overlapping_detections(
            content, [self._span("ssn", 0, 11), self._span("aadhaar", 7, 21)]
        )
        assert len(merged) == 1
        assert (merged[0]["start"], merged[0]["end"]) == (0, 21)

    def test_a_chain_is_covered_end_to_end(self) -> None:
        """A overlaps B, B overlaps C, A and C are disjoint.

        Every character any member claimed must end up inside the merged span.
        Picking a single winner from the cluster would leave the outer halves of
        ``A`` and ``C`` exposed.
        """
        merged = merge_overlapping_detections(
            "x" * 30,
            [self._span("email", 0, 10), self._span("phone", 8, 20), self._span("ssn", 18, 26)],
        )
        assert len(merged) == 1
        assert (merged[0]["start"], merged[0]["end"]) == (0, 26)
        assert merged[0]["members"] == ["email", "phone", "ssn"]

    def test_equal_length_ties_are_stable_not_arbitrary(self) -> None:
        """No confidence score exists, so a tie must at least be deterministic."""
        first, second = self._span("email", 0, 10), self._span("phone", 0, 10)
        assert [d["type"] for d in merge_overlapping_detections("x" * 12, [first, second])] == [
            d["type"] for d in merge_overlapping_detections("x" * 12, [second, first])
        ]

    def test_adjacent_but_not_overlapping_spans_both_survive(self) -> None:
        """``end`` is exclusive, so ``(0, 5)`` and ``(5, 9)`` do not overlap."""
        merged = merge_overlapping_detections(
            "x" * 12, [self._span("email", 0, 5), self._span("phone", 5, 9)]
        )
        assert len(merged) == 2

    def test_output_is_sorted_by_position(self) -> None:
        merged = merge_overlapping_detections(
            "x" * 30,
            [self._span("ssn", 20, 25), self._span("email", 0, 5), self._span("phone", 10, 14)],
        )
        assert [d["start"] for d in merged] == [0, 10, 20]

    def test_empty_input_is_not_an_error(self) -> None:
        assert merge_overlapping_detections("", []) == []

    def test_a_merged_cluster_uses_the_strictest_members_strategy(self) -> None:
        """Merging must never reveal more than the stricter member would have alone.

        ``ssn`` defaults to FULL and ``aadhaar`` to PARTIAL. The merged span
        covers both, so it has to be masked FULL; masking it PARTIAL would show
        a tail of a region that SSN wanted redacted outright.
        """
        result, detections = mask_sensitive_data("123-45-6789 4111-1111-1111-1111")
        assert "123-45-" not in result, "SSN prefix left unmasked"
        assert "6789" not in result
        assert len(detections) == 1
        assert set(detections[0]["members"]) >= {"ssn", "aadhaar"}


class TestMaskingInvariantsUnderRandomInput:
    """Properties that must hold for any input, checked over generated composites.

    The corruption this class guards against is invisible to example-based
    tests: the secret still looks masked and the damage is a character or two of
    ordinary text beside it. Stating the invariants directly is what makes the
    whole class of offset bugs detectable rather than only the instances someone
    thought to write down.
    """

    _FRAGMENTS = (
        "+91-9876543210",
        "9876543210",
        "415-555-2671",
        "a@b.co",
        "john@example.com",
        "4111111111111111",
        "123-45-6789",
        "10.0.0.1",
        "AKIAIOSFODNN7EXAMPLE",
        "ABCDE1234F",
        "user@upi",
        "HDFC0001234",
        "2222405343248877",
    )
    _JOINS = ("", " ", "-", ".", ",", ":", "/", " and ")

    def _inputs(self, count: int = 600) -> list[str]:
        rng = random.Random(11)
        return [
            rng.choice(self._JOINS).join(rng.sample(self._FRAGMENTS, rng.randint(1, 4)))
            for _ in range(count)
        ]

    def test_returned_spans_never_overlap_each_other(self) -> None:
        for content in self._inputs():
            _result, detections = mask_sensitive_data(content)
            ordered = sorted(detections, key=lambda d: d["start"])
            for earlier, later in zip(ordered, ordered[1:], strict=False):
                assert earlier["end"] <= later["start"], content

    def test_text_outside_every_span_survives_in_order(self) -> None:
        """The invariant the old reverse-splice masker broke."""
        for content in self._inputs():
            result, detections = mask_sensitive_data(content)
            cursor, untouched = 0, []
            for detection in sorted(detections, key=lambda d: d["start"]):
                untouched.append(content[cursor : detection["start"]])
                cursor = detection["end"]
            untouched.append(content[cursor:])

            remaining = result
            for piece in untouched:
                index = remaining.find(piece)
                assert index >= 0, f"{piece!r} lost from {content!r} -> {result!r}"
                remaining = remaining[index + len(piece) :]

    def test_every_detected_span_ends_up_inside_a_masked_region(self) -> None:
        """No detection may be dropped: that would be an unmasked secret."""
        for content in self._inputs():
            _result, kept = mask_sensitive_data(content)
            for raw in detect_sensitive_data(content):
                assert any(d["start"] <= raw["start"] and raw["end"] <= d["end"] for d in kept), (
                    f"{raw['type']} at {raw['start']}-{raw['end']} unmasked in {content!r}"
                )


class TestSecretLabelsInStructuredOutput:
    """V0.10.36: secret labels in JSON tool results, and opaque Bearer tokens.

    Measured on c2a5df9d (0.10.35): every line in ``UNMASKED_BEFORE`` came back unmasked,
    and so did a dict returned through ``@Airlock``, whose strings are masked one by one,
    away from the key that labels them.
    """

    SECRET = "a8Fk29dLqP0zXv7RtY3mN5bC"
    BEARER = "a8Fk29dLqP0zXv7RtY3mN5bC9xQw"

    UNMASKED_BEFORE = [
        ('{"password": "hunter2hunter2"}', "hunter2hunter2", '"password": '),
        ('{"token": "a8Fk29dLqP0zXv7RtY3mN5bC"}', SECRET, '"token": '),
        ('{"api_key": "a8Fk29dLqP0zXv7RtY3mN5bC"}', SECRET, '"api_key": '),
        ('api_key = "a8Fk29dLqP0zXv7RtY3mN5bC"', SECRET, "api_key = "),
        ("access_key=a8Fk29dLqP0zXv7RtY3mN5bC", SECRET, "access_key="),
        ("Authorization: Bearer a8Fk29dLqP0zXv7RtY3mN5bC9xQw", BEARER, "Authorization: Bearer "),
    ]

    def test_each_line_unmasked_before_is_masked_with_its_label_kept(self) -> None:
        for line, secret, label in self.UNMASKED_BEFORE:
            content = sanitize_output(line).content
            assert secret not in content, line
            assert label in content, line
            assert "[REDACTED]" in content, line

    def test_a_dict_given_to_sanitize_output_loses_both_secrets(self) -> None:
        content = sanitize_output({"password": "hunter2hunter2", "api_key": self.SECRET}).content
        assert "hunter2hunter2" not in content
        assert self.SECRET not in content
        assert '"password": "[REDACTED]"' in content
        assert '"api_key": "[REDACTED]"' in content

    def test_a_bearer_header_in_a_dict_is_masked(self) -> None:
        content = sanitize_output({"headers": {"Authorization": f"Bearer {self.BEARER}"}}).content
        assert self.BEARER not in content
        assert '"Authorization": "Bearer [REDACTED]"' in content

    def test_a_dict_returned_through_airlock_is_masked_by_its_keys(self) -> None:
        @Airlock()
        def get_credentials() -> dict:
            return {
                "user": "svc",
                "password": "hunter2hunter2",
                "refreshToken": self.SECRET,
                "headers": {"Authorization": f"Bearer {self.BEARER}"},
            }

        result = get_credentials()
        assert result == {
            "user": "svc",
            "password": "[REDACTED]",
            "refreshToken": "[REDACTED]",
            "headers": {"Authorization": "Bearer [REDACTED]"},
        }

    def test_the_structured_walk_masks_a_labelled_value_once(self) -> None:
        from agent_airlock.sanitizer import sanitize_structured_report

        report = sanitize_structured_report(
            {"client_secret": "correct horse battery", "OPENAI_API_KEY": self.SECRET, "n": 1}
        )
        assert report.value == {
            "client_secret": "[REDACTED]",
            "OPENAI_API_KEY": "[REDACTED]",
            "n": 1,
        }
        assert report.masked_count == 2

    def test_mask_secrets_off_leaves_labelled_values(self) -> None:
        from agent_airlock.sanitizer import sanitize_structured_report

        value = {"password": "hunter2hunter2"}
        assert sanitize_structured_report(value, mask_secrets=False).value == value
        assert "hunter2hunter2" in sanitize_output(value, mask_secrets=False).content

    def test_a_key_rule_value_under_eight_characters_is_kept(self) -> None:
        from agent_airlock.sanitizer import sanitize_structured_report

        assert sanitize_structured_report({"token": "abc"}).value == {"token": "abc"}

    NEGATIVES = [
        '{"max_tokens": 40960000}',
        '{"token_count": 12345678}',
        "the token: is short",
        "Bearer of bad news",
        '{"token": "abc"}',
    ]

    def test_negatives_are_unchanged(self) -> None:
        for line in self.NEGATIVES:
            assert sanitize_output(line).content == line, line

    def test_the_two_lines_masked_before_are_masked_the_same_way(self) -> None:
        assert sanitize_output('token = "a8Fk29dLqP0zXv7RtY3mN5bC"').content == (
            'token = "[REDACTED]"'
        )
        assert sanitize_output("client_secret: a8Fk29dLqP0zXv7RtY3mN5bC").content == (
            "client_secret: [REDACTED]"
        )

    def test_a_jwt_after_bearer_keeps_the_jwt_partial_mask(self) -> None:
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.abc"
        result = sanitize_output(f"Authorization: Bearer {jwt}")
        assert result.content == "Authorization: Bearer eyJhbGciOi...[JWT]"
        assert [d["type"] for d in result.detections] == ["jwt"]

    def test_a_bearer_token_is_its_own_type(self) -> None:
        detections = detect_sensitive_data(
            f"Bearer {self.BEARER}", [SensitiveDataType.BEARER_TOKEN]
        )
        assert [(d["type"], d["value"]) for d in detections] == [("bearer_token", self.BEARER)]
        assert SensitiveDataType.BEARER_TOKEN.value == "bearer_token"

    def test_a_short_bearer_value_is_not_a_token(self) -> None:
        assert sanitize_output("Authorization: Bearer abc123").content == (
            "Authorization: Bearer abc123"
        )

    def test_a_label_at_the_end_of_a_longer_name_matches(self) -> None:
        for line in (
            f"OPENAI_API_KEY={self.SECRET}",
            f'{{"accessToken": "{self.SECRET}"}}',
            f'{{"clientSecret": "{self.SECRET}"}}',
            f"private-key: {self.SECRET}",
        ):
            assert self.SECRET not in sanitize_output(line).content, line

    def test_a_quoted_value_is_read_to_its_closing_quote(self) -> None:
        content = sanitize_output('{"password": "correct horse battery staple"}').content
        assert content == '{"password": "[REDACTED]"}'

    def test_a_comma_inside_a_password_does_not_hide_it(self) -> None:
        assert sanitize_output("password=P@ss,word2026").content == "password=[REDACTED]"

    def test_a_page_cursor_is_not_a_secret(self) -> None:
        from agent_airlock.sanitizer import sanitize_structured_report

        cursor = "CAESBggBEAEYAQabc"
        for line in (
            f'{{"nextPageToken": "{cursor}"}}',
            f'{{"next_page_token": "{cursor}"}}',
            f'{{"NextToken": "{cursor}"}}',
            f"continuation_token={cursor}",
        ):
            assert cursor in sanitize_output(line).content, line
        value = {"nextPageToken": cursor, "items": []}
        assert sanitize_structured_report(value).value == value

    def test_a_shaped_key_under_a_secret_label_keeps_its_label(self) -> None:
        content = sanitize_output('"api_key": "sk-1234567890abcdefghijklmnop"').content
        assert content == '"api_key": "[REDACTED]"'

    def test_masked_as_is_what_reached_the_output(self) -> None:
        text, detections = mask_sensitive_data(
            f"password=hunter2hunter2 Authorization: Bearer {self.BEARER}"
        )
        assert text == "password=[REDACTED] Authorization: Bearer [REDACTED]"
        for detection in detections:
            assert detection["masked_as"] in text


class TestAnUnquotedSecretRunsPastAQuote:
    """V0.10.37: an unquoted labelled value is masked to its end, not to its first quote.

    Measured on 099fcef0: ``api_key=sk-abc123"def456ghi789jkl`` came back as
    ``api_key=[REDACTED]"def456ghi789jkl`` (the tail after the quote leaked), and
    ``password=Sup3r"S3cretValue9`` came back unchanged: the unquoted branch stopped at the
    first quote, and ``Sup3r`` is under eight characters.
    """

    @staticmethod
    def _masked(text: str) -> str:
        return str(sanitize_output(text).content)

    def test_the_tail_after_a_quote_is_masked(self) -> None:
        assert self._masked('api_key=sk-abc123"def456ghi789jkl') == "api_key=[REDACTED]"

    def test_a_short_head_before_a_quote_no_longer_hides_the_value(self) -> None:
        assert self._masked('password=Sup3r"S3cretValue9') == "password=[REDACTED]"
        assert self._masked('password: Sup3r"S3cretValue9') == "password: [REDACTED]"

    def test_an_escaped_quote_in_json_text_is_masked_too(self) -> None:
        text = '{"env": "PASSWORD=\\"Sup3rS3cretValue9\\""}'
        assert self._masked(text) == '{"env": "PASSWORD=[REDACTED]"}'

    def test_quoted_values_keep_their_quotes(self) -> None:
        assert self._masked('password="Sup3rS3cretValue9"') == 'password="[REDACTED]"'
        assert self._masked("password='Sup3rS3cretValue9'") == "password='[REDACTED]'"
        assert self._masked('{"password": "Sup3r\\"S3cretValue9"}') == (
            '{"password": "[REDACTED]"}'
        )
        assert self._masked('password="Sup3rS3cretValue9') == 'password="[REDACTED]'

    def test_a_quote_that_closes_the_string_around_the_value_stays(self) -> None:
        """The value ends at a quote followed by whitespace, the end, or ``, ; ) ] } >``."""
        assert self._masked('{"command": "mysql --password=Sup3rS3cretValue9", "exit": 0}') == (
            '{"command": "mysql --password=[REDACTED]", "exit": 0}'
        )
        assert self._masked("{'cmd': 'mysql --password=Sup3rS3cretValue9', 'x': 0}") == (
            "{'cmd': 'mysql --password=[REDACTED]', 'x': 0}"
        )
        assert self._masked('echo "password=Sup3rS3cretValue9"') == 'echo "password=[REDACTED]"'

    def test_short_values_and_prose_are_left_alone(self) -> None:
        for text in (
            "password=short",
            "the password is changed daily",
            '{"password":"abc","user":"bob","note":"x"}',
        ):
            assert self._masked(text) == text, text


class TestSecretsInArgvCookiesAndNameValuePairs:
    """V0.10.37: three shapes a secret sat in unmasked.

    Measured on d763fb5c, each returned unchanged by ``sanitize_output``:

    - a secret flag's value as the next argv word: ``run --token Zq8x...``,
      ``args = ["--token", "Zq8x..."]``, ``["--password", "Sup3r..."]`` (only
      ``--token=...`` was masked);
    - cookie values: ``Cookie: session=...``, ``Cookie: theme=dark; sessionid=...``,
      ``Set-Cookie: sid=...; HttpOnly``;
    - a name/value pair, the env-list shape Kubernetes, Docker and many tool APIs return:
      ``{"name": "DEMO_SECRET", "value": "dummy-value-123"}``, alone or in an ``env`` list
      (``{"DEMO_SECRET": ...}`` and ``DEMO_SECRET=...`` were masked).
    """

    TOKEN = "Zq8xY2mK7pL4vR8tW3nB"

    @staticmethod
    def _masked(text: str) -> str:
        return str(sanitize_output(text).content)

    def test_a_secret_flag_s_next_word_is_masked_flag_and_quotes_kept(self) -> None:
        cases = {
            f'args = ["--token", "{self.TOKEN}"]': 'args = ["--token", "[REDACTED]"]',
            f"run --token {self.TOKEN}": "run --token [REDACTED]",
            '["--password", "Sup3rS3cretValue9"]': '["--password", "[REDACTED]"]',
            f"['--api-key', '{self.TOKEN}']": "['--api-key', '[REDACTED]']",
            f'login --client-secret "{self.TOKEN}"': 'login --client-secret "[REDACTED]"',
            f'{{"cmd": "run --token {self.TOKEN}", "x": 1}}': (
                '{"cmd": "run --token [REDACTED]", "x": 1}'
            ),
        }
        for text, expected in cases.items():
            assert self._masked(text) == expected, text

    def test_flags_that_name_no_secret_or_carry_none_are_left_alone(self) -> None:
        for text in (
            f'args = ["--token={self.TOKEN}"]',  # masked as before, by the PASSWORD pattern
            "--token short",
            "--verbose --dry-run",
            "the token expires daily",
            "--token --verbose",
            "pip install -p something-long",
            f"--page-token {self.TOKEN}",
            "--password-file /etc/secretpw",
        ):
            expected = 'args = ["--token=[REDACTED]"]' if "=" in text else text
            assert self._masked(text) == expected, text

    def test_every_cookie_value_is_masked_and_names_kept(self) -> None:
        """Every value, ``theme=dark`` included: a session cookie need not look like one."""
        cases = {
            f"Cookie: session={self.TOKEN}": "Cookie: session=[REDACTED]",
            f"Cookie: theme=dark; sessionid={self.TOKEN}": (
                "Cookie: theme=[REDACTED]; sessionid=[REDACTED]"
            ),
            f"curl -H 'Cookie: sid={self.TOKEN}' https://x": "curl -H 'Cookie: sid=[REDACTED]' https://x",
            f'{{"Cookie": "a=1; b={self.TOKEN}"}}': '{"Cookie": "a=[REDACTED]; b=[REDACTED]"}',
            f'Cookie: sid="{self.TOKEN}"': 'Cookie: sid="[REDACTED]"',
        }
        for text, expected in cases.items():
            assert self._masked(text) == expected, text
        assert self._masked("Cookie: chocolate chip") == "Cookie: chocolate chip"

    def test_set_cookie_masks_the_first_pair_and_keeps_its_attributes(self) -> None:
        assert self._masked(f"Set-Cookie: sid={self.TOKEN}; HttpOnly; Path=/") == (
            "Set-Cookie: sid=[REDACTED]; HttpOnly; Path=/"
        )

    def test_a_secret_name_value_pair_is_masked_wherever_it_sits(self) -> None:
        assert self._masked('{"name": "DEMO_SECRET", "value": "dummy-value-123"}') == (
            '{"name": "DEMO_SECRET", "value": "[REDACTED]"}'
        )
        env = (
            '{"env": [{"name": "DB_PASSWORD", "value": "hunter2-opaque-77"}, '
            '{"name": "LOG_LEVEL", "value": "info"}]}'
        )
        assert self._masked(env) == (
            '{"env": [{"name": "DB_PASSWORD", "value": "[REDACTED]"}, '
            '{"name": "LOG_LEVEL", "value": "info"}]}'
        )
        assert self._masked('{"Key": "API_KEY", "Value": "abc"}') == (
            '{"Key": "API_KEY", "Value": "[REDACTED]"}'
        )

    def test_kubectl_yaml_env_entries_are_masked_too(self) -> None:
        yaml = (
            "    env:\n    - name: DB_PASSWORD\n      value: hunter2-opaque-77\n"
            "    - name: LOG_LEVEL\n      value: info"
        )
        assert self._masked(yaml) == (
            "    env:\n    - name: DB_PASSWORD\n      value: [REDACTED]\n"
            "    - name: LOG_LEVEL\n      value: info"
        )

    def test_a_non_secret_name_keeps_its_value(self) -> None:
        text = '{"name": "LOG_LEVEL", "value": "info"}'
        assert self._masked(text) == text

    def test_secret_key_is_a_label_now(self) -> None:
        """``AWS_SECRET_KEY=...`` ended in ``_KEY``, no label, until 0.10.37."""
        assert self._masked("AWS_SECRET_KEY=aZ9kQ2mX7pL4vR8t") == "AWS_SECRET_KEY=[REDACTED]"

    def test_the_new_detections_use_the_existing_types(self) -> None:
        found = detect_sensitive_data(f"run --token {self.TOKEN}\nCookie: sid={self.TOKEN}")
        assert {d["type"] for d in found} == {"password", "bearer_token"}
