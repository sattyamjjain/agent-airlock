"""0.10.29: PII written right next to non-ASCII text is masked.

Raised in langchain-ai/langchain#40002 ("Same bug: 48 detector- x script combinations." and
"All three leave @ex.org in the clear."). The ASCII-shaped detectors used Python's Unicode
``\\b``, which sees no word boundary between a Devanagari, Arabic, Hebrew, Thai or Bengali
letter and a Latin one, so on 0.10.28 ``ईमेलbob@example.com``, ``bob@example.comपर`` and a
valid PAN or Aadhaar written right after Devanagari were left unmasked while the
space-separated forms were masked. ``cc: bob-@list.dan@ex.org`` became
``b***@list.dan@ex.org``, and the EMAIL TLD class was ``[A-Z|a-z]``, so ``x@y.c|m`` was an
email. The detectors now compile with ``re.ASCII`` (``\\s`` kept Unicode-wide where a
separator is allowed), the TLD class is ``[A-Za-z]``, and a chained ``local@domain@domain``
run is masked whole.
"""

from __future__ import annotations

import pytest

from agent_airlock.sanitizer import _verhoeff_check, sanitize_output


def _aadhaar() -> str:
    """A 12-digit number starting 2-9 that passes UIDAI's Verhoeff check."""
    base = "23456789012"
    for digit in "0123456789":
        if _verhoeff_check(base + digit):
            return f"{base[:4]} {base[4:8]} {base[8:]}{digit}"
    raise AssertionError("no Verhoeff check digit")  # pragma: no cover


# Assembled, so no secret scanner files this module.
KEY = "sk-proj-" + "FAKEFAKEFAKEFAKEFAKEFAKE1234"

VALUES = {
    "email": "bob@example.com",
    "phone": "555-123-4567",
    "india_mobile": "+919876543210",
    "pan": "ABCPE1234F",  # P (person) is a valid fourth character
    "aadhaar": _aadhaar(),
    "upi": "bob.smith@okaxis",
    "credit_card": "4111111111111111",
    "api_key": KEY,
}

#: (a word ending in a letter, a word ending in a combining mark, a word to follow).
SCRIPTS = {
    "devanagari": ("ईमेल", "मेरा", "पर"),  # ends in ल / in the matra ा
    "arabic": ("بريد", "بريدُ", "في"),  # ends in د / in a damma
    "hebrew": ("דואר", "דוארָ", "של"),  # ends in ר / in a qamats
    "thai": ("อีเมล", "ที่", "ของ"),  # ends in ล / in the tone mark ่
    "bengali": ("ইমেল", "মেইলে", "এর"),  # ends in ল / in the vowel sign ে
}

POSITIONS = ("after_letter", "after_mark", "before_word")


def _text(value: str, script: str, position: str) -> str:
    letter_word, mark_word, following = SCRIPTS[script]
    if position == "after_letter":
        return f"{letter_word}{value}"
    if position == "after_mark":
        return f"{mark_word}{value}"
    return f"{value}{following}"


def _masked(text: str) -> str:
    return sanitize_output(text, pii_locales=["in"]).content


class TestDetectorsByScript:
    """Every detector, next to every script, in every position, is masked."""

    @pytest.mark.parametrize("position", POSITIONS)
    @pytest.mark.parametrize("script", list(SCRIPTS))
    @pytest.mark.parametrize("detector", list(VALUES))
    def test_value_is_masked(self, detector: str, script: str, position: str) -> None:
        value = VALUES[detector]
        assert value not in _masked(_text(value, script, position))

    @pytest.mark.parametrize("detector", list(VALUES))
    def test_space_separated_control(self, detector: str) -> None:
        """Control: the form that was always masked still is."""
        value = VALUES[detector]
        assert value not in _masked(f"ईमेल {value} पर")


class TestEmailShapes:
    def test_a_pipe_in_the_tld_is_not_an_email(self) -> None:
        assert sanitize_output("x@y.c|m").detection_count == 0

    def test_a_chained_address_leaves_no_trailing_domain(self) -> None:
        out = sanitize_output("cc: bob-@list.dan@ex.org").content
        assert "ex.org" not in out
        assert "list.dan" not in out
        assert out.startswith("cc: ")

    def test_email_in_url_userinfo_keeps_the_url_shape(self) -> None:
        """Pins the overlap fix of 6f15923 (BerriAI/litellm#42130)."""
        out = sanitize_output("see https://bob@example.com/path").content
        assert "bob@example.com" not in out
        assert out.startswith("see https://")
        assert out.endswith("@example.com/path")

    def test_a_plain_address_is_masked_as_before(self) -> None:
        """Control: the ASCII output is unchanged."""
        assert sanitize_output("mail alice.smith@example.com now").content == (
            "mail a***@example.com now"
        )


class TestUnicodeSeparatorsStillCount:
    """``re.ASCII`` narrows ``\\s``; the separators a number may use stay Unicode-wide."""

    @pytest.mark.parametrize("separator", [" ", " ", "　"], ids=["nbsp", "nnbsp", "ideographic"])
    def test_a_phone_split_by_a_unicode_space_is_masked(self, separator: str) -> None:
        value = f"555{separator}123{separator}4567"
        assert value not in sanitize_output(f"call {value}").content

    def test_an_aadhaar_split_by_nbsp_is_masked(self) -> None:
        value = _aadhaar().replace(" ", " ")
        assert value not in _masked(f"aadhaar {value}")
