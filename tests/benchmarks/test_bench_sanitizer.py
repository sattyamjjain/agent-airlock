"""Benchmark the output sanitizer (PII + secret detection + masking).

Sanitization runs on EVERY tool return value in production, so its latency
is load-bearing. We benchmark two representative payloads:

- `test_sanitize_mixed_pii` — a short response with one email + one phone,
  representative of a typical CRM-lookup tool return.
- `test_sanitize_long_payload_no_pii` — a 4 KB clean payload, representative
  of a documentation-fetch tool. Measures the cost of the detection scan
  itself (no matches = no masking) on realistic-length text.
"""

from __future__ import annotations

from agent_airlock.sanitizer import sanitize_output

MIXED_PII = (
    "Customer record: "
    "email=alice@example.com, phone=555-123-4567. "
    "Notes: followed up on the support ticket; escalating to L2."
)

LONG_CLEAN = ("The quick brown fox jumps over the lazy dog. " * 90)[:4096]


def test_sanitize_mixed_pii(benchmark):
    result = benchmark(sanitize_output, MIXED_PII)
    assert "alice@example.com" not in result.content
    assert len(result.detections) >= 2


def test_sanitize_long_payload_no_pii(benchmark):
    result = benchmark(sanitize_output, LONG_CLEAN)
    # No PII to find in a clean lorem-ipsum; still exercises every detector.
    assert result.content.startswith("The quick brown fox")
