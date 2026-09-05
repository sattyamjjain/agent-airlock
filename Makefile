.PHONY: help test coverage lint format bench benchmark test-badge egress-bench check-links check-docs check-changelog check-changelog-release check-benchmark-freshness check-benchmark-freshness-release check-registry-parity check-registry-parity-distance verify-corpus check-cve-catalog

help:
	@echo "Targets:"
	@echo "  test                    Run the pytest suite (no coverage)"
	@echo "  coverage                Run pytest with coverage"
	@echo "  lint                    Run ruff + mypy"
	@echo "  format                  Apply ruff format"
	@echo "  bench                   Run pytest-benchmark suite"
	@echo "  benchmark               Regenerate BENCHMARK.md (guard-suite block-rate corpus)"
	@echo "  test-badge              Regenerate the TEST-BADGE block in README.md"
	@echo "  egress-bench            Run the CVE egress-bench walker against tests/cves/fixtures/"
	@echo "  verify-corpus           Verify wild_payload_corpus MANIFEST.sha256"
	@echo "  check-links             Dead relative-link gate (README + docs/)"
	@echo "  check-cve-catalog       docs/cves/index.md matches the tests/cves/ suite"
	@echo "  check-changelog         Post-release drift gate (fails if [Unreleased] has entries after a release)"
	@echo "  check-changelog-release Pre-tag gate (fails if [Unreleased] is empty)"
	@echo "  check-benchmark-freshness         Structural gate (every benchmark row carries a date)"
	@echo "  check-benchmark-freshness-release Pre-tag gate (fails on a benchmark claim >30d old)"

verify-corpus:
	@python3 scripts/verify_corpus_manifest.py

test:
	python3 -m pytest tests/ -v --no-cov

coverage:
	python3 -m pytest tests/

lint:
	ruff check src/ tests/
	ruff format --check src/ tests/
	mypy src/

format:
	ruff format src/ tests/
	ruff check --fix src/ tests/

bench:
	python3 -m pytest tests/benchmarks/ --benchmark-only --no-cov

benchmark:
	python3 scripts/generate_benchmark.py

test-badge:
	python3 scripts/update_test_badge.py

egress-bench:
	python3 scripts/egress_bench.py --format tap

check-links:
	python3 scripts/check_links.py

# The catalog is generated from tests/cves/ docstrings. docs/cves/index.md told
# readers "CI runs `gen_cve_catalog.py --check` on every PR" from the day it was
# written, and no workflow ever did - the script was referenced by neither a
# workflow nor a Makefile target. test_cve_catalog_gate.py gates the committed
# file's *row count*, so a drifted title, CVSS or advisory URL would have shipped
# unnoticed. This is the gate the docs already promised.
check-cve-catalog:
	python3 scripts/gen_cve_catalog.py --check

# The CI 'docs' job runs `mkdocs build --strict`, where a link that leaves the docs/
# tree is a warning and a warning is a failure. check_links.py does NOT catch it: it
# resolves relative links from the repo root, so ../../PRIOR_ART.md passes there and
# fails here. Needs the [docs] extra.
check-docs:
	mkdocs build --strict

check-changelog:
	python3 scripts/check_changelog.py

check-changelog-release:
	python3 scripts/check_changelog.py --release

check-benchmark-freshness:
	python3 scripts/check_benchmark_freshness.py

check-benchmark-freshness-release:
	python3 scripts/check_benchmark_freshness.py --release

check-registry-parity:
	python3 scripts/check_registry_parity.py

check-registry-parity-distance:
	python3 scripts/check_registry_parity.py --distance-only
