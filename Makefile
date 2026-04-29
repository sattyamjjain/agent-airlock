.PHONY: help test coverage lint format bench test-badge egress-bench check-changelog check-changelog-release verify-corpus

help:
	@echo "Targets:"
	@echo "  test                    Run the pytest suite (no coverage)"
	@echo "  coverage                Run pytest with coverage"
	@echo "  lint                    Run ruff + mypy"
	@echo "  format                  Apply ruff format"
	@echo "  bench                   Run pytest-benchmark suite"
	@echo "  test-badge              Regenerate the TEST-BADGE block in README.md"
	@echo "  egress-bench            Run the CVE egress-bench walker against tests/cves/fixtures/"
	@echo "  verify-corpus           Verify wild_payload_corpus MANIFEST.sha256"
	@echo "  check-changelog         Post-release drift gate (fails if [Unreleased] has entries after a release)"
	@echo "  check-changelog-release Pre-tag gate (fails if [Unreleased] is empty)"

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

test-badge:
	python3 scripts/update_test_badge.py

egress-bench:
	python3 scripts/egress_bench.py --format tap

check-changelog:
	python3 scripts/check_changelog.py

check-changelog-release:
	python3 scripts/check_changelog.py --release
