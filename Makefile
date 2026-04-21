.PHONY: help test coverage lint format bench test-badge egress-bench

help:
	@echo "Targets:"
	@echo "  test         Run the pytest suite (no coverage)"
	@echo "  coverage     Run pytest with coverage"
	@echo "  lint         Run ruff + mypy"
	@echo "  format       Apply ruff format"
	@echo "  bench        Run pytest-benchmark suite"
	@echo "  test-badge   Regenerate the TEST-BADGE block in README.md"
	@echo "  egress-bench Run the CVE egress-bench walker against tests/cves/fixtures/"

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
