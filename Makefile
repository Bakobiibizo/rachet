.PHONY: fixtures fmt fmt-check lint test test-release check

fixtures:
	python3 tools/generate_hrep_fixtures.py

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

lint:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

test: fixtures
	cargo test --workspace

test-release: fixtures
	cargo test --workspace --release

check: fixtures fmt-check lint test test-release
