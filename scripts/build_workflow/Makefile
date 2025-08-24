# Vulnera Rust Development Makefile

.PHONY: help build test check lint format clean run dev install-deps update-deps audit security-audit docker-build docker-run

# Default target
help: ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Development
build: ## Build the project
	cargo build

build-release: ## Build the project in release mode
	cargo build --release

test: ## Run tests
	cargo test

test-verbose: ## Run tests with verbose output
	cargo test -- --nocapture

check: ## Run cargo check
	cargo check

lint: ## Run clippy linter
	cargo clippy --all-targets --all-features -- -D warnings

format: ## Format code with rustfmt
	cargo fmt

format-check: ## Check if code is formatted
	cargo fmt -- --check

clean: ## Clean build artifacts
	cargo clean

# Running
run: ## Run the application
	cargo run

dev: ## Run in development mode with file watching
	cargo watch -x run

# Dependencies
install-deps: ## Install development dependencies
	cargo install cargo-watch cargo-audit cargo-outdated

update-deps: ## Update dependencies
	cargo update

audit: ## Run security audit
	cargo audit

security-audit: ## Run comprehensive security audit
	cargo audit --deny warnings

# Quality checks
ci-check: format-check lint test ## Run all CI checks
	@echo "All CI checks passed!"

pre-commit: format lint test ## Run pre-commit checks
	@echo "Pre-commit checks passed!"

# Docker
docker-build: ## Build Docker image
	docker build -t vulnera-rust .

docker-run: ## Run Docker container
	docker run -p 3000:3000 vulnera-rust

# Documentation
docs: ## Generate documentation
	cargo doc --no-deps --open

docs-private: ## Generate documentation including private items
	cargo doc --no-deps --document-private-items --open

# Benchmarks
bench: ## Run benchmarks
	cargo bench

# Coverage
coverage: ## Generate test coverage report
	cargo tarpaulin --out Html --output-dir coverage

# Comprehensive testing
test-comprehensive: ## Run comprehensive test suite with coverage
	../../scripts/test-comprehensive.sh --coverage

test-all: ## Run all tests including edge cases and integration
	../../scripts/test-comprehensive.sh

test-unit: ## Run only unit tests
	cargo test --lib --bins

test-integration: ## Run only integration tests
	cargo test --test integration_tests

test-parsers: ## Run parser edge case tests
	cargo test parser_edge_cases -- --nocapture

test-api-clients: ## Run API client tests with mocking
	cargo test api_client_tests -- --nocapture

test-repositories: ## Run repository and cache tests
	cargo test repository_cache_tests -- --nocapture

test-controllers: ## Run controller unit tests
	cargo test controller_tests -- --nocapture

test-with-coverage: ## Run tests with coverage analysis (95% threshold)
	COVERAGE_THRESHOLD=95 ../../scripts/test-comprehensive.sh --coverage

test-fast: ## Run tests without coverage for quick feedback
	../../scripts/test-comprehensive.sh --no-coverage

test-verbose: ## Run comprehensive tests with verbose output
	../../scripts/test-comprehensive.sh --verbose

test-benchmarks: ## Run performance benchmarks
	../../scripts/test-comprehensive.sh --benchmarks

test-property: ## Run property-based tests
	../../scripts/test-comprehensive.sh --property-tests

test-security: ## Run tests with security audit
	../../scripts/test-comprehensive.sh --audit

test-ci: ## Run CI-optimized test suite
	JUNIT_REPORT=1 COVERAGE_THRESHOLD=95 ../../scripts/test-comprehensive.sh --coverage --junit

test-deploy-ready: ## Check if code is ready for deployment (all tests + 95% coverage)
	ENABLE_COVERAGE=1 ENABLE_AUDIT=1 COVERAGE_THRESHOLD=95 ../../scripts/test-comprehensive.sh

# Release
release-check: test-deploy-ready ## Check if ready for release
	cargo check --release
	cargo test --release
	cargo clippy --release -- -D warnings
	cargo audit

# Database/Migration related (for future use)
migrate: ## Run database migrations (placeholder)
	@echo "Database migrations not implemented yet"

# Environment setup
setup: install-deps ## Setup development environment
	@echo "Installing additional test dependencies..."
	cargo install cargo-tarpaulin cargo-audit || true
	@echo "Development environment setup complete"
	@echo "Run 'make help' to see available commands"
	@echo ""
	@echo "Quick test commands:"
	@echo "  make test-fast          - Quick test run without coverage"
	@echo "  make test-comprehensive - Full test suite with coverage"
	@echo "  make test-deploy-ready  - Production readiness check"

# Quality gates
quality-gate: test-deploy-ready ## Run all quality checks for production
	@echo "✅ All quality gates passed! Code is ready for deployment."

quick-check: test-fast lint format-check ## Quick development checks
	@echo "✅ Quick checks passed!"
