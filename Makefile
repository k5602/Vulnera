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

# Release
release-check: ## Check if ready for release
	cargo check --release
	cargo test --release
	cargo clippy --release -- -D warnings
	cargo audit

# Database/Migration related (for future use)
migrate: ## Run database migrations (placeholder)
	@echo "Database migrations not implemented yet"

# Environment setup
setup: install-deps ## Setup development environment
	@echo "Development environment setup complete"
	@echo "Run 'make help' to see available commands"