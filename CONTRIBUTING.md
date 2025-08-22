# Contributing to Vulnera

Thanks for your interest in contributing!

## Getting started

- Fork the repo and create a feature branch.
- Install Rust (stable) and run:
  - `make -C scripts/build_workflow install-deps`
  - `make -C scripts/build_workflow ci-check`

## Development workflow

- Format and lint before committing: `make -C scripts/build_workflow ci-check`.
- Add tests for new features and bug fixes.
- Keep changes focused and small; open draft PRs early.

## Testing

- Run unit + integration tests: `cargo test`.
- Run parser-only tests: `cargo test parsers`.
- Mock HTTP: use `mockito`.

## Commit & PR guidelines

- Conventional commits are encouraged.
- Link related issues in PR description.
- Update docs/OpenAPI when API shapes change.

## Code of Conduct

This project adheres to the Code of Conduct in CODE_OF_CONDUCT.md.
