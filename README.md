# Vulnera Rust – High-Performance Vulnerability Analysis API

Vulnera is a fast, scalable, multi-ecosystem vulnerability analysis toolkit and testing platform built in Rust. While it excels at analyzing dependency manifests, Vulnera is intended as a comprehensive vulnerability analysis and testing toolkit—supporting not only dependency scanning, but also future features like codebase auditing, security testing, and integration with CI/CD workflows. It aggregates results from OSV, NVD, and GHSA, and exposes a robust HTTP API with OpenAPI docs. Designed for cloud-native workflows, Vulnera leverages async Rust, domain-driven design, and smart caching for reliability and speed.

---

## 🚀 Key Features

- **Multi-Ecosystem Support:** npm, PyPI, Maven/Gradle, Cargo, Go, Packagist, and more
- **Aggregated Vulnerability Data:** Combines OSV, NVD, and GitHub Security Advisories
- **Async & Concurrent:** Built with Tokio for high throughput and bounded concurrency
- **Smart Caching:** Filesystem-based, TTL-configurable cache for reduced API calls
- **Domain-Driven Design:** Clean separation of domain, application, infrastructure, and presentation layers
- **OpenAPI Documentation:** Auto-generated Swagger UI for easy API exploration
- **Secure by Default:** Input validation, rate limiting, and secure API handling
- **Container Ready:** Docker and Kubernetes support for production deployments
- **Developer Friendly:** Comprehensive tooling, linting, and CI/CD integration

---

## ⚡ Quick Start

### Installation

#### From Source

```bash
git clone https://github.com/vulnera/vulnera.git
cd vulnera
curl --proto '=https' --tlsv
```

1.2 -sSf https://sh.rustup.rs | sh
```bash

source ~/.cargo/env
sudo apt-get install pkg-config libssl-dev # Ubuntu/Debian
cargo build --release
cargo run

````

#### Using Docker

```bash
docker build -t vulnera-rust .
docker run -p 3000:3000 vulnera-rust
````

---

## 🛠️ Usage

- **API Docs:** [http://localhost:3000/docs](http://localhost:3000/docs)
- **Health Check:** [http://localhost:3000/health](http://localhost:3000/health)

### Example: Analyze a Dependency File

```bash
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"file_content": "django==3.2.0\nrequests>=2.25.0", "ecosystem": "PyPI", "filename": "requirements.txt"}'
```

### Example: Analyze a GitHub Repository

```bash
curl -X POST http://localhost:3000/api/v1/analyze/repository \
  -H "Content-Type: application/json" \
  -d '{"repository_url": "https://github.com/rust-lang/cargo", "ref": "main"}'
```

---

## 📦 Supported Ecosystems & File Formats

- **Python:** `requirements.txt`, `Pipfile`, `pyproject.toml`
- **Node.js:** `package.json`, `package-lock.json`, `yarn.lock`
- **Java:** `pom.xml`, `build.gradle`
- **Rust:** `Cargo.toml`, `Cargo.lock`
- **Go:** `go.mod`, `go.sum`
- **PHP:** `composer.json`, `composer.lock`

---

## ⚙️ Configuration

- Configurable via TOML files in `config/` and environment variables (prefix `VULNERA__`)
- Profiles: `development`, `staging`, `production` (set via `ENV`)
- Example environment overrides:
  ```bash
  VULNERA__SERVER__PORT=8080
  VULNERA__CACHE__TTL_HOURS=24
  VULNERA__APIS__NVD__API_KEY=your_nvd_api_key
  VULNERA__APIS__GHSA__TOKEN=your_github_token
  ```

---

## 🏗️ Architecture & Design

Vulnera is built with **Domain-Driven Design (DDD)** and a layered architecture:

- **Domain Layer:** Pure business logic, entities, value objects
- **Application Layer:** Use cases, orchestration, error mapping
- **Infrastructure Layer:** API clients, parsers, caching, repositories
- **Presentation Layer:** HTTP API, DTOs, OpenAPI, middleware

**Core Flow:**
Dependency file → Parser → AggregatingVulnerabilityRepository (parallel API calls, merge results) → AnalysisReport → Optional reporting/caching.

**Caching:**
Filesystem-based, SHA256 keys, TTL configurable. Always use provided cache key helpers.

**Error Handling:**
Early mapping to domain/application errors, graceful degradation, and clear API responses.

---

## 🧑‍💻 Development & Contribution

- **Dev Setup:**
  ```bash
  make -C scripts/build_workflow install-deps
  pre-commit install
  make dev
  ```
- **Testing:**
  `make test` (unit/integration), `make ci-check` (lint, format, audit)
- **Contribution:**
  Fork, branch, code, test, document, PR. Follow DDD, Rust best practices, and update OpenAPI docs for API changes.

---

## 🚢 Deployment

- **Docker:**

  ```bash
  docker build -t vulnera-rust .
  docker run -p 3000:3000 vulnera-rust
  ```
- **Kubernetes:**
  See example deployment YAML in this repo.
- **Production:**
  Harden config, disable docs, restrict CORS, provide API keys.

---

## 🛡️ Security Considerations

- HTTPS for all external API calls
- Input validation and sanitization
- Rate limiting and abuse protection
- Runs as non-root in containers
- Secure API key management

---

## 🐞 Troubleshooting

- **Build errors:** Update Rust, install system dependencies
- **API rate limits:** Provide API keys for OSV/NVD/GHSA
- **Cache issues:** Clear `.vulnera_cache` or adjust TTL
- **Debugging:**
  ```bash
  VULNERA__LOGGING__LEVEL=debug cargo run
  ```

---

## 📜 Changelog & Roadmap

- **v3.0.0:** Rust rewrite, multi-ecosystem, async, aggregation, caching, OpenAPI, Docker/K8s
- **Planned:** ML-powered risk scoring, webhook integrations, Redis cache, advanced reporting, plugin system, **VSCode extension** for in-editor vulnerability analysis

---

## 🦀 Why Rust? (vs Python)

Vulnera was rewritten from Python to Rust for several reasons:

- **Performance:** Rust is compiled and memory-safe, enabling much faster analysis and lower latency than Python’s interpreter.
- **Concurrency:** Tokio async runtime allows true parallelism and efficient IO, while Python’s async is limited by the GIL.
- **Reliability:** Rust’s strict type system and error handling prevent many runtime bugs common in Python.
- **Security:** Rust eliminates entire classes of memory safety vulnerabilities (buffer overflows, use-after-free) that can affect Python extensions.
- **Scalability:** Rust’s async and concurrency model scales to thousands of requests with minimal resources.
- **Ecosystem:** Rust’s package ecosystem (crates.io) and tooling (cargo, clippy, rustfmt) support modern development practices.

**Legacy Python:**
The original Vulnera was written in Python for rapid prototyping, but hit limits in performance, reliability, and maintainability. The Rust rewrite delivers a robust, production-grade backend for cloud-native deployments.

---

## 👥 Team

- Khaled Mahmoud — Project Manager, Main Developer, Rust Backend Developer
- Amr Medhat — Cloud Engineer
- Youssef Mohammed — Database Engineer
- Gasser Mohammed — Frontend Developer
- Abd El-Rahman Mossad — Frontend Developer

---

## 📚 AWS Cloud Architecture

![Architecture Diagram](./AWS2.png)

**Summary:**
Vulnera is designed for cloud-native, serverless deployment on AWS.

- **Edge:** CloudFront for CDN, WAF for security
- **Frontend:** Amplify for SPA hosting
- **API:** API Gateway for routing, throttling, and security
- **Compute:** Lambda (containerized via ECR) for backend
- **Observability:** CloudWatch for logs and metrics
- **CI/CD:** GitHub Actions → Amplify/ECR/Lambda

This architecture enables scalable, resilient, and secure deployments with minimal operational overhead.

---

## 📝 License

MIT License – see LICENSE file.

---

## 🌐 Vulnera Frontend

Looking for the web UI?
Find the official Vulnera Frontend at: [https://github.com/k5602/Vulnera-Frontend](https://github.com/k5602/Vulnera-Frontend)
