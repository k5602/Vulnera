# Research Notes: Fetter vs. Vulfy — What We Can Adapt in Vulnera

Status: Draft
Audience: Vulnera maintainers and contributors
Purpose: Compare two production-grade OSS scanners (Fetter and Vulfy) and extract concrete patterns to adopt in Vulnera’s Rust backend, aligned with our DDD + async architecture.

---

## TL;DR (Executive Summary)

- Both Fetter and Vulfy validate the direction we’re heading: async Rust, multi-ecosystem parsers, and OSV-first data.
- Key adoptions for Vulnera:
  - Use the `osv` crate for schema and client, standardizing parsing and minimizing drift.
  - Use `nvd_cve` for local/offline NVD queries to avoid rate limiting and improve reliability.
  - Introduce Pest grammars for tricky parsers (e.g., yarn.lock v1/v2, Gradle KTS), preserving existing serde-based JSON/TOML parsers.
  - Strengthen caching: per-vuln ID cache and per-package TTL cache (we already have CacheService—reuse it consistently).
  - Keep Tokio + JoinSet for bounded concurrency; centralize retry/backoff in resilience.
- Keep Vulnera’s DDD layering, trait boundaries, repository aggregation and deduplication. We only replace internals with crate-powered adapters and Pest grammars where it improves correctness and maintainability.

---

## Overview of the Projects

### Fetter (fetter-io/fetter-rs)

- Scope: Python-centric environment scanning, validation, and auditing (OSV-based) with excellent CLI UX.
- Notable traits:
  - Uses Pest for complex config/lockfile parsing and reliable text grammars.
  - OSV-focused vulnerability retrieval; introduces in-process caching to reduce repeat queries.
  - Rayon for parallelism in CLI workflows; local file system caching for OSV responses.
  - Clean modularization around scanning, lockfiles, OSV querying, table output, and utility modules.
- Takeaways for Vulnera:
  - Pest is a great fit for complex non-JSON formats (e.g., yarn.lock, Gradle KTS); serde remains fine for JSON/TOML.
  - Caching OSV responses by vulnerability ID improves performance, reliability, and reduces rate exposure.
  - A simple priority scheme for severity (CVSS v4 > v3 > other) and for “prime” references is effective.
  - CLI-centric concurrency (Rayon) can be mirrored with Tokio’s JoinSet on the server.

References:
- https://github.com/fetter-io/fetter-rs
- README (high-level CLI features and OSV audit)
- Notable modules: osv_vulns.rs, lock_file.rs, version_spec.rs, scan_fs.rs

### Vulfy (MindPatch/Vulfy)

- Scope: Broad multi-ecosystem dependency scanner with OSV.dev integration, outputs in multiple formats (table/JSON/CSV/SARIF), and automation/monitoring.
- Notable traits:
  - Async-first design with Tokio; structured error handling; strong multi-ecosystem coverage.
  - Uses OSV as primary source; concurrency and retry tuned for CI usage.
  - Practical parsers per ecosystem; leverages existing crates (e.g., quick-xml for pom.xml), semver for version matching.
  - Automation features: scheduler, notifications, repository monitoring.
- Takeaways for Vulnera:
  - Async-first scanning matches our Axum backend; we should continue to rely on Tokio.
  - Use existing ecosystem-native parsers/crates when possible (e.g., quick-xml for Maven) to avoid bespoke regex.
  - Keep OSV as the primary source of truth and enrich with NVD/GHSA where available.
  - Offer multiple outputs downstream (we expose a web API today; if we add export formats, keep DTOs stable).

References:
- https://github.com/MindPatch/Vulfy
- README (architecture overview, feature set)
- Cargo.toml (ecosystem crates and parsing tools)

---

## Specific Areas of Comparison

### 1) Vulnerability Sources

- Fetter: OSV-only with a simple caching layer. Leans into OSV’s comprehensive coverage.
- Vulfy: OSV-first, cleanly integrated into an async pipeline.
- Vulnera today: OSV + NVD + GHSA aggregation with bounded concurrency and deduplication.

What to adopt:
- Replace manual OSV client with `osv` crate to align with upstream schema and reduce maintenance.
- Replace remote NVD API with `nvd_cve` local dataset for reliability and performance; keep OSV as primary.
- Keep GHSA as optional enrichment (token-driven).

### 2) Parsing Strategy

- Fetter: Pest grammars where formats are complex and not machine-friendly JSON.
- Vulfy: Uses appropriate crates (e.g., quick-xml) and robust parsing strategies per ecosystem.
- Vulnera today: Mix of serde/regex for JSON, lockfiles, and text (yarn.lock simple parser, Gradle regex).

What to adopt:
- Pest for grammars with tricky, line-oriented formats:
  - yarn.lock (v1/v2+)
  - Gradle KTS (extracting “group:name:version” and map syntax robustly)
  - requirements.txt advanced features (markers, nested includes) in phases
- Keep serde-based JSON/TOML (Cargo.lock, package-lock.json) and XML parsers (prefer quick-xml) where applicable.

### 3) Concurrency and Resilience

- Fetter: Rayon-based parallelism for CLI workflows; simple caching reduces repeated HTTP calls.
- Vulfy: Tokio, async-first; robust pipeline for scanning and fetching OSV.
- Vulnera today: Tokio + JoinSet, bounded concurrency (max 3), resilience module stubs.

What to adopt:
- Keep Tokio + JoinSet bounded concurrency for API calls; keep the 3-source limit.
- Centralize retry/backoff policy in resilience (backoff on 429/5xx); reduce per-client duplication.
- Extend structured logging and tracing around cache hit/miss and aggregation summaries (we already do some; expand coverage).

### 4) Caching

- Fetter: Caches OSV per vulnerability ID on disk.
- Vulfy: Not strongly cache-centric; relies on OSV responsiveness.
- Vulnera today: Filesystem cache with SHA256 keys, TTLs per package and 24h for per-ID details.

What to adopt:
- Keep and expand our CacheService usage:
  - Per-package query cache (TTL).
  - Per-vulnerability details (24h fixed) using stable key helpers.
- Consider pre-warming caches for popular packages (optional, later).

### 5) Severity and References

- Fetter: selects “prime” severity (prefers CVSS v4 → v3) and a primary reference (ADVISORY if present).
- Vulfy: severity surfaced from OSV; filters/high-only modes for CLI usage.
- Vulnera today: numeric mapping to domain Severity (>=9.0 critical, >=7.0 high, >=4.0 medium, >0 low, else medium) and merges references across sources.

What to adopt:
- Keep current severity mapping; for OSV choose numeric score from CVSS v4/v3 where possible.
- Keep deduplication: union references, sources; pick highest severity and earliest published_at.
- Preserve IDs and stable dedupe keying.

### 6) Output and Interfaces

- Fetter: CLI output, tables/CSV/JSON; library exports for integrations.
- Vulfy: CLI with multiple formats including SARIF; automation workflows.
- Vulnera today: Axum HTTP API; JSON DTOs with OpenAPI.

What to adopt:
- Keep Vulnera as an API-first service. If export formats are added later (CSV/SARIF), do so as new DTOs/endpoints while maintaining backward compatibility.
- Retain OpenAPI and explicit DTOs in presentation layer.

---

## Concrete Adaptations for Vulnera

1) OSV Client via `osv` crate
- Replace manual reqwest models in `infrastructure/api_clients/osv.rs` with `osv` client usage.
- Map crate types → our `RawVulnerability` (unchanged trait boundary).
- Prefer CVSS v4 > v3 scores; include all references (ADVISORY commonly “prime”).

2) NVD via `nvd_cve` (local)
- Replace remote NVD HTTP client with local dataset queries in `infrastructure/api_clients/nvd.rs`.
- Config options for dataset location and optional update cadence. If dataset not present, degrade gracefully (empty results + log warning).
- For search, use keyword parity on package name; consider future CPE enrichment per ecosystem.

3) Pest parsers for tricky formats
- Add grammars under `src/infrastructure/parsers/grammars`.
- Start with:
  - yarn.lock v1/v2+: robust handling of quotes, multi-line blocks, and multiple selectors.
  - Gradle (including KTS): capture “group:name:version” and map-style syntax; treat unresolved variables conservatively.
- Keep serde for JSON/TOML; use quick-xml for Maven to avoid regex.

4) Concurrency + Resilience
- Keep JoinSet + bounded concurrency in `AggregatingVulnerabilityRepository`.
- Put retry/backoff in resilience module (common function), used by OSV and GHSA clients (and any network-bound source).
- Add structured tracing at debug/info around cache hits, miss, backoff attempts.

5) Caching discipline
- Continue using `CacheServiceImpl` and existing key helpers (`package_vulnerabilities_key`, `vulnerability_details_key`, etc.).
- Do not introduce ad-hoc keys or paths.
- Evaluate an optional cache “preload popular packages” flow.

6) Configuration updates
- Extend `Config::load()` to include:
  - cache.nvd.local_path (default .vulnera_cache/nvd)
  - cache.nvd.update_on_start (default false)
  - apis.osv timeout/backoff knobs if necessary (or rely on defaults)
- Env override pattern maintained (VULNERA__SECTION__FIELD).

7) Repository aggregation
- Minimal change; keep:
  - dedupe by ID, merge references/sources, prefer highest severity, earliest published_at.
  - use affected ranges from `osv` where present to more accurately map `AffectedPackage`.

---

## Risks & Mitigations

- NVD accuracy and mapping: Keyword matching may not always map neatly to package ecosystems.
  - Mitigation: Keep OSV as primary source; treat NVD as enrichment. Later, consider CPE enrichment where available.
- Parser regressions with new Pest grammars.
  - Mitigation: Golden fixtures and keeping legacy parser as fallback until coverage is proven.
- Dependency drift and crate API changes.
  - Mitigation: Isolate adapters behind our `VulnerabilityApiClient` trait; test conversions with recorded fixtures.

---

## Suggested Milestones

1) OSV adapter (crate-backed)
- Swap internals to use `osv` crate; maintain tests and result equivalence.

2) NVD local adapter
- Introduce `nvd_cve` adapter; add config; document local dataset bootstrap.

3) Pest parser phase 1
- Implement yarn.lock grammar, Gradle/KTS grammar; wire into `ParserFactory` with high priority.

4) Docs & operational guides
- Admin doc for NVD cache management.
- Developer doc for Pest grammar contribution and test fixtures.

5) Optional phase 2
- Extend Pest to other formats (pip-tools, uv.lock) based on ROI and test data.

---

## How This Aligns with Vulnera’s Architecture Guidelines

- DDD layering remains intact; only infra internals change.
- Dependency injection via `AppState` preserved; no service instantiation in handlers.
- Async IO preserved; `tokio::fs` for any async file operations.
- Error handling reused (`ApplicationError` / `VulnerabilityError`); no stringly-typed errors.
- DTOs stay explicit with `utoipa::ToSchema`.
- Testing approach aligned: mock clients/trait for repository tests; no live network in CI.

---

## References

- Fetter (fetter-io/fetter-rs)
  - https://github.com/fetter-io/fetter-rs
  - Highlights: Pest grammars; OSV auditing with cache; resilient CLI pipelines.
- Vulfy (MindPatch/Vulfy)
  - https://github.com/MindPatch/Vulfy
  - Highlights: Async scanning; multi-ecosystem; OSV-first; CI-friendly outputs.
- Crates
  - `osv`: https://crates.io/crates/osv (schema + client)
  - `nvd_cve`: https://crates.io/crates/nvd_cve (local NVD search)

---

## Appendix: Mapping Cheatsheet (Vulnera)

- OSV client
  - Before: custom reqwest + serde models
  - After: `osv` crate client → adapter → `RawVulnerability`
- NVD client
  - Before: remote API + custom rate limiter
  - After: `nvd_cve` local dataset query; no external rate limit; keep resilience for dataset updates
- Parsers
  - Before: serde/regex for many formats (e.g., yarn.lock, Gradle)
  - After: Pest for complex grammars; keep serde for JSON/TOML; prefer quick-xml for Maven
- Repository
  - Before/After: same bounded concurrency, dedupe rules, severity mapping, and graceful source failures
- Caching
  - Before/After: same CacheService keys and TTL; consider pre-warm utilities later
