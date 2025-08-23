# Refactor Plan: Adopt `osv` and `nvd_cve` crates + Migrate parsers to Pest

Status: Proposed
Owner: Khaled 'The backend Team'
Applies to: Rust backend (DDD + Async Axum API)
Related: src/infrastructure/api_clients/{osv.rs,nvd.rs}, src/infrastructure/parsers/\*, AggregatingVulnerabilityRepository

## Executive Summary

We will:

- Replace the custom OSV and NVD clients with maintained crates:
  - OSV: use the `osv` crate for schema and client requests instead of hand-rolled models and HTTP wiring.
  - NVD: use the `nvd_cve` crate to query a locally cached NVD database instead of remote rate-limited HTTP queries.
- Migrate file parsers to Pest where it creates correctness and maintainability benefits, starting with complex formats.
- Keep our Domain/Application boundaries intact via adapters that implement our `VulnerabilityApiClient` trait.
- Preserve repository concurrency, caching, severity mapping, and deduplication rules.

This change reduces maintenance risk, improves correctness by aligning with upstream schemas, and gives us an offline-capable NVD path (reliability + performance).

References informing this plan:

- Fetter (fetter-io/fetter-rs): Uses Pest grammars, OSV auditing with caching and a performant pipeline.
- Vulfy (MindPatch/Vulfy): Async scanning with multi-ecosystem parsing; OSV-first approach; architectural patterns similar to our parser factory + repository concurrency.

---

## Goals and Non-Goals

Goals:

- Integrate `osv` crate to replace our `OsvClient` internals (maintain trait boundary).
- Integrate `nvd_cve` for local NVD querying with simple bootstrap and update flow.
- Move parsers for complex grammars to Pest: yarn.lock (v1/v2), Gradle (KTS), complex requirements syntax, and lockfiles with tricky syntax.
- Maintain existing public API (presentation layer) and data contracts.
- Preserve Aggregating Repository design: bounded concurrency, dedupe, source fallback.

Non-Goals:

- Changing DTOs or OpenAPI schemas (unless additive).
- Introducing DB storage.
- Rewriting all parsers to Pest on day one (we’ll prioritize high-benefit formats).

---

## Dependencies and Cargo Changes

Add:

- osv crate with client feature (pick the latest compatible: 0.2.x)
- nvd_cve crate (0.2.0 as of writing)
- pest + pest_derive retained (already present)
- quick-xml for robust XML parsing (Maven pom.xml), replacing regex-based parsing
- serde_yml to replace deprecated serde_yaml for YAML parsing

Cargo.toml adjustments (illustrative; exact versions must align with our resolver):

- osv = { version = "0.2", features = ["client"] }
- nvd_cve = "0.2"
- quick-xml = "0.38"
- serde_yml = "0.0.12"

We retain reqwest for other HTTP needs (GHSA GraphQL, repository client, etc.).

Licensing:

- `osv` (Apache-2.0) and `nvd_cve` (BSD-2-Clause) are compatible with our AGPL-3.0 project when linked as dependencies. No license conflicts anticipated.

---

## Architecture Impact (DDD Alignment)

We keep the layering intact:

- domain: no changes required; continue using `Package`, `Vulnerability`, `Severity`, `VersionRange`.
- application: minor: configuration and cache wiring enhancements; service interfaces unchanged.
- infrastructure:
  - api_clients:
    - Replace internals of OSV and NVD clients with adapters that translate crate responses into our `RawVulnerability`, then into domain models in the repository.
    - Keep `VulnerabilityApiClient` trait untouched; write adapter implementations around `osv` and `nvd_cve`.
  - parsers:
    - Introduce Pest grammars for high-value formats and route parsing through Pest-based modules via `ParserFactory`.
  - repositories:
    - Minor: adjust conversion logic only if new data from crates allows richer `affected` mapping (keep dedupe, severity mapping rules).
- presentation: unchanged.

---

## OSV Integration Plan

Today:

- `OsvClient` does manual HTTP + serde of OSV JSON.
- We convert to `RawVulnerability` and aggregate.

Target:

- Replace manual request/response structs with `osv` crate types + client.
- Map `osv` response types → `RawVulnerability` (unchanged shape in our infra).

Adapter sketch:

- Create `infrastructure/api_clients/osv_adapter.rs` (or repurpose `osv.rs`) that:
  - Constructs an `osv::Client` (tokio/reqwest-based) with sane timeouts from Config.
  - Uses appropriate query (`/v1/query` analog in `osv` crate API) for package vulnerabilities.
  - Uses `osv::vulns::get(id)` style (depending on crate API) for details.
  - Maps `affected`, `references`, `severity`:
    - severity: pick CVSS_V4 > CVSS_V3 > first available to mirror our preference (Fetter chooses a “prime” severity similarly).
    - references: collect URLs; we may prefer ADVISORY link if present as “prime”, but keep all for dedupe/merge.
    - affected: preserve events/ranges and versions for accurate `VersionRange` derivation.

Notes:

- Continue logging cache hit/miss at debug via our `CacheServiceImpl` (OSV client itself doesn’t cache; our layer does).
- Preserve rate limiting/backoff in resilience module for outbound calls if needed (OSV limits are generally lax but keep resilience).

---

## NVD Integration Plan (Local)

Today:

- `NvdClient` makes remote HTTP to NVD API v2.0 with custom rate limiter and retry.

Target:

- Replace with `nvd_cve` that operates on a locally cached copy of NVD feeds.
- Benefits: no rate limiting, more predictable latencies, simpler retries.

Adapter behavior:

- Provide configuration for NVD cache directory (default under `.vulnera_cache/nvd`).
- Add CLI/admin endpoint (future) or startup hook to “update NVD cache” on a schedule or on-demand.
- Query strategy:
  - `nvd_cve` exposes search/index interfaces (name/keyword/CPE). As exact API differs from remote NVD HTTP, we will:
    - Use keyword search against package names first (parity with our current approach).
    - If feasible, evolve to CPE mapping by ecosystem:
      - npm/pypi/crates often lack robust CPE mapping; keep keyword search while collecting reference IDs (CVE/GHSA) to merge with OSV results.
- Map result to `RawVulnerability`:
  - severity: prefer CVSS v3.1 → v3 → v2 (numerical score string).
  - references: include all URLs.
  - published_at: parse from feed metadata.

Fallback:

- If local cache not initialized or corrupted, return empty results and log a warning; do not block OSV or GHSA.

---

## Parser Migration to Pest

Motivation:

- Our current parsers use ad hoc regex/serde-based extraction. This is fine for simple formats, but error-prone for complex grammars and edge cases.
- Fetter uses Pest for structured parsing and demonstrates better correctness for nuanced formats (poetry/pip-tools, nested requirements, etc.).

Strategy:

- Keep the `PackageFileParser` trait and `ParserFactory` unchanged.
- Introduce Pest grammars (under `src/infrastructure/parsers/grammars/`) for high-value, high-complexity formats:
  1. yarn.lock (v1 and v2+ variants; tricky quoting and multi-line blocks)
  2. Gradle (kts flavor subset for “group:name:version” and map syntax)
  3. requirements.txt extended syntax (environment markers, nested -r includes) – phased; begin with robust baseline
  4. Lockfiles that benefit from grammars (e.g., pip-tools, uv.lock) after investigation

- Where serde is robust (Cargo.lock, package-lock.json), keep serde
  - Pest helps where formats are not pure JSON/TOML/XML or have irregular line-oriented grammar.

Implementation notes:

- Each Pest-based parser module compiles grammar via `pest_derive`, produces strongly typed intermediate AST, then maps to `Package` with cleaned versions (respecting ecosystem-specific normalization rules already present).
- Maintain our “version cleaning” policy (strip ^, ~, ranges to base version) consistently. Consider extracting shared normalization helpers reused by both Pest and non-Pest parsers.

Trade-offs: Pest vs JSON/TOML/XML

- Pest is not a replacement for structured format parsers. For JSON and TOML, serde_json and toml provide faster, simpler, and schema-aligned parsing. For XML (e.g., Maven pom.xml), prefer quick-xml over regex to correctly handle namespaces and nested elements.
- When Pest shines:
  - Irregular, line-oriented grammars (e.g., yarn.lock v1/v2, Gradle/Groovy/KTS snippets, complex requirements.txt with markers and nested includes).
  - Need for precise grammar, better error reporting, and resilience to formatting quirks that break naive regex.
- Costs of Pest:
  - More code (grammar + AST mapping) and maintenance when upstream formats evolve.
  - Performance can be lower than streaming serde/quick-xml for large, structured documents.
- Pros of serde/quick-xml:
  - High performance, tight coupling to well-defined specs, simpler code paths, fewer moving parts.
- Cons of serde/quick-xml:
  - Brittle when encountering non-standard syntax, comments, or loosely specified/hand-authored files.
- Rule of thumb:
  - Use serde_json/toml for JSON/TOML and quick-xml for XML when files adhere to their specs.
  - Use Pest for text-based, irregular, or loosely specified formats where grammar helps avoid edge-case bugs.

Testing:

- Golden test fixtures for each grammar (valid + edge-case files).
- Property tests for resilience where cost-effective.
- Ensure output parity with current parsers where intended; document any beneficial differences (e.g., more precise extraction).

---

## Aggregating Repository: What Changes and What Stays

Stays:

- Bounded concurrency JoinSet strategy; default limit = 3 (OSV/NVD/GHSA).
- Deduplication by ID; merge sources + references; pick highest severity.
- Graceful degradation: source failure returns empty set.

Changes:

- Converters will consume crate-native types via `RawVulnerability` adapter mapping (minimize change in repository).
- Potentially richer `affected` modeling if crates expose more detail.

Severity Mapping (unchanged semantics):

- Numeric CVSS: >=9.0 Critical, >=7.0 High, >=4.0 Medium, >0 Low; fallback Medium for unknown strings.
- This aligns with project rules; ensure `osv` severity string extraction remains numeric when possible.

---

## Configuration and Caching

Configuration additions (Config::load):

- cache:
  - nvd.local_path: directory for `nvd_cve` datasets (default: .vulnera_cache/nvd)
  - nvd.update_on_start: bool (default: false)
  - nvd.update_interval_hours: u16 (optional; for future scheduler)
- apis:
  - osv: timeout/retry; base URL if exposed by crate (else our HTTP client config not strictly needed)
  - ghsa: unchanged
- server/security: unchanged

Caching:

- OSV: continue CacheService per package vulnerabilities key; details key TTL 24h.
- NVD: handled by local datasets; we add lightweight wrapper metadata in CacheService only if needed.
- Maintain consistent key helpers; avoid ad hoc strings.

---

## Concurrency, Rate Limiting, and Resilience

- OSV via `osv` crate: likely no strict rate limit; keep exponential backoff for transient failures; log warnings.
- NVD local: no rate limit; updating datasets should be rate-limited/backoff-savvy when downloading feeds (nvd_cve handles this; if not, gate via resilience module when we add an update job).
- Maintain `max_concurrent_requests: 3` at repository-level by default (configurable later).

---

## Testing Strategy

- Unit tests:
  - Adapters: map real `osv`/`nvd_cve` sample payloads to `RawVulnerability`; assert severity, references, affected mapping.
  - Pest parsers: fixtures per grammar; cover edge cases.
- Integration tests:
  - Repository queries with adapters (mock layer as needed); confirm dedupe, merge, severity selection.
  - Ensure HTTP-visible behavior unchanged (presentation layer).
- No live network tests in CI:
  - For OSV: supply recorded fixtures or use crate’s types with local JSON.
  - For NVD: initialize a minimal local NVD snapshot fixture for testing (tiny subset).

CI:

- Keep clippy -D warnings, fmt, coverage thresholds.
- Consider caching nvd fixture in repo under tests/resources (small subset) to avoid network.

---

## Rollout Plan (Phased)

Phase 0: Spike & Design

- Prototype `osv` adapter mapping one ecosystem (npm).
- Prototype `nvd_cve` minimal search for keyword and map to RawVulnerability.

Phase 1: OSV Adapter Swap

- Status: Completed — OSV adapter swapped to use the `osv` crate end-to-end (`osv::client::query_package` + `osv::client::vulnerability`), manual HTTP removed, mapping to `RawVulnerability` preserved, all tests passing.
- Verification: cargo check and tests completed — Commands run: `cargo check`, `cargo test -q`. Result: 171 tests passed, 0 failed; build succeeded.
- Notes: Mockito-based HTTP tests were removed in favor of crate-level OSV calls; ecosystem conversion tests retained. OSV config fields (`apis.osv.base_url`, `apis.osv.timeout_seconds`) were removed from `Config` since the `osv` crate manages endpoints internally. Next, proceed to Phase 2 (NVD local adapter). Optionally run `make -C scripts/build_workflow ci-check` locally and capture outcomes.

- Replace internals of `infrastructure/api_clients/osv.rs` to use `osv` crate while keeping file path and trait name stable.
- Keep test coverage; ensure parity with existing tests.

Phase 2: NVD Local Adapter

- Replace internals of `infrastructure/api_clients/nvd.rs` to use `nvd_cve`.
- Add configuration for local dataset location; add a env variable to set the duration of the data set auto update.

Phase 3: Pest Parsers (Priority Formats)

- New modules + grammar files for yarn.lock and Gradle (kts/gradle).
- Swap `ParserFactory` to use Pest implementations with higher priority than legacy regex parser for those files.
- Validate against comprehensive fixtures.
- and quick-xml for Maven (pom.xml) instead of regex.

Phase 4: Safe Version Recommendation & GHSA Integration

- Status: Parsers done — RubyGems (Gemfile, Gemfile.lock) and NuGet (.csproj/.fsproj/.vbproj, packages.config) implemented, registered in ParserFactory, and fully tested. Starting Phase 4 now.
- Objective: For each dependency, return two upgrade options when current version is known:
  1. nearest_safe_above_current — the smallest safe version greater than or equal to the current version.
  2. most_up_to_date_safe — the newest safe version available.
     If current is unknown, still compute most_up_to_date_safe. If latest is vulnerable, fall back to the newest safe below latest. When no stable safe exists, allow pre-release as a last resort (with a note). Use GHSA alongside OSV for fixed versions/ranges.

- Algorithm (VersionResolutionService):
  1. Fetch available versions via PackageRegistryClient per ecosystem (initially: npm, PyPI, RubyGems, NuGet). Normalize versions (lenient parsing for 4-segment variants in Ruby/NuGet; detect prerelease; exclude yanked/unlisted when available).
  2. Build vulnerability predicate from merged OSV + GHSA:
     - OSV affected ranges and events (introduced/fixed/last_affected).
     - GHSA vulnerableVersionRange + firstPatchedVersion mapped into RawVulnerability.affected as OSV-like events (add “fixed” when firstPatchedVersion exists).
     - A version is vulnerable if any affected package ranges contain it and it is not present in fixed_versions for that affected package.
  3. Compute safe sets:
     - safe_all = all versions not vulnerable
     - safe_stable = safe_all ∩ not prerelease
  4. Select recommendations:
     - most_up_to_date_safe:
       - If safe_stable non-empty: max(safe_stable)
       - Else if safe_all non-empty: max(safe_all) and note prerelease
       - Else: None (no known fix)
     - nearest_safe_above_current (only if current known):
       - min(safe_stable where v >= current), else min(safe_all where v >= current)
       - If none: None
  5. Fallbacks:
     - If registry unavailable, attempt nearest using the minimal fixed version >= current from OSV/GHSA; leave most_up_to_date_safe as None with a note.
  6. Notes/flags:
     - Mark when a prerelease was chosen due to lack of stable safe versions.
     - Preserve reasons when no safe versions exist (“no known fix”).

- GHSA Integration Work:
  - Extend GHSA client to populate RawVulnerability.affected:
    - Map vulnerableVersionRange (parse to semver range when possible; otherwise mark as ecosystem range with best-effort bounds).
    - Map firstPatchedVersion to a “fixed” event value.
  - Aggregation: union fixed_versions and vulnerable_ranges across OSV + GHSA for the same package, keeping existing dedup behavior by vulnerability ID and merging sources/references.

- PackageRegistryClient (initial scope and caching):
  - npm: registry.npmjs.org/{name} — dist-tags.latest and versions[].
  - PyPI: pypi.org/pypi/{name}/json — releases (+ yanked info).
  - RubyGems: rubygems.org/api/v1/versions/{name}.json.
  - NuGet: api.nuget.org v3 flat container index + registration for metadata.
  - Cargo: crates.io API (/api/v1/crates/{name}) — crate metadata (versions[]).
  - Cache version lists (TTL 6–12h) and respect rate limits/backoff.

- API & DTO (additive-only):
  - Add VersionRecommendation fields to dependency analysis results:
    - nearest_safe_above_current: Option<String>
    - most_up_to_date_safe: Option<String>
    - notes: Option<Vec<String>> (e.g., “only prereleases are safe”, “registry unavailable”)
  - Keep backward compatibility (new optional fields).

- Acceptance Criteria (Phase 4):
  - For a vulnerable latest: most_up_to_date_safe returns the highest safe below latest.
  - With a known current: nearest_safe_above_current returns the minimal safe ≥ current.
  - When only prereleases are safe: recommendations provided with a note.
  - GHSA-provided firstPatchedVersion influences fixed_versions and alters recommendations accordingly.
  - When no safe versions exist: both fields None with a clear note; overall behavior documented.
  - Tests cover algorithm edge cases and GHSA mapping.

- Risks & Mitigations (Phase 4):
  - Registry availability and rate limits → cache aggressively; use backoff; partial fallback on OSV/GHSA fixed versions.
  - Non-semver ranges (ecosystem-specific) → best-effort parsing; prefer explicit fixed versions when present.
  - Pre-release semantics differ across ecosystems → conservative policy (prefer stable; allow prerelease only when necessary).

- Work Items (Phase 4):
  - application/: add VersionResolutionService and unit tests.
  - infrastructure/api_clients/ghsa.rs: extend mapping to affected packages with fixed events and ranges.
  - infrastructure/registries/: introduce PackageRegistryClient + minimal npm/PyPI/RubyGems/NuGet implementations with caching/resilience.
  - presentation/: extend DTOs and response assembly to include both recommendations per dependency; update OpenAPI.
  - Add integration tests for recommendation outcomes with mocked registry + OSV/GHSA inputs.

- Start:
  - Begin GHSA affected mapping and VersionResolutionService implementation first, then wire registries and DTO updates.

Phase 5: Cleanups & Docs

- Remove dead code from old manual OSV/NVD models.
- Update docs and examples; add admin instructions for NVD dataset bootstrap/update.
- Final regression and `make ci-check`.

Phase 6: Optional

- Extend Pest to other tricky formats (pip-tools/uv.lock); evaluate ROI.

---

## Risks and Mitigations

- Risk: `nvd_cve` API may not offer direct “package name to CVE” mapping parity.
  - Mitigation: Start with keyword search parity; document limits; use OSV as primary signal, NVD to enrich references/severity.
- Risk: Larger binary due to datasets or extra code.
  - Mitigation: NVD datasets are external; not shipped in binary. Ensure config path is writable; document disk usage.
- Risk: Unexpected schema differences.
  - Mitigation: Centralize mapping in adapters; keep exhaustive tests from fixtures.
- Risk: Parser regressions with Pest.
  - Mitigation: Roll out per-format; preserve legacy parser fallback; expand test fixtures before elevating Pest parser priority.

---

## Work Items (File-Level)

- infrastructure/api_clients/osv.rs
  - Replace manual reqwest models with `osv` client usage; map to `RawVulnerability`.
- infrastructure/api_clients/nvd.rs
  - Replace HTTP client with `nvd_cve`-backed implementation; add config for dataset path.
- infrastructure/resilience.rs
  - Ensure retry/backoff utilities are reused by OSV adapter as needed.
- infrastructure/parsers/grammars/\*
  - Add Pest grammars (yarn.lock, Gradle KTS first).
- infrastructure/parsers/npm.rs, java.rs, python.rs, rust.rs
  - Introduce Pest-backed variants where applicable; prefer quick-xml for Maven (pom.xml) instead of regex; wire into `ParserFactory` with higher priority.
- application/services.rs (CacheServiceImpl)
  - No required changes, but verify cache key usage remains consistent.
- src/config.rs
  - Add new config fields for NVD dataset path and OSV timeouts.
- docs/
  - This plan; add “Admin Guide: NVD Local Cache” doc; update API examples if needed.

---

## Acceptance Criteria

- Endpoints behave the same externally (response JSON, DTOs).
- Analysis returns identical or strictly-better vulnerability coverage for existing test fixtures.
- Repository logs show sources queried, dedupe count, severity mapping as before.
- CI green: lint, fmt, tests, coverage within tolerance.
- Pest parser migration improves correctness for targeted formats; no regressions for others.

---

## Implementation Notes: Mapping Details

OSV adapter:

- Prefer severity from CVSS_V4 → CVSS_V3 → first available; store as string score, map to Severity in repository conversion.
- References: include all; ADVISORY links are often primary.
- Affected: convert events “introduced”/“fixed” to VersionRanges; keep versions list fallback.

NVD adapter:

- Use local search for CVE entries by keyword; parse metrics to numeric base score string.
- `published_at` from CVE metadata (convert to UTC).
- references: all URLs.

Deduplication:

- Unchanged: dedupe by ID exactly; union references and sources; prefer higher severity; earliest published date.

---

## Lessons from Fetter and Vulfy (Applied)

From Fetter:

- Pest grammars yield resilient parsing for complex formats and edge cases; adopt for yarn.lock and Gradle.
- Caching OSV responses: we keep our CacheService; consider optional per-ID OSV cache warmers for popular packages.

From Vulfy:

- Async-first scanning and modular parsers mirrors our ParserFactory design.
- OSV-first sourcing aligns with prioritizing OSV as primary; NVD used to enrich + cross-reference.

---

## Future Considerations

- Add CPE enrichment where feasible per ecosystem (would help NVD matching precision).
- Policy filters (like Vulfy) to prioritize or suppress known false positives (application-layer feature).
- Optional scheduler to update NVD datasets periodically on server start with backoff.

---

## Admin Guide (NVD Local Cache) – Draft

- Configure:
  - VULNERA**CACHE**NVD\_\_LOCAL_PATH=.vulnera_cache/nvd
  - VULNERA**CACHE**NVD\_\_UPDATE_ON_START=false
- First-time setup:
  - Run helper task: `make -C scripts/build_workflow nvd-update` (to be added)
  - Verify dataset presence under configured path.
- Ongoing:
  - Schedule periodic updates via cron or a background task with resilience backoff (future).

---
