# Changelog

All notable changes to this project will be documented in this file.
The format is based on Keep a Changelog and this project adheres to Semantic Versioning.

## [Unreleased]

### Added
- Safe version recommendations integrated across the API:
  - Analyze endpoint now returns `version_recommendations` per vulnerable dependency.
  - Repository analysis endpoint now returns `version_recommendations` for unique vulnerable packages across manifests.
- Version resolution algorithm and features:
  - Recommends both:
    - `nearest_safe_above_current` (the minimal safe version ≥ current)
    - `most_up_to_date_safe` (newest safe version available)
  - Adds `next_safe_minor_within_current_major` hint (next safe version within current major).
  - Upgrade impact classification for each recommendation:
    - `nearest_impact` and `most_up_to_date_impact` — values: `major`/`minor`/`patch`/`unknown`.
  - Prerelease exclusion switch via env:
    - `VULNERA__RECOMMENDATIONS__EXCLUDE_PRERELEASES` (default: `false`).
  - Cap the number of version queries per request:
    - `VULNERA__RECOMMENDATIONS__MAX_VERSION_QUERIES_PER_REQUEST` (default: `50`).
- Registry coverage extended and wired into the multiplexer:
  - Packagist (Composer): `https://repo.packagist.org/packages/{name}.json`
  - Go proxy: `https://proxy.golang.org/{module}/@v/list`
  - Maven Central: `https://repo1.maven.org/maven2/{groupPath}/{artifact}/maven-metadata.xml`
- Caching for registry version listings:
  - Cached via filesystem cache with TTL from `VULNERA__CACHE__TTL_HOURS` (default: 24).
  - Cache keys follow standard helpers to ensure consistent naming.
- OpenAPI/Swagger updates:
  - New DTO fields for recommendations and repository response documented and included in components.
- Tests:
  - Version resolution tests for normal flow, fallback flow (registry unavailable), and GHSA fixed events influence.
  - Ecosystem corner cases:
    - NuGet 4-segment version normalization (e.g., `4.2.11.1` → `4.2.11`)
    - PyPI prerelease-only safe versions and behavior under prerelease exclusion flag.

### Changed
- API responses now include optional `version_recommendations`:
  - AnalysisResponse: `version_recommendations?: VersionRecommendationDto[]`
  - RepositoryAnalysisResponse: `version_recommendations?: VersionRecommendationDto[]`
- VersionRecommendationDto now includes:
  - `nearest_safe_above_current`, `most_up_to_date_safe`
  - `next_safe_minor_within_current_major`
  - `nearest_impact`, `most_up_to_date_impact`
  - `prerelease_exclusion_applied`, `notes`
- Controllers deduplicate packages prior to computing recommendations to reduce redundant registry calls.
- Registry results add explanatory notes if:
  - Registry returns no versions
  - All available versions are yanked/unlisted
  - The nearest recommendation is a prerelease

### Documentation
- `docs/api-examples.md`:
  - Expanded with examples including `version_recommendations` and the new fields.
  - Configuration section added for:
    - `VULNERA__CACHE__DIRECTORY`, `VULNERA__CACHE__TTL_HOURS`
    - `VULNERA__RECOMMENDATIONS__EXCLUDE_PRERELEASES`
  - Added repository analysis example with recommendations.
  - Ecosystem notes on NuGet 4-segment versions and PyPI prerelease behavior.
- `scripts/env/.env.example`:
  - Added:
    - `VULNERA__RECOMMENDATIONS__EXCLUDE_PRERELEASES=false`
    - `VULNERA__RECOMMENDATIONS__MAX_VERSION_QUERIES_PER_REQUEST=50`

### Fixed
- Reduced duplicate recommendation computations via identifier-level deduplication in controllers.
- Notes emitted when registries provide empty/yanked version lists to improve operator diagnostics.

### Breaking Changes
- None. All changes are additive. Existing API fields are unchanged; new fields are optional.

### Environment Variables (recap)
- Cache:
  - `VULNERA__CACHE__DIRECTORY` (default: `.vulnera_cache`)
  - `VULNERA__CACHE__TTL_HOURS` (default: `24`)
- Recommendations:
  - `VULNERA__RECOMMENDATIONS__EXCLUDE_PRERELEASES` (default: `false`)
  - `VULNERA__RECOMMENDATIONS__MAX_VERSION_QUERIES_PER_REQUEST` (default: `50`)

---
