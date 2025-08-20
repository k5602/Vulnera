//! Application services for orchestrating business logic

use async_trait::async_trait;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};

use super::errors::ApplicationError;
use crate::domain::{
    AnalysisMetadata, AnalysisReport, Ecosystem, Package, Vulnerability, VulnerabilityId,
};
use crate::infrastructure::{VulnerabilityRepository, cache::file_cache::FileCacheRepository};

/// Structured report data for API consumption
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StructuredReport {
    pub id: uuid::Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub summary: ReportSummary,
    pub severity_breakdown: crate::domain::SeverityBreakdown,
    pub package_summaries: Vec<PackageSummary>,
    pub prioritized_vulnerabilities: Vec<Vulnerability>,
}

/// Summary statistics for the report
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReportSummary {
    pub total_packages: usize,
    pub vulnerable_packages: usize,
    pub clean_packages: usize,
    pub total_vulnerabilities: usize,
    pub vulnerability_percentage: f64,
    pub analysis_duration: std::time::Duration,
    pub sources_queried: Vec<String>,
}

/// Package summary with vulnerability information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackageSummary {
    pub name: String,
    pub version: crate::domain::Version,
    pub ecosystem: Ecosystem,
    pub vulnerability_count: usize,
    pub highest_severity: crate::domain::Severity,
    pub vulnerabilities: Vec<VulnerabilityId>,
}

/// Service for orchestrating vulnerability analysis
#[async_trait]
pub trait AnalysisService: Send + Sync {
    async fn analyze_dependencies(
        &self,
        file_content: &str,
        ecosystem: Ecosystem,
    ) -> Result<AnalysisReport, ApplicationError>;

    async fn get_vulnerability_details(
        &self,
        vulnerability_id: &VulnerabilityId,
    ) -> Result<Vulnerability, ApplicationError>;
}

/// Service for managing caching strategies
/// Note: This trait is not dyn-compatible due to generic methods
/// Use concrete implementations instead of trait objects
#[async_trait]
pub trait CacheService: Send + Sync {
    async fn get<T>(&self, key: &str) -> Result<Option<T>, ApplicationError>
    where
        T: serde::de::DeserializeOwned + Send;

    async fn set<T>(&self, key: &str, value: &T, ttl: Duration) -> Result<(), ApplicationError>
    where
        T: serde::Serialize + Send + Sync;

    async fn invalidate(&self, key: &str) -> Result<(), ApplicationError>;
}

/// Service for generating and formatting reports
#[async_trait]
pub trait ReportService: Send + Sync {
    async fn generate_report(&self, analysis: &AnalysisReport) -> Result<String, ApplicationError>;
    async fn generate_html_report(
        &self,
        analysis: &AnalysisReport,
    ) -> Result<String, ApplicationError>;
}

/// Service for managing popular package vulnerabilities with efficient caching
#[async_trait]
pub trait PopularPackageService: Send + Sync {
    async fn list_vulnerabilities(
        &self,
        page: u32,
        per_page: u32,
        ecosystem_filter: Option<&str>,
        severity_filter: Option<&str>,
    ) -> Result<PopularPackageVulnerabilityResult, ApplicationError>;

    async fn refresh_cache(&self) -> Result<(), ApplicationError>;
}

/// Result for popular package vulnerability listing
#[derive(Debug, Clone)]
pub struct PopularPackageVulnerabilityResult {
    pub vulnerabilities: Vec<Vulnerability>,
    pub total_count: u64,
    pub cache_status: String,
}

/// Service implementation for popular package vulnerability management
pub struct PopularPackageServiceImpl<C: CacheService> {
    vulnerability_repository: Arc<dyn VulnerabilityRepository>,
    cache_service: Arc<C>,
    config: Arc<crate::config::Config>,
}

impl<C: CacheService> PopularPackageServiceImpl<C> {
    /// Create a new popular package service
    pub fn new(
        vulnerability_repository: Arc<dyn VulnerabilityRepository>,
        cache_service: Arc<C>,
        config: Arc<crate::config::Config>,
    ) -> Self {
        Self {
            vulnerability_repository,
            cache_service,
            config,
        }
    }

    /// Get cache key for popular packages vulnerabilities
    fn popular_packages_cache_key(&self) -> String {
        "popular_packages_vulnerabilities".to_string()
    }

    /// Get popular packages from configuration
    fn get_popular_packages(&self) -> Vec<(Ecosystem, String, String)> {
        let mut packages = Vec::new();

        if let Some(ref popular_config) = self.config.popular_packages {
            // Add NPM packages
            if let Some(ref npm_packages) = popular_config.npm {
                for pkg in npm_packages {
                    packages.push((Ecosystem::Npm, pkg.name.clone(), pkg.version.clone()));
                }
            }

            // Add PyPI packages
            if let Some(ref pypi_packages) = popular_config.pypi {
                for pkg in pypi_packages {
                    packages.push((Ecosystem::PyPI, pkg.name.clone(), pkg.version.clone()));
                }
            }

            // Add Maven packages
            if let Some(ref maven_packages) = popular_config.maven {
                for pkg in maven_packages {
                    packages.push((Ecosystem::Maven, pkg.name.clone(), pkg.version.clone()));
                }
            }

            // Add Cargo packages
            if let Some(ref cargo_packages) = popular_config.cargo {
                for pkg in cargo_packages {
                    packages.push((Ecosystem::Cargo, pkg.name.clone(), pkg.version.clone()));
                }
            }

            // Add Go packages
            if let Some(ref go_packages) = popular_config.go {
                for pkg in go_packages {
                    packages.push((Ecosystem::Go, pkg.name.clone(), pkg.version.clone()));
                }
            }

            // Add Packagist packages
            if let Some(ref packagist_packages) = popular_config.packagist {
                for pkg in packagist_packages {
                    packages.push((Ecosystem::Packagist, pkg.name.clone(), pkg.version.clone()));
                }
            }
        } else {
            // Fallback to hardcoded packages if no configuration
            packages = vec![
                (Ecosystem::Npm, "react".to_string(), "18.0.0".to_string()),
                (Ecosystem::Npm, "lodash".to_string(), "4.17.20".to_string()),
                (Ecosystem::Npm, "express".to_string(), "4.17.0".to_string()),
                (Ecosystem::PyPI, "django".to_string(), "3.0.0".to_string()),
                (Ecosystem::PyPI, "flask".to_string(), "1.1.0".to_string()),
                (
                    Ecosystem::PyPI,
                    "requests".to_string(),
                    "2.24.0".to_string(),
                ),
            ];
        }

        packages
    }

    /// Get cache TTL for popular packages
    fn get_cache_ttl(&self) -> Duration {
        let hours = self
            .config
            .popular_packages
            .as_ref()
            .and_then(|p| p.cache_ttl_hours)
            .unwrap_or(6); // Default to 6 hours

        Duration::from_secs(hours * 60 * 60)
    }

    /// Query vulnerabilities for all popular packages
    async fn query_popular_packages(&self) -> Result<Vec<Vulnerability>, ApplicationError> {
        let packages = self.get_popular_packages();
        let mut all_vulnerabilities = Vec::new();

        info!(
            "Querying vulnerabilities for {} popular packages",
            packages.len()
        );

        for (ecosystem, name, version) in packages {
            if let Ok(version_obj) = crate::domain::Version::parse(&version) {
                if let Ok(package) = Package::new(name.clone(), version_obj, ecosystem) {
                    match self
                        .vulnerability_repository
                        .find_vulnerabilities(&package)
                        .await
                    {
                        Ok(vulns) => {
                            debug!("Found {} vulnerabilities for {}", vulns.len(), name);
                            all_vulnerabilities.extend(vulns);
                        }
                        Err(e) => {
                            debug!("No vulnerabilities found for {}: {}", name, e);
                        }
                    }
                }
            }
        }

        // Remove duplicates based on vulnerability ID
        all_vulnerabilities.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
        all_vulnerabilities.dedup_by(|a, b| a.id.as_str() == b.id.as_str());

        info!(
            "Found {} unique vulnerabilities across popular packages",
            all_vulnerabilities.len()
        );
        Ok(all_vulnerabilities)
    }
}

#[async_trait]
impl<C: CacheService> PopularPackageService for PopularPackageServiceImpl<C> {
    async fn list_vulnerabilities(
        &self,
        page: u32,
        per_page: u32,
        ecosystem_filter: Option<&str>,
        severity_filter: Option<&str>,
    ) -> Result<PopularPackageVulnerabilityResult, ApplicationError> {
        let cache_key = self.popular_packages_cache_key();
        let mut cache_status = "hit".to_string();

        // Try to get from cache first
        let mut vulnerabilities = if let Some(cached_vulns) = self
            .cache_service
            .get::<Vec<Vulnerability>>(&cache_key)
            .await?
        {
            debug!("Cache hit for popular packages vulnerabilities");
            cached_vulns
        } else {
            debug!("Cache miss for popular packages vulnerabilities, querying sources");
            cache_status = "miss".to_string();

            let vulns = self.query_popular_packages().await?;

            // Cache the result
            let cache_ttl = self.get_cache_ttl();
            if let Err(e) = self.cache_service.set(&cache_key, &vulns, cache_ttl).await {
                warn!("Failed to cache popular packages vulnerabilities: {}", e);
            } else {
                debug!(
                    "Cached popular packages vulnerabilities for {:?}",
                    cache_ttl
                );
            }

            vulns
        };

        // Apply ecosystem filter if specified
        if let Some(ecosystem_filter) = ecosystem_filter {
            let filter_ecosystem = match ecosystem_filter.to_lowercase().as_str() {
                "npm" => Some(Ecosystem::Npm),
                "pypi" => Some(Ecosystem::PyPI),
                "maven" => Some(Ecosystem::Maven),
                "cargo" => Some(Ecosystem::Cargo),
                "go" => Some(Ecosystem::Go),
                "packagist" => Some(Ecosystem::Packagist),
                _ => None,
            };

            if let Some(ecosystem) = filter_ecosystem {
                vulnerabilities.retain(|v| {
                    v.affected_packages
                        .iter()
                        .any(|p| p.package.ecosystem == ecosystem)
                });
            }
        }

        // Apply severity filter if specified
        if let Some(severity_filter) = severity_filter {
            let filter_severity = match severity_filter.to_lowercase().as_str() {
                "critical" => Some(crate::domain::Severity::Critical),
                "high" => Some(crate::domain::Severity::High),
                "medium" => Some(crate::domain::Severity::Medium),
                "low" => Some(crate::domain::Severity::Low),
                _ => None,
            };

            if let Some(severity) = filter_severity {
                vulnerabilities.retain(|v| v.severity == severity);
            }
        }

        // Apply pagination
        let total_count = vulnerabilities.len() as u64;
        let start_index = ((page - 1) * per_page) as usize;
        let end_index = (start_index + per_page as usize).min(vulnerabilities.len());

        let paginated_vulnerabilities = if start_index < vulnerabilities.len() {
            vulnerabilities[start_index..end_index].to_vec()
        } else {
            Vec::new()
        };

        Ok(PopularPackageVulnerabilityResult {
            vulnerabilities: paginated_vulnerabilities,
            total_count,
            cache_status,
        })
    }

    async fn refresh_cache(&self) -> Result<(), ApplicationError> {
        info!("Refreshing popular packages vulnerability cache");

        let cache_key = self.popular_packages_cache_key();

        // Invalidate existing cache
        if let Err(e) = self.cache_service.invalidate(&cache_key).await {
            warn!("Failed to invalidate cache: {}", e);
        }

        // Query fresh data
        let vulnerabilities = self.query_popular_packages().await?;

        // Cache the new data
        let cache_ttl = self.get_cache_ttl();
        self.cache_service
            .set(&cache_key, &vulnerabilities, cache_ttl)
            .await?;

        info!(
            "Refreshed cache with {} vulnerabilities",
            vulnerabilities.len()
        );
        Ok(())
    }
}

/// Cache service implementation with advanced features
pub struct CacheServiceImpl {
    cache_repository: Arc<FileCacheRepository>,
}

impl CacheServiceImpl {
    /// Create a new cache service implementation
    pub fn new(cache_repository: Arc<FileCacheRepository>) -> Self {
        Self { cache_repository }
    }

    /// Generate cache key for package vulnerabilities
    pub fn package_vulnerabilities_key(package: &Package) -> String {
        format!(
            "vuln:{}:{}:{}",
            package.ecosystem.canonical_name(),
            package.name,
            package.version
        )
    }

    /// Generate cache key for vulnerability details
    pub fn vulnerability_details_key(vulnerability_id: &VulnerabilityId) -> String {
        format!("vuln_details:{}", vulnerability_id.as_str())
    }

    /// Generate cache key for analysis reports
    pub fn analysis_report_key(content_hash: &str, ecosystem: &Ecosystem) -> String {
        format!("analysis:{}:{}", ecosystem.canonical_name(), content_hash)
    }

    /// Generate cache key for parsed packages
    pub fn parsed_packages_key(content_hash: &str, ecosystem: &Ecosystem) -> String {
        format!("packages:{}:{}", ecosystem.canonical_name(), content_hash)
    }

    /// Generate a hash for file content to use as cache key component
    pub fn content_hash(content: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Cache warming: preload commonly accessed data
    pub async fn warm_cache(&self, packages: &[Package]) -> Result<(), ApplicationError> {
        info!("Starting cache warming for {} packages", packages.len());

        let mut successful_warms = 0;
        let failed_warms = 0;

        for package in packages {
            let cache_key = Self::package_vulnerabilities_key(package);

            // Check if already cached
            if self.exists(&cache_key).await? {
                debug!("Package {} already cached, skipping", package.identifier());
                continue;
            }

            // This would typically involve fetching from the repository
            // For now, we'll just mark the attempt
            debug!("Would warm cache for package: {}", package.identifier());
            successful_warms += 1;
        }

        info!(
            "Cache warming completed: {} successful, {} failed",
            successful_warms, failed_warms
        );

        Ok(())
    }

    /// Preload cache with vulnerability data for a list of packages
    pub async fn preload_vulnerabilities(
        &self,
        packages: &[Package],
        vulnerability_repository: Arc<dyn VulnerabilityRepository>,
    ) -> Result<(), ApplicationError> {
        info!(
            "Preloading vulnerability cache for {} packages",
            packages.len()
        );

        let mut join_set = JoinSet::new();
        let max_concurrent = 5; // Limit concurrent preloading

        for chunk in packages.chunks(max_concurrent) {
            for package in chunk {
                let package_clone = package.clone();
                let cache_service = self.cache_repository.clone();
                let repo_clone = vulnerability_repository.clone();

                join_set.spawn(async move {
                    let cache_key = Self::package_vulnerabilities_key(&package_clone);

                    // Skip if already cached
                    if cache_service.exists(&cache_key).await.unwrap_or(false) {
                        return Ok::<_, ApplicationError>(());
                    }

                    // Try to find and cache vulnerabilities for this package
                    match repo_clone.find_vulnerabilities(&package_clone).await {
                        Ok(vulnerabilities) => {
                            debug!(
                                "Preloaded {} vulnerabilities for: {}",
                                vulnerabilities.len(),
                                package_clone.identifier()
                            );
                            // Cache the vulnerabilities
                            if let Err(e) = cache_service
                                .set(&cache_key, &vulnerabilities, Duration::from_secs(3600))
                                .await
                            {
                                warn!(
                                    "Failed to cache vulnerabilities for {}: {}",
                                    package_clone.identifier(),
                                    e
                                );
                            }
                        }
                        Err(e) => {
                            debug!(
                                "Failed to preload vulnerabilities for {}: {}",
                                package_clone.identifier(),
                                e
                            );
                        }
                    }
                    Ok(())
                });
            }

            // Wait for current chunk to complete
            while let Some(result) = join_set.join_next().await {
                if let Err(e) = result {
                    warn!("Preload task failed: {}", e);
                }
            }
        }

        info!("Vulnerability cache preloading completed");
        Ok(())
    }

    /// Invalidate cache entries for updated vulnerability data
    pub async fn invalidate_vulnerability_data(
        &self,
        package: &Package,
    ) -> Result<(), ApplicationError> {
        let cache_key = Self::package_vulnerabilities_key(package);
        self.invalidate(&cache_key).await?;

        debug!(
            "Invalidated vulnerability cache for package: {}",
            package.identifier()
        );
        Ok(())
    }

    /// Invalidate all cache entries for a specific ecosystem
    pub async fn invalidate_ecosystem_cache(
        &self,
        ecosystem: &Ecosystem,
    ) -> Result<u64, ApplicationError> {
        info!(
            "Invalidating all cache entries for ecosystem: {}",
            ecosystem
        );

        // This would require iterating through all cache files and checking their keys
        // For now, we'll return a placeholder count
        let invalidated_count = 0u64;

        info!(
            "Invalidated {} cache entries for ecosystem: {}",
            invalidated_count, ecosystem
        );
        Ok(invalidated_count)
    }

    /// Get cache statistics
    pub async fn get_cache_statistics(&self) -> Result<CacheStatistics, ApplicationError> {
        let stats = self.cache_repository.get_stats().await;
        let (total_size, entry_count) = self.cache_repository.get_cache_info().await?;

        Ok(CacheStatistics {
            hits: stats.hits,
            misses: stats.misses,
            hit_rate: if stats.hits + stats.misses > 0 {
                stats.hits as f64 / (stats.hits + stats.misses) as f64
            } else {
                0.0
            },
            total_entries: entry_count,
            total_size_bytes: total_size,
            expired_entries: stats.expired_entries,
            cleanup_runs: stats.cleanup_runs,
        })
    }

    /// Check if a cache entry exists and is not expired
    pub async fn exists(&self, key: &str) -> Result<bool, ApplicationError> {
        self.cache_repository.exists(key).await
    }

    /// Manually trigger cache cleanup
    pub async fn cleanup_expired_entries(&self) -> Result<u64, ApplicationError> {
        self.cache_repository.cleanup_expired().await
    }
}

/// Cache statistics for monitoring and debugging
#[derive(Debug, Clone)]
pub struct CacheStatistics {
    pub hits: u64,
    pub misses: u64,
    pub hit_rate: f64,
    pub total_entries: u64,
    pub total_size_bytes: u64,
    pub expired_entries: u64,
    pub cleanup_runs: u64,
}

#[async_trait]
impl CacheService for CacheServiceImpl {
    async fn get<T>(&self, key: &str) -> Result<Option<T>, ApplicationError>
    where
        T: serde::de::DeserializeOwned + Send,
    {
        self.cache_repository.get(key).await
    }

    async fn set<T>(&self, key: &str, value: &T, ttl: Duration) -> Result<(), ApplicationError>
    where
        T: serde::Serialize + Send + Sync,
    {
        self.cache_repository.set(key, value, ttl).await
    }

    async fn invalidate(&self, key: &str) -> Result<(), ApplicationError> {
        self.cache_repository.invalidate(key).await
    }
}

/// Report service implementation with advanced features
pub struct ReportServiceImpl {
    deduplication_enabled: bool,
    include_metadata: bool,
}

impl ReportServiceImpl {
    /// Create a new report service implementation
    pub fn new() -> Self {
        Self {
            deduplication_enabled: true,
            include_metadata: true,
        }
    }

    /// Create a new report service with custom configuration
    pub fn with_config(deduplication_enabled: bool, include_metadata: bool) -> Self {
        Self {
            deduplication_enabled,
            include_metadata,
        }
    }

    /// Deduplicate vulnerabilities across multiple sources
    pub fn deduplicate_vulnerabilities(
        &self,
        vulnerabilities: Vec<Vulnerability>,
    ) -> Vec<Vulnerability> {
        if !self.deduplication_enabled {
            return vulnerabilities;
        }

        let mut deduplicated: Vec<Vulnerability> = Vec::new();
        let mut seen_ids = std::collections::HashSet::new();
        let original_count = vulnerabilities.len();

        for vulnerability in vulnerabilities {
            let id_str = vulnerability.id.as_str();

            if seen_ids.contains(id_str) {
                // Find existing vulnerability and merge sources
                if let Some(existing) = deduplicated.iter_mut().find(|v| v.id.as_str() == id_str) {
                    // Merge sources from duplicate vulnerability
                    for source in vulnerability.sources {
                        if !existing.sources.contains(&source) {
                            existing.sources.push(source);
                        }
                    }

                    // Merge references
                    for reference in vulnerability.references {
                        if !existing.references.contains(&reference) {
                            existing.references.push(reference);
                        }
                    }

                    // Use the higher severity if different
                    if vulnerability.severity > existing.severity {
                        existing.severity = vulnerability.severity.clone();
                    }
                }
            } else {
                seen_ids.insert(id_str.to_string());
                deduplicated.push(vulnerability);
            }
        }

        info!(
            "Deduplicated {} vulnerabilities down to {}",
            original_count,
            deduplicated.len()
        );

        deduplicated
    }

    /// Calculate severity score for prioritization
    pub fn calculate_severity_score(&self, vulnerability: &Vulnerability) -> f64 {
        let base_score = match vulnerability.severity {
            crate::domain::Severity::Critical => 10.0,
            crate::domain::Severity::High => 7.5,
            crate::domain::Severity::Medium => 5.0,
            crate::domain::Severity::Low => 2.5,
        };

        // Adjust score based on number of affected packages
        let package_multiplier = 1.0 + (vulnerability.affected_packages.len() as f64 * 0.1);

        // Adjust score based on number of sources (more sources = higher confidence)
        let source_multiplier = 1.0 + (vulnerability.sources.len() as f64 * 0.05);

        // Adjust score based on age (newer vulnerabilities might be more critical)
        let age_days = chrono::Utc::now()
            .signed_duration_since(vulnerability.published_at)
            .num_days();
        let age_multiplier = if age_days < 30 {
            1.2 // Recent vulnerabilities get higher priority
        } else if age_days < 365 {
            1.0
        } else {
            0.9 // Older vulnerabilities get slightly lower priority
        };

        base_score * package_multiplier * source_multiplier * age_multiplier
    }

    /// Sort vulnerabilities by priority (severity score)
    pub fn prioritize_vulnerabilities(
        &self,
        mut vulnerabilities: Vec<Vulnerability>,
    ) -> Vec<Vulnerability> {
        vulnerabilities.sort_by(|a, b| {
            let score_a = self.calculate_severity_score(a);
            let score_b = self.calculate_severity_score(b);
            score_b
                .partial_cmp(&score_a)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        vulnerabilities
    }

    /// Generate comprehensive analysis metadata
    pub fn generate_analysis_metadata(&self, report: &AnalysisReport) -> AnalysisMetadata {
        let mut metadata = report.metadata.clone();

        if self.include_metadata {
            // Add additional metadata calculations
            let vulnerability_sources: std::collections::HashSet<_> = report
                .vulnerabilities
                .iter()
                .flat_map(|v| &v.sources)
                .collect();

            let unique_sources: Vec<String> = vulnerability_sources
                .iter()
                .map(|source| format!("{:?}", source))
                .collect();

            // Update sources queried with actual sources found
            metadata.sources_queried = unique_sources;
        }

        metadata
    }

    /// Generate text report format
    pub fn generate_text_report(&self, analysis: &AnalysisReport) -> String {
        let mut report = String::new();

        // Header
        report.push_str("# Vulnerability Analysis Report\n\n");
        report.push_str(&format!(
            "Generated: {}\n",
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        ));
        report.push_str(&format!("Analysis ID: {}\n\n", analysis.id));

        // Summary
        report.push_str("## Summary\n\n");
        report.push_str(&format!(
            "- Total packages analyzed: {}\n",
            analysis.metadata.total_packages
        ));
        report.push_str(&format!(
            "- Vulnerable packages: {}\n",
            analysis.metadata.vulnerable_packages
        ));
        report.push_str(&format!(
            "- Total vulnerabilities: {}\n",
            analysis.metadata.total_vulnerabilities
        ));
        report.push_str(&format!(
            "- Analysis duration: {:?}\n\n",
            analysis.metadata.analysis_duration
        ));

        // Severity breakdown
        report.push_str("## Severity Breakdown\n\n");
        let breakdown = &analysis.metadata.severity_breakdown;
        report.push_str(&format!("- Critical: {}\n", breakdown.critical));
        report.push_str(&format!("- High: {}\n", breakdown.high));
        report.push_str(&format!("- Medium: {}\n", breakdown.medium));
        report.push_str(&format!("- Low: {}\n\n", breakdown.low));

        // Vulnerable packages
        if !analysis.vulnerabilities.is_empty() {
            report.push_str("## Vulnerable Packages\n\n");

            let vulnerable_packages = analysis.vulnerable_packages();
            for package in vulnerable_packages {
                report.push_str(&format!("### {}\n\n", package.identifier()));

                let package_vulns = analysis.vulnerabilities_for_package(package);
                for vuln in package_vulns {
                    report.push_str(&format!("- **{}** ({})\n", vuln.id.as_str(), vuln.severity));
                    report.push_str(&format!("  {}\n", vuln.summary));
                    if !vuln.references.is_empty() {
                        report.push_str(&format!("  References: {}\n", vuln.references.join(", ")));
                    }
                    report.push('\n');
                }
            }
        }

        // Clean packages
        let clean_packages = analysis.clean_packages();
        if !clean_packages.is_empty() {
            report.push_str("## Clean Packages\n\n");
            for package in clean_packages {
                report.push_str(&format!("- {}\n", package.identifier()));
            }
            report.push('\n');
        }

        report
    }

    /// Generate JSON-based analysis report for API consumption
    pub fn generate_json_report(
        &self,
        analysis: &AnalysisReport,
    ) -> Result<String, ApplicationError> {
        serde_json::to_string_pretty(analysis).map_err(ApplicationError::Json)
    }

    /// Generate structured report data for frontend consumption
    pub fn generate_structured_report(&self, analysis: &AnalysisReport) -> StructuredReport {
        let vulnerable_packages = analysis.vulnerable_packages();
        let clean_packages = analysis.clean_packages();

        let vulnerability_percentage = if analysis.metadata.total_packages > 0 {
            (analysis.metadata.vulnerable_packages as f64 / analysis.metadata.total_packages as f64)
                * 100.0
        } else {
            0.0
        };

        let package_summaries: Vec<PackageSummary> = vulnerable_packages
            .iter()
            .map(|package| {
                let package_vulns = analysis.vulnerabilities_for_package(package);
                let highest_severity = package_vulns
                    .iter()
                    .map(|v| &v.severity)
                    .max()
                    .cloned()
                    .unwrap_or(crate::domain::Severity::Low);

                PackageSummary {
                    name: package.name.clone(),
                    version: package.version.clone(),
                    ecosystem: package.ecosystem.clone(),
                    vulnerability_count: package_vulns.len(),
                    highest_severity,
                    vulnerabilities: package_vulns.iter().map(|v| v.id.clone()).collect(),
                }
            })
            .collect();

        let prioritized_vulnerabilities =
            self.prioritize_vulnerabilities(analysis.vulnerabilities.clone());

        StructuredReport {
            id: analysis.id,
            created_at: analysis.created_at,
            summary: ReportSummary {
                total_packages: analysis.metadata.total_packages,
                vulnerable_packages: analysis.metadata.vulnerable_packages,
                clean_packages: clean_packages.len(),
                total_vulnerabilities: analysis.metadata.total_vulnerabilities,
                vulnerability_percentage,
                analysis_duration: analysis.metadata.analysis_duration,
                sources_queried: analysis.metadata.sources_queried.clone(),
            },
            severity_breakdown: analysis.metadata.severity_breakdown.clone(),
            package_summaries,
            prioritized_vulnerabilities,
        }
    }
}

impl Default for ReportServiceImpl {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ReportService for ReportServiceImpl {
    async fn generate_report(&self, analysis: &AnalysisReport) -> Result<String, ApplicationError> {
        info!("Generating text report for analysis: {}", analysis.id);

        // Create a copy of the analysis with deduplicated vulnerabilities
        let deduplicated_vulnerabilities =
            self.deduplicate_vulnerabilities(analysis.vulnerabilities.clone());
        let prioritized_vulnerabilities =
            self.prioritize_vulnerabilities(deduplicated_vulnerabilities);

        // Create a new analysis report with processed vulnerabilities
        let processed_analysis = AnalysisReport {
            id: analysis.id,
            packages: analysis.packages.clone(),
            vulnerabilities: prioritized_vulnerabilities,
            metadata: self.generate_analysis_metadata(analysis),
            created_at: analysis.created_at,
        };

        let report = self.generate_text_report(&processed_analysis);

        info!("Generated text report ({} characters)", report.len());
        Ok(report)
    }

    async fn generate_html_report(
        &self,
        analysis: &AnalysisReport,
    ) -> Result<String, ApplicationError> {
        info!("Generating JSON report for analysis: {}", analysis.id);

        // Create a copy of the analysis with deduplicated vulnerabilities
        let deduplicated_vulnerabilities =
            self.deduplicate_vulnerabilities(analysis.vulnerabilities.clone());
        let prioritized_vulnerabilities =
            self.prioritize_vulnerabilities(deduplicated_vulnerabilities);

        // Create a new analysis report with processed vulnerabilities
        let processed_analysis = AnalysisReport {
            id: analysis.id,
            packages: analysis.packages.clone(),
            vulnerabilities: prioritized_vulnerabilities,
            metadata: analysis.metadata.clone(),
            created_at: analysis.created_at,
        };

        let report = self.generate_json_report(&processed_analysis)?;

        info!("Generated HTML report ({} characters)", report.len());
        Ok(report)
    }
}

/// Implementation of the analysis service
pub struct AnalysisServiceImpl<C: CacheService> {
    parser_factory: Arc<crate::infrastructure::parsers::ParserFactory>,
    vulnerability_repository: Arc<dyn VulnerabilityRepository>,
    cache_service: Arc<C>,
    #[allow(dead_code)]
    max_concurrent_requests: usize, // Reserved for future concurrency control
}

impl<C: CacheService> AnalysisServiceImpl<C> {
    /// Create a new analysis service implementation
    pub fn new(
        parser_factory: Arc<crate::infrastructure::parsers::ParserFactory>,
        vulnerability_repository: Arc<dyn VulnerabilityRepository>,
        cache_service: Arc<C>,
    ) -> Self {
        Self {
            parser_factory,
            vulnerability_repository,
            cache_service,
            max_concurrent_requests: 10, // Default to 10 concurrent requests
        }
    }

    /// Create a new analysis service with custom concurrency limit
    pub fn with_concurrency(
        parser_factory: Arc<crate::infrastructure::parsers::ParserFactory>,
        vulnerability_repository: Arc<dyn VulnerabilityRepository>,
        cache_service: Arc<C>,
        max_concurrent_requests: usize,
    ) -> Self {
        Self {
            parser_factory,
            vulnerability_repository,
            cache_service,
            max_concurrent_requests,
        }
    }

    /// Parse dependency file content into packages
    async fn parse_dependencies(
        &self,
        file_content: &str,
        ecosystem: Ecosystem,
        filename: Option<&str>,
    ) -> Result<Vec<Package>, ApplicationError> {
        // Try to find a parser based on filename first
        if let Some(filename) = filename {
            if let Some(parser) = self.parser_factory.create_parser(filename) {
                debug!("Using parser for filename: {}", filename);
                return parser
                    .parse_file(file_content)
                    .await
                    .map_err(ApplicationError::Parse);
            }
        }

        // Fall back to ecosystem-based parsing by trying common filenames for the ecosystem
        let common_filenames = match ecosystem {
            Ecosystem::Npm => vec!["package.json", "package-lock.json", "yarn.lock"],
            Ecosystem::PyPI => vec!["requirements.txt", "Pipfile", "pyproject.toml"],
            Ecosystem::Maven => vec!["pom.xml"],
            Ecosystem::Cargo => vec!["Cargo.toml", "Cargo.lock"],
            Ecosystem::Go => vec!["go.mod", "go.sum"],
            Ecosystem::Packagist => vec!["composer.json", "composer.lock"],
            _ => vec![],
        };

        // Try each common filename for the ecosystem
        for filename in common_filenames {
            if let Some(parser) = self.parser_factory.create_parser(filename) {
                debug!(
                    "Using parser for ecosystem {:?} with filename: {}",
                    ecosystem, filename
                );
                return parser
                    .parse_file(file_content)
                    .await
                    .map_err(ApplicationError::Parse);
            }
        }

        error!("No parser found for ecosystem: {:?}", ecosystem);
        Err(ApplicationError::InvalidEcosystem {
            ecosystem: format!("{:?}", ecosystem),
        })
    }

    /// Generate cache key for vulnerability lookup
    fn vulnerability_cache_key(&self, package: &Package) -> String {
        format!(
            "vuln:{}:{}:{}",
            package.ecosystem.canonical_name(),
            package.name,
            package.version
        )
    }

    /// Look up vulnerabilities for a single package with caching
    async fn lookup_vulnerabilities_for_package(
        &self,
        package: &Package,
    ) -> Result<Vec<Vulnerability>, ApplicationError> {
        let cache_key = self.vulnerability_cache_key(package);

        // Try to get from cache first
        if let Some(cached_vulnerabilities) = self
            .cache_service
            .get::<Vec<Vulnerability>>(&cache_key)
            .await?
        {
            debug!("Cache hit for package: {}", package.identifier());
            return Ok(cached_vulnerabilities);
        }

        debug!(
            "Cache miss for package: {}, querying repository",
            package.identifier()
        );

        // Query the repository
        let vulnerabilities = self
            .vulnerability_repository
            .find_vulnerabilities(package)
            .await
            .map_err(ApplicationError::Vulnerability)?;

        // Cache the result for 24 hours
        let cache_ttl = Duration::from_secs(24 * 60 * 60);
        if let Err(e) = self
            .cache_service
            .set(&cache_key, &vulnerabilities, cache_ttl)
            .await
        {
            warn!(
                "Failed to cache vulnerabilities for {}: {}",
                package.identifier(),
                e
            );
        }

        Ok(vulnerabilities)
    }

    /// Process packages sequentially with proper error handling
    async fn process_packages_sequentially(
        &self,
        packages: Vec<Package>,
    ) -> Result<Vec<Vulnerability>, ApplicationError> {
        let mut all_vulnerabilities = Vec::new();
        let mut processed_count = 0;

        for package in packages {
            match self.lookup_vulnerabilities_for_package(&package).await {
                Ok(vulnerabilities) => {
                    processed_count += 1;
                    debug!(
                        "Found {} vulnerabilities for package: {}",
                        vulnerabilities.len(),
                        package.identifier()
                    );
                    all_vulnerabilities.extend(vulnerabilities);
                }
                Err(e) => {
                    error!(
                        "Failed to lookup vulnerabilities for package {}: {}",
                        package.identifier(),
                        e
                    );
                    // Continue processing other packages instead of failing completely
                    processed_count += 1;
                }
            }
        }

        info!(
            "Processed {} packages, found {} total vulnerabilities",
            processed_count,
            all_vulnerabilities.len()
        );

        Ok(all_vulnerabilities)
    }
}

#[async_trait]
impl<C: CacheService> AnalysisService for AnalysisServiceImpl<C> {
    async fn analyze_dependencies(
        &self,
        file_content: &str,
        ecosystem: Ecosystem,
    ) -> Result<AnalysisReport, ApplicationError> {
        let start_time = Instant::now();
        info!(
            "Starting dependency analysis for ecosystem: {:?}",
            ecosystem
        );

        // Parse the dependency file
        let packages = self
            .parse_dependencies(file_content, ecosystem, None)
            .await?;

        if packages.is_empty() {
            warn!("No packages found in dependency file");
            let analysis_duration = start_time.elapsed();
            return Ok(AnalysisReport::new(
                packages,
                vec![],
                analysis_duration,
                vec!["No packages found".to_string()],
            ));
        }

        info!("Parsed {} packages from dependency file", packages.len());

        // Look up vulnerabilities for all packages sequentially
        let vulnerabilities = self.process_packages_sequentially(packages.clone()).await?;

        let analysis_duration = start_time.elapsed();
        let sources_queried = vec!["OSV".to_string(), "NVD".to_string(), "GHSA".to_string()];

        let report = AnalysisReport::new(
            packages,
            vulnerabilities,
            analysis_duration,
            sources_queried,
        );

        info!(
            "Analysis completed in {:?}: {} packages, {} vulnerabilities",
            analysis_duration,
            report.metadata.total_packages,
            report.metadata.total_vulnerabilities
        );

        Ok(report)
    }

    async fn get_vulnerability_details(
        &self,
        vulnerability_id: &VulnerabilityId,
    ) -> Result<Vulnerability, ApplicationError> {
        let cache_key = format!("vuln_details:{}", vulnerability_id.as_str());

        // Try cache first
        if let Some(cached_vulnerability) =
            self.cache_service.get::<Vulnerability>(&cache_key).await?
        {
            debug!("Cache hit for vulnerability: {}", vulnerability_id.as_str());
            return Ok(cached_vulnerability);
        }

        debug!(
            "Cache miss for vulnerability: {}, querying repository",
            vulnerability_id.as_str()
        );

        // Query repository
        let vulnerability = self
            .vulnerability_repository
            .get_vulnerability_by_id(vulnerability_id)
            .await
            .map_err(ApplicationError::Vulnerability)?
            .ok_or_else(|| ApplicationError::NotFound {
                resource: "vulnerability".to_string(),
                id: vulnerability_id.as_str().to_string(),
            })?;

        // Cache for 24 hours
        let cache_ttl = Duration::from_secs(24 * 60 * 60);
        if let Err(e) = self
            .cache_service
            .set(&cache_key, &vulnerability, cache_ttl)
            .await
        {
            warn!(
                "Failed to cache vulnerability details for {}: {}",
                vulnerability_id.as_str(),
                e
            );
        }

        Ok(vulnerability)
    }
}
