//! Repository implementations

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};

use super::api_clients::traits::{RawVulnerability, VulnerabilityApiClient};
use crate::application::errors::VulnerabilityError;
use crate::domain::{
    AffectedPackage, Package, Severity, Version, VersionRange, Vulnerability, VulnerabilityId,
    VulnerabilitySource,
};

/// Repository trait for vulnerability data access
#[async_trait]
pub trait VulnerabilityRepository: Send + Sync {
    async fn find_vulnerabilities(
        &self,
        package: &Package,
    ) -> Result<Vec<Vulnerability>, VulnerabilityError>;

    async fn get_vulnerability_by_id(
        &self,
        id: &VulnerabilityId,
    ) -> Result<Option<Vulnerability>, VulnerabilityError>;
}

/// Aggregating repository that combines multiple vulnerability sources
pub struct AggregatingVulnerabilityRepository {
    osv_client: Arc<dyn VulnerabilityApiClient>,
    nvd_client: Arc<dyn VulnerabilityApiClient>,
    ghsa_client: Arc<dyn VulnerabilityApiClient>,
    max_concurrent_requests: usize,
}

impl AggregatingVulnerabilityRepository {
    /// Create a new aggregating repository with all vulnerability sources
    pub fn new(
        osv_client: Arc<dyn VulnerabilityApiClient>,
        nvd_client: Arc<dyn VulnerabilityApiClient>,
        ghsa_client: Arc<dyn VulnerabilityApiClient>,
    ) -> Self {
        Self {
            osv_client,
            nvd_client,
            ghsa_client,
            max_concurrent_requests: 3, // One per source
        }
    }

    /// Convert RawVulnerability to domain Vulnerability
    fn convert_raw_vulnerability(
        &self,
        raw: RawVulnerability,
        source: VulnerabilitySource,
        package: &Package,
    ) -> Result<Vulnerability, String> {
        // Parse vulnerability ID
        let vuln_id = VulnerabilityId::new(raw.id.clone())?;

        // Parse severity with fallback
        let severity = self.parse_severity(&raw.severity);

        // Create affected package for the queried package
        // Note: We don't have detailed version range info from raw data,
        // so we assume the current package version is affected
        let affected_package = AffectedPackage::new(
            package.clone(),
            vec![VersionRange::exact(package.version.clone())],
            vec![], // No fixed versions available from raw data
        );

        // Use published_at or current time as fallback
        let published_at = raw.published_at.unwrap_or_else(Utc::now);

        // Create the vulnerability
        Vulnerability::new(
            vuln_id,
            raw.summary,
            raw.description,
            severity,
            vec![affected_package],
            raw.references,
            published_at,
            vec![source],
        )
    }

    /// Parse severity string to Severity enum with fallback
    fn parse_severity(&self, severity_str: &Option<String>) -> Severity {
        if let Some(severity) = severity_str {
            let severity_lower = severity.to_lowercase();
            match severity_lower.as_str() {
                "critical" | "9.0" | "10.0" => Severity::Critical,
                "high" | "7.0" | "8.0" | "8.9" => Severity::High,
                "medium" | "4.0" | "5.0" | "6.0" | "6.9" => Severity::Medium,
                "low" | "0.1" | "1.0" | "2.0" | "3.9" => Severity::Low,
                _ => {
                    debug!("Unknown severity '{}', defaulting to Medium", severity);
                    Severity::Medium
                }
            }
        } else {
            debug!("No severity provided, defaulting to Medium");
            Severity::Medium
        }
    }

    /// Deduplicate and merge vulnerabilities from multiple sources
    fn deduplicate_vulnerabilities(
        &self,
        vulnerabilities: Vec<Vulnerability>,
    ) -> Vec<Vulnerability> {
        let mut deduplicated: HashMap<String, Vulnerability> = HashMap::new();
        let original_count = vulnerabilities.len();

        for vulnerability in vulnerabilities {
            let id_str = vulnerability.id.as_str().to_string();

            if let Some(existing) = deduplicated.get_mut(&id_str) {
                // Merge sources
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

                // Merge affected packages
                for affected_pkg in vulnerability.affected_packages {
                    // Check if we already have this package
                    if !existing
                        .affected_packages
                        .iter()
                        .any(|existing_pkg| existing_pkg.package.matches(&affected_pkg.package))
                    {
                        existing.affected_packages.push(affected_pkg);
                    }
                }

                // Use the higher severity if different
                if vulnerability.severity > existing.severity {
                    existing.severity = vulnerability.severity;
                }

                // Use the earlier published date
                if vulnerability.published_at < existing.published_at {
                    existing.published_at = vulnerability.published_at;
                }
            } else {
                deduplicated.insert(id_str, vulnerability);
            }
        }

        let final_count = deduplicated.len();
        if original_count != final_count {
            info!(
                "Deduplicated {} vulnerabilities down to {}",
                original_count, final_count
            );
        }

        deduplicated.into_values().collect()
    }

    /// Query all vulnerability sources concurrently
    async fn query_all_sources(
        &self,
        package: &Package,
    ) -> Result<Vec<Vulnerability>, VulnerabilityError> {
        info!(
            "Querying all vulnerability sources for package: {} (max_concurrent: {})",
            package.identifier(),
            self.max_concurrent_requests
        );

        let mut join_set: JoinSet<
            Result<(Vec<RawVulnerability>, VulnerabilitySource), VulnerabilityError>,
        > = JoinSet::new();

        // Query OSV
        let osv_client = self.osv_client.clone();
        let package_clone = package.clone();
        join_set.spawn(async move {
            match osv_client.query_vulnerabilities(&package_clone).await {
                Ok(raw_vulns) => Ok((raw_vulns, VulnerabilitySource::OSV)),
                Err(e) => {
                    warn!("OSV query failed for {}: {}", package_clone.identifier(), e);
                    Ok((vec![], VulnerabilitySource::OSV))
                }
            }
        });

        // Query NVD
        let nvd_client = self.nvd_client.clone();
        let package_clone = package.clone();
        join_set.spawn(async move {
            match nvd_client.query_vulnerabilities(&package_clone).await {
                Ok(raw_vulns) => Ok((raw_vulns, VulnerabilitySource::NVD)),
                Err(e) => {
                    warn!("NVD query failed for {}: {}", package_clone.identifier(), e);
                    Ok((vec![], VulnerabilitySource::NVD))
                }
            }
        });

        // Query GHSA
        let ghsa_client = self.ghsa_client.clone();
        let package_clone = package.clone();
        join_set.spawn(async move {
            match ghsa_client.query_vulnerabilities(&package_clone).await {
                Ok(raw_vulns) => Ok((raw_vulns, VulnerabilitySource::GHSA)),
                Err(e) => {
                    warn!(
                        "GHSA query failed for {}: {}",
                        package_clone.identifier(),
                        e
                    );
                    Ok((vec![], VulnerabilitySource::GHSA))
                }
            }
        });

        // Collect results
        let mut all_vulnerabilities = Vec::new();
        let mut successful_sources = 0;
        let mut total_raw_vulnerabilities = 0;

        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(Ok((raw_vulns, source))) => {
                    successful_sources += 1;
                    total_raw_vulnerabilities += raw_vulns.len();

                    debug!(
                        "Retrieved {} vulnerabilities from {:?} for {}",
                        raw_vulns.len(),
                        source,
                        package.identifier()
                    );

                    // Convert raw vulnerabilities to domain objects
                    for raw_vuln in raw_vulns {
                        match self.convert_raw_vulnerability(raw_vuln, source.clone(), package) {
                            Ok(vulnerability) => all_vulnerabilities.push(vulnerability),
                            Err(e) => {
                                error!("Failed to convert vulnerability from {:?}: {}", source, e);
                            }
                        }
                    }
                }
                Ok(Err(e)) => {
                    error!("Source query error: {}", e);
                }
                Err(e) => {
                    error!("Join error: {}", e);
                }
            }
        }

        info!(
            "Queried {} sources successfully, found {} raw vulnerabilities for {}",
            successful_sources,
            total_raw_vulnerabilities,
            package.identifier()
        );

        // Deduplicate and merge results
        let deduplicated = self.deduplicate_vulnerabilities(all_vulnerabilities);

        info!(
            "Final result: {} unique vulnerabilities for {}",
            deduplicated.len(),
            package.identifier()
        );

        Ok(deduplicated)
    }

    /// Query all sources for a specific vulnerability ID
    async fn query_vulnerability_by_id(
        &self,
        id: &VulnerabilityId,
    ) -> Result<Option<Vulnerability>, VulnerabilityError> {
        debug!("Querying all sources for vulnerability ID: {}", id.as_str());

        let mut join_set: JoinSet<
            Result<(Option<RawVulnerability>, VulnerabilitySource), VulnerabilityError>,
        > = JoinSet::new();

        // Query OSV
        let osv_client = self.osv_client.clone();
        let id_str = id.as_str().to_string();
        join_set.spawn(async move {
            match osv_client.get_vulnerability_details(&id_str).await {
                Ok(raw_vuln_opt) => Ok((raw_vuln_opt, VulnerabilitySource::OSV)),
                Err(e) => {
                    warn!(
                        "OSV vulnerability details query failed for {}: {}",
                        id_str, e
                    );
                    Ok((None, VulnerabilitySource::OSV))
                }
            }
        });

        // Query NVD
        let nvd_client = self.nvd_client.clone();
        let id_str = id.as_str().to_string();
        join_set.spawn(async move {
            match nvd_client.get_vulnerability_details(&id_str).await {
                Ok(raw_vuln_opt) => Ok((raw_vuln_opt, VulnerabilitySource::NVD)),
                Err(e) => {
                    warn!(
                        "NVD vulnerability details query failed for {}: {}",
                        id_str, e
                    );
                    Ok((None, VulnerabilitySource::NVD))
                }
            }
        });

        // Query GHSA
        let ghsa_client = self.ghsa_client.clone();
        let id_str = id.as_str().to_string();
        join_set.spawn(async move {
            match ghsa_client.get_vulnerability_details(&id_str).await {
                Ok(raw_vuln_opt) => Ok((raw_vuln_opt, VulnerabilitySource::GHSA)),
                Err(e) => {
                    warn!(
                        "GHSA vulnerability details query failed for {}: {}",
                        id_str, e
                    );
                    Ok((None, VulnerabilitySource::GHSA))
                }
            }
        });

        // Collect results - we need to create a dummy package for conversion
        // In a real scenario, we'd need to query with the affected packages info
        let dummy_package = Package::new(
            "unknown".to_string(),
            Version::parse("0.0.0").map_err(|e| VulnerabilityError::RateLimit {
                api: format!("Failed to create dummy package: {}", e),
            })?,
            crate::domain::Ecosystem::Npm, // Use Npm as default instead of Other
        )
        .map_err(|e| VulnerabilityError::RateLimit { api: e })?;

        let mut vulnerabilities = Vec::new();

        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(Ok((Some(raw_vuln), source))) => {
                    match self.convert_raw_vulnerability(raw_vuln, source.clone(), &dummy_package) {
                        Ok(vulnerability) => vulnerabilities.push(vulnerability),
                        Err(e) => {
                            error!("Failed to convert vulnerability from {:?}: {}", source, e);
                        }
                    }
                }
                Ok(Ok((None, _source))) => {
                    // No vulnerability found in this source
                }
                Ok(Err(e)) => {
                    error!("Source query error: {}", e);
                }
                Err(e) => {
                    error!("Join error: {}", e);
                }
            }
        }

        if vulnerabilities.is_empty() {
            debug!("No vulnerability found for ID: {}", id.as_str());
            return Ok(None);
        }

        // Deduplicate and merge (should result in one vulnerability)
        let mut deduplicated = self.deduplicate_vulnerabilities(vulnerabilities);

        match deduplicated.len() {
            0 => Ok(None),
            1 => Ok(Some(deduplicated.remove(0))),
            n => {
                warn!(
                    "Expected 1 vulnerability for ID {}, got {}. Returning first one.",
                    id.as_str(),
                    n
                );
                Ok(Some(deduplicated.remove(0)))
            }
        }
    }
}

#[async_trait]
impl VulnerabilityRepository for AggregatingVulnerabilityRepository {
    #[tracing::instrument(skip(self))]
    async fn find_vulnerabilities(
        &self,
        package: &Package,
    ) -> Result<Vec<Vulnerability>, VulnerabilityError> {
        self.query_all_sources(package).await
    }

    #[tracing::instrument(skip(self))]
    async fn get_vulnerability_by_id(
        &self,
        id: &VulnerabilityId,
    ) -> Result<Option<Vulnerability>, VulnerabilityError> {
        self.query_vulnerability_by_id(id).await
    }
}
