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
    AffectedPackage, Ecosystem, Package, Severity, Version, VersionRange, Vulnerability,
    VulnerabilityId, VulnerabilitySource,
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
        _package: &Package, // Keep for interface compatibility but use affected data instead
    ) -> Result<Vulnerability, String> {
        // Parse vulnerability ID
        let vuln_id = VulnerabilityId::new(raw.id.clone())?;

        // Parse severity with fallback
        let severity = self.parse_severity(&raw.severity);

        // Create affected packages from raw vulnerability data
        let mut affected_packages = Vec::new();

        for affected_data in &raw.affected {
            // Convert ecosystem string to domain enum
            let ecosystem = match affected_data.package.ecosystem.as_str() {
                "npm" | "NPM" => Ecosystem::Npm,
                "PyPI" | "pypi" => Ecosystem::PyPI,
                "crates.io" => Ecosystem::Cargo,
                "Go" | "go" => Ecosystem::Go,
                "Maven" | "maven" => Ecosystem::Maven,
                "Packagist" | "packagist" => Ecosystem::Packagist,
                "RubyGems" | "rubygems" => Ecosystem::RubyGems,
                "NuGet" | "nuget" => Ecosystem::NuGet,
                _ => {
                    debug!(
                        "Unknown ecosystem '{}', skipping affected entry",
                        affected_data.package.ecosystem
                    );
                    continue;
                }
            };

            // Parse affected versions and ranges
            let mut affected_version_ranges = Vec::new();
            let mut fixed_versions = Vec::new();

            // Process version ranges if available
            if let Some(ranges) = &affected_data.ranges {
                for range in ranges {
                    // Process events to determine version ranges
                    let mut introduced_version = None;
                    let mut fixed_version = None;

                    for event in &range.events {
                        match event.event_type.as_str() {
                            "introduced" => {
                                if event.value != "0" {
                                    introduced_version = Some(event.value.clone());
                                }
                            }
                            "fixed" => {
                                fixed_version = Some(event.value.clone());
                                fixed_versions.push(event.value.clone());
                            }
                            "last_affected" => {
                                // Use last_affected as the upper bound
                            }
                            _ => {} // Handle other event types as needed
                        }
                    }

                    // Create version range based on available data
                    if let (Some(introduced), Some(fixed)) =
                        (introduced_version.clone(), fixed_version.clone())
                    {
                        if let (Ok(intro_ver), Ok(fix_ver)) =
                            (Version::parse(&introduced), Version::parse(&fixed))
                        {
                            affected_version_ranges.push(VersionRange::new(
                                Some(intro_ver),
                                Some(fix_ver),
                                true,  // start inclusive
                                false, // end exclusive (fixed version not affected)
                            ));
                        }
                    } else if let Some(introduced) = introduced_version {
                        if let Ok(intro_ver) = Version::parse(&introduced) {
                            affected_version_ranges.push(VersionRange::at_least(intro_ver));
                        }
                    }
                }
            }

            // If no ranges but has specific versions, use those
            if affected_version_ranges.is_empty() {
                if let Some(versions) = &affected_data.versions {
                    for version_str in versions {
                        if let Ok(version) = Version::parse(version_str) {
                            affected_version_ranges.push(VersionRange::exact(version));
                        }
                    }
                }
            }

            // Create affected package
            if !affected_version_ranges.is_empty() {
                if let Ok(package) = Package::new(
                    affected_data.package.name.clone(),
                    Version::parse("0.0.0").unwrap(), // Placeholder version
                    ecosystem,
                ) {
                    let affected_package = AffectedPackage::new(
                        package,
                        affected_version_ranges,
                        fixed_versions
                            .into_iter()
                            .filter_map(|v| Version::parse(&v).ok())
                            .collect(),
                    );
                    affected_packages.push(affected_package);
                }
            }
        }

        // If no affected packages from data, fall back to queried package
        if affected_packages.is_empty() {
            let affected_package = AffectedPackage::new(
                _package.clone(),
                vec![VersionRange::exact(_package.version.clone())],
                vec![], // No fixed versions available from raw data
            );
            affected_packages.push(affected_package);
        }

        // Use published_at or current time as fallback
        let published_at = raw.published_at.unwrap_or_else(Utc::now);

        // Ensure summary is not empty - use description or fallback
        let summary = if raw.summary.trim().is_empty() {
            if !raw.description.trim().is_empty() {
                // Use first sentence of description as summary
                raw.description
                    .split('.')
                    .next()
                    .unwrap_or(&raw.description)
                    .trim()
                    .to_string()
            } else {
                // Fallback to ID-based summary
                format!("Vulnerability {}", raw.id)
            }
        } else {
            raw.summary
        };

        // Create the vulnerability
        Vulnerability::new(
            vuln_id,
            summary,
            raw.description,
            severity,
            affected_packages,
            raw.references,
            published_at,
            vec![source],
        )
    }

    /// Parse severity string to Severity enum with fallback
    fn parse_severity(&self, severity_str: &Option<String>) -> Severity {
        if let Some(severity) = severity_str {
            // First, try to parse as a float for CVSS scores
            if let Ok(score) = severity.parse::<f64>() {
                if score >= 9.0 {
                    return Severity::Critical;
                } else if score >= 7.0 {
                    return Severity::High;
                } else if score >= 4.0 {
                    return Severity::Medium;
                } else if score > 0.0 {
                    return Severity::Low;
                }
            }

            // Check if it's a CVSS vector string and extract severity from impact scores
            if severity.starts_with("CVSS:") {
                let parsed_severity = self.parse_cvss_vector_severity(severity);
                debug!(
                    "Parsed CVSS vector '{}' as severity: {}",
                    severity, parsed_severity
                );
                return parsed_severity;
            }

            // If parsing as float fails, try string matching
            let severity_lower = severity.to_lowercase();
            match severity_lower.as_str() {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                "medium" => Severity::Medium,
                "low" => Severity::Low,
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

    /// Parse CVSS vector string to estimate severity based on impact metrics
    ///
    /// This function handles both CVSS v2 and v3 vector strings that GitHub may return
    /// instead of simple severity strings. It extracts the Confidentiality (C), Integrity (I),
    /// and Availability (A) impact scores and maps them to our Severity enum.
    ///
    /// CVSS v3 format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    /// CVSS v2 format: CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C
    ///
    /// Impact values:
    /// - v3: H=High, L=Low, N=None
    /// - v2: C=Complete, P=Partial, N=None
    fn parse_cvss_vector_severity(&self, cvss_vector: &str) -> Severity {
        // Parse CVSS vector components to estimate severity
        // Format v3: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
        // Format v2: CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P

        let mut confidentiality_impact = "N";
        let mut integrity_impact = "N";
        let mut availability_impact = "N";

        // Split by '/' and parse each component
        for component in cvss_vector.split('/') {
            if let Some((key, value)) = component.split_once(':') {
                match key {
                    "C" => confidentiality_impact = value,
                    "I" => integrity_impact = value,
                    "A" => availability_impact = value,
                    _ => continue,
                }
            }
        }

        // Normalize impact values for both CVSS v2 and v3
        // v3: H=High, L=Low, N=None
        // v2: C=Complete, P=Partial, N=None
        let normalize_impact = |impact: &str| -> u8 {
            match impact {
                "H" | "C" => 3, // High/Complete
                "L" | "P" => 2, // Low/Partial
                "N" => 1,       // None
                _ => 1,         // Default to None
            }
        };

        let c_score = normalize_impact(confidentiality_impact);
        let i_score = normalize_impact(integrity_impact);
        let a_score = normalize_impact(availability_impact);

        // Calculate total impact score
        let total_score = c_score + i_score + a_score;
        let high_impacts = [c_score, i_score, a_score]
            .iter()
            .filter(|&&score| score == 3)
            .count();

        // Map to severity based on impact distribution
        match (high_impacts, total_score) {
            // Multiple high/complete impacts = Critical
            (2.., _) => Severity::Critical,
            // Single high/complete impact = High
            (1, _) => Severity::High,
            // Multiple partial impacts or high total = Medium
            (0, 6..) => Severity::Medium,
            // Some impact but not severe = Medium
            (0, 4..=5) => Severity::Medium,
            // Minimal impact = Low
            _ => Severity::Low,
        }
    }

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
                    match e {
                        VulnerabilityError::Json(_) => {
                            debug!(
                                "OSV JSON decode failed for {}: {}",
                                package_clone.identifier(),
                                e
                            );
                        }
                        _ => {
                            warn!("OSV query failed for {}: {}", package_clone.identifier(), e);
                        }
                    }
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

        // Query GHSA (optional - only when token configured)
        if std::env::var("VULNERA__APIS__GHSA__TOKEN")
            .map(|v| !v.is_empty())
            .unwrap_or(false)
        {
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
        } else {
            debug!(
                "Skipping GHSA query for {}: no GHSA token configured",
                package.identifier()
            );
        }

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
                    match e {
                        VulnerabilityError::Json(_) => {
                            debug!(
                                "OSV vulnerability details JSON decode failed for {}: {}",
                                id_str, e
                            );
                        }
                        _ => {
                            warn!(
                                "OSV vulnerability details query failed for {}: {}",
                                id_str, e
                            );
                        }
                    }
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

        // Query GHSA (optional - only when token configured)
        if std::env::var("VULNERA__APIS__GHSA__TOKEN")
            .map(|v| !v.is_empty())
            .unwrap_or(false)
        {
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
        } else {
            debug!(
                "Skipping GHSA vulnerability details query for {}: no GHSA token configured",
                id.as_str()
            );
        }

        // Collect results from all sources
        let mut vulnerabilities = Vec::new();

        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(Ok((Some(raw_vuln), source))) => {
                    // Use a placeholder package since we now extract affected packages from the vulnerability data
                    let placeholder_package = Package::new(
                        "placeholder".to_string(),
                        Version::parse("0.0.0").map_err(|e| {
                            VulnerabilityError::DomainCreation {
                                message: format!("Failed to parse placeholder version: {}", e),
                            }
                        })?,
                        crate::domain::Ecosystem::Npm,
                    )
                    .map_err(|e| VulnerabilityError::DomainCreation {
                        message: format!("Failed to create placeholder package: {}", e),
                    })?;

                    match self.convert_raw_vulnerability(
                        raw_vuln,
                        source.clone(),
                        &placeholder_package,
                    ) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::api_clients::{ghsa::GhsaClient, nvd::NvdClient, osv::OsvClient};

    #[test]
    fn test_parse_severity_numeric_scores() {
        let repo = create_test_repo();

        // Test CVSS numeric scores
        assert_eq!(
            repo.parse_severity(&Some("9.8".to_string())),
            Severity::Critical
        );
        assert_eq!(
            repo.parse_severity(&Some("9.0".to_string())),
            Severity::Critical
        );
        assert_eq!(
            repo.parse_severity(&Some("8.5".to_string())),
            Severity::High
        );
        assert_eq!(
            repo.parse_severity(&Some("7.0".to_string())),
            Severity::High
        );
        assert_eq!(
            repo.parse_severity(&Some("6.5".to_string())),
            Severity::Medium
        );
        assert_eq!(
            repo.parse_severity(&Some("4.0".to_string())),
            Severity::Medium
        );
        assert_eq!(repo.parse_severity(&Some("3.5".to_string())), Severity::Low);
        assert_eq!(repo.parse_severity(&Some("0.1".to_string())), Severity::Low);
    }

    #[test]
    fn test_parse_severity_string_values() {
        let repo = create_test_repo();

        // Test string-based severity levels
        assert_eq!(
            repo.parse_severity(&Some("critical".to_string())),
            Severity::Critical
        );
        assert_eq!(
            repo.parse_severity(&Some("CRITICAL".to_string())),
            Severity::Critical
        );
        assert_eq!(
            repo.parse_severity(&Some("High".to_string())),
            Severity::High
        );
        assert_eq!(
            repo.parse_severity(&Some("medium".to_string())),
            Severity::Medium
        );
        assert_eq!(repo.parse_severity(&Some("LOW".to_string())), Severity::Low);
    }

    #[test]
    fn test_parse_severity_edge_cases() {
        let repo = create_test_repo();

        // Test edge cases and fallbacks
        assert_eq!(
            repo.parse_severity(&Some("unknown".to_string())),
            Severity::Medium
        );
        assert_eq!(repo.parse_severity(&Some("".to_string())), Severity::Medium);
        assert_eq!(repo.parse_severity(&None), Severity::Medium);
        assert_eq!(
            repo.parse_severity(&Some("invalid_number".to_string())),
            Severity::Medium
        );
    }

    #[test]
    fn test_parse_severity_cvss_vectors() {
        let repo = create_test_repo();

        // Test CVSS vector parsing with different impact combinations

        // Critical: Multiple high impacts (C:H/I:H/A:H)
        assert_eq!(
            repo.parse_severity(&Some(
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string()
            )),
            Severity::Critical
        );

        // Critical: Two high impacts (C:H/I:H/A:N)
        assert_eq!(
            repo.parse_severity(&Some(
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N".to_string()
            )),
            Severity::Critical
        );

        // High: Single high impact (C:N/I:N/A:H)
        assert_eq!(
            repo.parse_severity(&Some(
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H".to_string()
            )),
            Severity::High
        );

        // Medium: Multiple low impacts (C:L/I:L/A:N)
        assert_eq!(
            repo.parse_severity(&Some(
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N".to_string()
            )),
            Severity::Medium
        );

        // Medium: Single low impact (C:N/I:L/A:N)
        assert_eq!(
            repo.parse_severity(&Some(
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N".to_string()
            )),
            Severity::Medium
        );

        // Low: No impacts (C:N/I:N/A:N)
        assert_eq!(
            repo.parse_severity(&Some(
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N".to_string()
            )),
            Severity::Low
        );

        // Test CVSS v2 format (P=Partial in v2)
        assert_eq!(
            repo.parse_severity(&Some("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P".to_string())),
            Severity::Medium
        );

        // Test CVSS v2 with complete impact (C=Complete in v2)
        assert_eq!(
            repo.parse_severity(&Some("CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C".to_string())),
            Severity::Critical
        );
    }

    fn create_test_repo() -> AggregatingVulnerabilityRepository {
        // Create mock clients for testing
        let osv_client = Arc::new(OsvClient);
        let nvd_client = Arc::new(NvdClient::new(
            "https://services.nvd.nist.gov".to_string(),
            None,
        ));
        let ghsa_client = Arc::new(GhsaClient::new(
            "test_token".to_string(),
            "https://api.github.com/graphql".to_string(),
        ));

        AggregatingVulnerabilityRepository::new(osv_client, nvd_client, ghsa_client)
    }
}
