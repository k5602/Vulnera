//! Domain entities representing core business concepts

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::value_objects::*;

/// Represents a software package with its metadata
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: Version,
    pub ecosystem: Ecosystem,
}

impl Package {
    /// Create a new package with validation
    pub fn new(name: String, version: Version, ecosystem: Ecosystem) -> Result<Self, String> {
        if name.trim().is_empty() {
            return Err("Package name cannot be empty".to_string());
        }

        let name = name.trim().to_string();
        if name.len() > 214 {
            return Err("Package name too long (max 214 characters)".to_string());
        }

        Ok(Package {
            name,
            version,
            ecosystem,
        })
    }

    /// Get a unique identifier for this package
    pub fn identifier(&self) -> String {
        format!(
            "{}:{}@{}",
            self.ecosystem.canonical_name(),
            self.name,
            self.version
        )
    }

    /// Check if this package matches another package (same name and ecosystem)
    pub fn matches(&self, other: &Package) -> bool {
        self.name == other.name && self.ecosystem == other.ecosystem
    }

    /// Check if this package is the same as another (including version)
    pub fn is_same_as(&self, other: &Package) -> bool {
        self.matches(other) && self.version == other.version
    }
}

/// Represents a security vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: VulnerabilityId,
    pub summary: String,
    pub description: String,
    pub severity: Severity,
    pub affected_packages: Vec<AffectedPackage>,
    pub references: Vec<String>,
    pub published_at: DateTime<Utc>,
    pub sources: Vec<VulnerabilitySource>,
}

impl Vulnerability {
    /// Create a new vulnerability with validation
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: VulnerabilityId,
        summary: String,
        description: String,
        severity: Severity,
        affected_packages: Vec<AffectedPackage>,
        references: Vec<String>,
        published_at: DateTime<Utc>,
        sources: Vec<VulnerabilitySource>,
    ) -> Result<Self, String> {
        if summary.trim().is_empty() {
            return Err("Vulnerability summary cannot be empty".to_string());
        }

        if description.trim().is_empty() {
            return Err("Vulnerability description cannot be empty".to_string());
        }

        if sources.is_empty() {
            return Err("Vulnerability must have at least one source".to_string());
        }

        Ok(Vulnerability {
            id,
            summary: summary.trim().to_string(),
            description: description.trim().to_string(),
            severity,
            affected_packages,
            references,
            published_at,
            sources,
        })
    }

    /// Check if this vulnerability affects a specific package
    pub fn affects_package(&self, package: &Package) -> bool {
        self.affected_packages.iter().any(|affected| {
            affected.package.matches(package) && affected.is_vulnerable(&package.version)
        })
    }

    /// Get the highest severity level among all affected packages
    pub fn max_severity(&self) -> &Severity {
        &self.severity
    }

    /// Check if this vulnerability has been fixed in a specific version
    pub fn is_fixed_in_version(&self, package: &Package, version: &Version) -> bool {
        self.affected_packages
            .iter()
            .filter(|affected| affected.package.matches(package))
            .any(|affected| affected.fixed_versions.contains(version))
    }

    /// Get all ecosystems affected by this vulnerability
    pub fn affected_ecosystems(&self) -> Vec<&Ecosystem> {
        self.affected_packages
            .iter()
            .map(|affected| &affected.package.ecosystem)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect()
    }
}

/// Represents the result of a vulnerability analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub id: Uuid,
    pub packages: Vec<Package>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub metadata: AnalysisMetadata,
    pub created_at: DateTime<Utc>,
}

impl AnalysisReport {
    /// Create a new analysis report
    pub fn new(
        packages: Vec<Package>,
        vulnerabilities: Vec<Vulnerability>,
        analysis_duration: std::time::Duration,
        sources_queried: Vec<String>,
    ) -> Self {
        let metadata = AnalysisMetadata::new(
            &packages,
            &vulnerabilities,
            analysis_duration,
            sources_queried,
        );

        Self {
            id: Uuid::new_v4(),
            packages,
            vulnerabilities,
            metadata,
            created_at: Utc::now(),
        }
    }

    /// Get vulnerabilities that affect a specific package
    pub fn vulnerabilities_for_package(&self, package: &Package) -> Vec<&Vulnerability> {
        self.vulnerabilities
            .iter()
            .filter(|vuln| vuln.affects_package(package))
            .collect()
    }

    /// Get packages that have vulnerabilities
    pub fn vulnerable_packages(&self) -> Vec<&Package> {
        self.packages
            .iter()
            .filter(|package| {
                self.vulnerabilities
                    .iter()
                    .any(|vuln| vuln.affects_package(package))
            })
            .collect()
    }

    /// Get packages that are clean (no vulnerabilities)
    pub fn clean_packages(&self) -> Vec<&Package> {
        self.packages
            .iter()
            .filter(|package| {
                !self
                    .vulnerabilities
                    .iter()
                    .any(|vuln| vuln.affects_package(package))
            })
            .collect()
    }

    /// Get vulnerabilities grouped by severity
    pub fn vulnerabilities_by_severity(
        &self,
    ) -> std::collections::HashMap<&Severity, Vec<&Vulnerability>> {
        let mut grouped = std::collections::HashMap::new();

        for vulnerability in &self.vulnerabilities {
            grouped
                .entry(&vulnerability.severity)
                .or_insert_with(Vec::new)
                .push(vulnerability);
        }

        grouped
    }

    /// Check if the analysis found any vulnerabilities
    pub fn has_vulnerabilities(&self) -> bool {
        !self.vulnerabilities.is_empty()
    }

    /// Get a summary of the analysis results
    pub fn summary(&self) -> String {
        format!(
            "Analyzed {} packages, found {} vulnerabilities ({} packages affected)",
            self.metadata.total_packages,
            self.metadata.total_vulnerabilities,
            self.metadata.vulnerable_packages
        )
    }
}

/// Represents a package affected by a vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedPackage {
    pub package: Package,
    pub vulnerable_ranges: Vec<VersionRange>,
    pub fixed_versions: Vec<Version>,
}

impl AffectedPackage {
    /// Create a new affected package
    pub fn new(
        package: Package,
        vulnerable_ranges: Vec<VersionRange>,
        fixed_versions: Vec<Version>,
    ) -> Self {
        Self {
            package,
            vulnerable_ranges,
            fixed_versions,
        }
    }

    /// Check if a specific version is vulnerable
    pub fn is_vulnerable(&self, version: &Version) -> bool {
        // If no ranges specified, assume all versions are vulnerable
        if self.vulnerable_ranges.is_empty() {
            return !self.fixed_versions.contains(version);
        }

        // Check if version falls within any vulnerable range
        let in_vulnerable_range = self
            .vulnerable_ranges
            .iter()
            .any(|range| range.contains(version));

        // Version is vulnerable if it's in a vulnerable range and not in fixed versions
        in_vulnerable_range && !self.fixed_versions.contains(version)
    }

    /// Get the recommended fixed version (latest fixed version)
    pub fn recommended_fix(&self) -> Option<&Version> {
        self.fixed_versions.iter().max()
    }

    /// Check if there are any fixed versions available
    pub fn has_fix(&self) -> bool {
        !self.fixed_versions.is_empty()
    }
}

/// Metadata about the analysis process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisMetadata {
    pub total_packages: usize,
    pub vulnerable_packages: usize,
    pub total_vulnerabilities: usize,
    pub severity_breakdown: SeverityBreakdown,
    pub analysis_duration: std::time::Duration,
    pub sources_queried: Vec<String>,
}

impl AnalysisMetadata {
    /// Create new analysis metadata
    pub fn new(
        packages: &[Package],
        vulnerabilities: &[Vulnerability],
        analysis_duration: std::time::Duration,
        sources_queried: Vec<String>,
    ) -> Self {
        let vulnerable_packages = packages
            .iter()
            .filter(|package| {
                vulnerabilities
                    .iter()
                    .any(|vuln| vuln.affects_package(package))
            })
            .count();

        let severity_breakdown = SeverityBreakdown::from_vulnerabilities(vulnerabilities);

        Self {
            total_packages: packages.len(),
            vulnerable_packages,
            total_vulnerabilities: vulnerabilities.len(),
            severity_breakdown,
            analysis_duration,
            sources_queried,
        }
    }

    /// Get the percentage of packages that are vulnerable
    pub fn vulnerability_percentage(&self) -> f64 {
        if self.total_packages == 0 {
            0.0
        } else {
            (self.vulnerable_packages as f64 / self.total_packages as f64) * 100.0
        }
    }

    /// Check if the analysis was fast (under 1 second)
    pub fn is_fast_analysis(&self) -> bool {
        self.analysis_duration < std::time::Duration::from_secs(1)
    }
}

/// Breakdown of vulnerabilities by severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityBreakdown {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

impl SeverityBreakdown {
    /// Create a new severity breakdown from vulnerabilities
    pub fn from_vulnerabilities(vulnerabilities: &[Vulnerability]) -> Self {
        let mut breakdown = Self {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
        };

        for vulnerability in vulnerabilities {
            match vulnerability.severity {
                Severity::Critical => breakdown.critical += 1,
                Severity::High => breakdown.high += 1,
                Severity::Medium => breakdown.medium += 1,
                Severity::Low => breakdown.low += 1,
            }
        }

        breakdown
    }

    /// Get the total number of vulnerabilities
    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low
    }

    /// Check if there are any high-severity vulnerabilities (High or Critical)
    pub fn has_high_severity(&self) -> bool {
        self.critical > 0 || self.high > 0
    }

    /// Get the highest severity level present
    pub fn highest_severity(&self) -> Option<Severity> {
        if self.critical > 0 {
            Some(Severity::Critical)
        } else if self.high > 0 {
            Some(Severity::High)
        } else if self.medium > 0 {
            Some(Severity::Medium)
        } else if self.low > 0 {
            Some(Severity::Low)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_package() -> Package {
        Package::new(
            "express".to_string(),
            Version::parse("4.17.1").unwrap(),
            Ecosystem::Npm,
        )
        .unwrap()
    }

    fn create_test_vulnerability() -> Vulnerability {
        let affected_package = AffectedPackage::new(
            create_test_package(),
            vec![VersionRange::less_than(Version::parse("4.18.0").unwrap())],
            vec![Version::parse("4.18.0").unwrap()],
        );

        Vulnerability::new(
            VulnerabilityId::new("CVE-2022-24999".to_string()).unwrap(),
            "Test vulnerability".to_string(),
            "A test vulnerability for unit testing".to_string(),
            Severity::High,
            vec![affected_package],
            vec!["https://example.com/advisory".to_string()],
            Utc::now(),
            vec![VulnerabilitySource::OSV],
        )
        .unwrap()
    }

    #[test]
    fn test_package_creation() {
        let package = Package::new(
            "lodash".to_string(),
            Version::parse("4.17.21").unwrap(),
            Ecosystem::Npm,
        )
        .unwrap();

        assert_eq!(package.name, "lodash");
        assert_eq!(package.version, Version::parse("4.17.21").unwrap());
        assert_eq!(package.ecosystem, Ecosystem::Npm);
    }

    #[test]
    fn test_package_validation() {
        // Empty name should fail
        let result = Package::new(
            "".to_string(),
            Version::parse("1.0.0").unwrap(),
            Ecosystem::Npm,
        );
        assert!(result.is_err());

        // Very long name should fail
        let long_name = "a".repeat(215);
        let result = Package::new(long_name, Version::parse("1.0.0").unwrap(), Ecosystem::Npm);
        assert!(result.is_err());
    }

    #[test]
    fn test_package_identifier() {
        let package = create_test_package();
        let identifier = package.identifier();
        assert_eq!(identifier, "npm:express@4.17.1");
    }

    #[test]
    fn test_package_matches() {
        let package1 = create_test_package();
        let package2 = Package::new(
            "express".to_string(),
            Version::parse("4.18.0").unwrap(),
            Ecosystem::Npm,
        )
        .unwrap();
        let package3 = Package::new(
            "lodash".to_string(),
            Version::parse("4.17.1").unwrap(),
            Ecosystem::Npm,
        )
        .unwrap();

        assert!(package1.matches(&package2));
        assert!(!package1.matches(&package3));
        assert!(!package1.is_same_as(&package2));
        assert!(package1.is_same_as(&package1));
    }

    #[test]
    fn test_vulnerability_creation() {
        let vulnerability = create_test_vulnerability();
        assert_eq!(vulnerability.id.as_str(), "CVE-2022-24999");
        assert_eq!(vulnerability.severity, Severity::High);
        assert!(!vulnerability.affected_packages.is_empty());
    }

    #[test]
    fn test_vulnerability_validation() {
        // Empty summary should fail
        let result = Vulnerability::new(
            VulnerabilityId::new("CVE-2022-24999".to_string()).unwrap(),
            "".to_string(),
            "Description".to_string(),
            Severity::High,
            vec![],
            vec![],
            Utc::now(),
            vec![VulnerabilitySource::OSV],
        );
        assert!(result.is_err());

        // Empty sources should fail
        let result = Vulnerability::new(
            VulnerabilityId::new("CVE-2022-24999".to_string()).unwrap(),
            "Summary".to_string(),
            "Description".to_string(),
            Severity::High,
            vec![],
            vec![],
            Utc::now(),
            vec![],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_vulnerability_affects_package() {
        let vulnerability = create_test_vulnerability();
        let affected_package = create_test_package();
        let unaffected_package = Package::new(
            "lodash".to_string(),
            Version::parse("4.17.21").unwrap(),
            Ecosystem::Npm,
        )
        .unwrap();

        assert!(vulnerability.affects_package(&affected_package));
        assert!(!vulnerability.affects_package(&unaffected_package));
    }

    #[test]
    fn test_affected_package_is_vulnerable() {
        let package = create_test_package();
        let affected = AffectedPackage::new(
            Package::new(
                "express".to_string(),
                Version::parse("4.0.0").unwrap(),
                Ecosystem::Npm,
            )
            .unwrap(),
            vec![VersionRange::less_than(Version::parse("4.18.0").unwrap())],
            vec![Version::parse("4.18.0").unwrap()],
        );

        assert!(affected.is_vulnerable(&package.version));

        let safe_version = Version::parse("4.18.0").unwrap();
        assert!(!affected.is_vulnerable(&safe_version));
    }

    #[test]
    fn test_affected_package_recommended_fix() {
        let affected = AffectedPackage::new(
            create_test_package(),
            vec![],
            vec![
                Version::parse("4.18.0").unwrap(),
                Version::parse("4.18.1").unwrap(),
                Version::parse("4.17.3").unwrap(),
            ],
        );

        let recommended = affected.recommended_fix();
        assert_eq!(recommended, Some(&Version::parse("4.18.1").unwrap()));
    }

    #[test]
    fn test_analysis_report_creation() {
        let packages = vec![create_test_package()];
        let vulnerabilities = vec![create_test_vulnerability()];
        let duration = std::time::Duration::from_millis(500);
        let sources = vec!["OSV".to_string()];

        let report = AnalysisReport::new(packages, vulnerabilities, duration, sources);

        assert_eq!(report.packages.len(), 1);
        assert_eq!(report.vulnerabilities.len(), 1);
        assert_eq!(report.metadata.total_packages, 1);
        assert_eq!(report.metadata.vulnerable_packages, 1);
        assert!(report.has_vulnerabilities());
    }

    #[test]
    fn test_analysis_report_vulnerable_packages() {
        let vulnerable_package = create_test_package();
        let safe_package = Package::new(
            "lodash".to_string(),
            Version::parse("4.17.21").unwrap(),
            Ecosystem::Npm,
        )
        .unwrap();

        let packages = vec![vulnerable_package.clone(), safe_package.clone()];
        let vulnerabilities = vec![create_test_vulnerability()];
        let duration = std::time::Duration::from_millis(500);
        let sources = vec!["OSV".to_string()];

        let report = AnalysisReport::new(packages, vulnerabilities, duration, sources);

        let vulnerable = report.vulnerable_packages();
        let clean = report.clean_packages();

        assert_eq!(vulnerable.len(), 1);
        assert_eq!(clean.len(), 1);
        assert_eq!(vulnerable[0], &vulnerable_package);
        assert_eq!(clean[0], &safe_package);
    }

    #[test]
    fn test_severity_breakdown() {
        let vulnerabilities = vec![
            create_test_vulnerability(), // High
            {
                let mut vuln = create_test_vulnerability();
                vuln.severity = Severity::Critical;
                vuln
            },
            {
                let mut vuln = create_test_vulnerability();
                vuln.severity = Severity::Medium;
                vuln
            },
        ];

        let breakdown = SeverityBreakdown::from_vulnerabilities(&vulnerabilities);

        assert_eq!(breakdown.critical, 1);
        assert_eq!(breakdown.high, 1);
        assert_eq!(breakdown.medium, 1);
        assert_eq!(breakdown.low, 0);
        assert_eq!(breakdown.total(), 3);
        assert!(breakdown.has_high_severity());
        assert_eq!(breakdown.highest_severity(), Some(Severity::Critical));
    }

    #[test]
    fn test_analysis_metadata() {
        let packages = vec![
            create_test_package(),
            Package::new(
                "lodash".to_string(),
                Version::parse("4.17.21").unwrap(),
                Ecosystem::Npm,
            )
            .unwrap(),
        ];
        let vulnerabilities = vec![create_test_vulnerability()];
        let duration = std::time::Duration::from_millis(500);
        let sources = vec!["OSV".to_string(), "NVD".to_string()];

        let metadata = AnalysisMetadata::new(&packages, &vulnerabilities, duration, sources);

        assert_eq!(metadata.total_packages, 2);
        assert_eq!(metadata.vulnerable_packages, 1);
        assert_eq!(metadata.total_vulnerabilities, 1);
        assert_eq!(metadata.vulnerability_percentage(), 50.0);
        assert!(metadata.is_fast_analysis());
    }
}
