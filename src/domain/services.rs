//! Domain services containing business logic

use super::{Package, Version, VersionRange, Vulnerability, VulnerabilitySource};
use std::collections::HashMap;

/// Service for matching packages against vulnerabilities
pub struct VulnerabilityMatcher;

impl VulnerabilityMatcher {
    pub fn new() -> Self {
        Self
    }

    /// Check if a package is affected by a vulnerability
    pub fn is_affected(&self, package: &Package, vulnerability: &Vulnerability) -> bool {
        vulnerability.affects_package(package)
    }

    /// Find all vulnerabilities that affect a specific package
    pub fn find_affecting_vulnerabilities<'a>(
        &self,
        package: &Package,
        vulnerabilities: &'a [Vulnerability],
    ) -> Vec<&'a Vulnerability> {
        vulnerabilities
            .iter()
            .filter(|vuln| self.is_affected(package, vuln))
            .collect()
    }

    /// Check if any vulnerabilities affect a package
    pub fn has_vulnerabilities(
        &self,
        package: &Package,
        vulnerabilities: &[Vulnerability],
    ) -> bool {
        vulnerabilities
            .iter()
            .any(|vuln| self.is_affected(package, vuln))
    }
}

impl Default for VulnerabilityMatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Service for comparing versions and ranges
pub struct VersionComparator;

impl VersionComparator {
    pub fn new() -> Self {
        Self
    }

    /// Check if a version falls within a vulnerable range
    pub fn is_in_range(&self, version: &Version, range: &VersionRange) -> bool {
        range.contains(version)
    }

    /// Compare two versions
    pub fn compare(&self, version1: &Version, version2: &Version) -> std::cmp::Ordering {
        version1.cmp(version2)
    }

    /// Check if version1 is greater than version2
    pub fn is_greater(&self, version1: &Version, version2: &Version) -> bool {
        version1 > version2
    }

    /// Check if version1 is less than version2
    pub fn is_less(&self, version1: &Version, version2: &Version) -> bool {
        version1 < version2
    }

    /// Check if two versions are compatible (same major version)
    pub fn is_compatible(&self, version1: &Version, version2: &Version) -> bool {
        version1.is_compatible_with(version2)
    }

    /// Find the latest version from a list
    pub fn find_latest<'a>(&self, versions: &'a [Version]) -> Option<&'a Version> {
        versions.iter().max()
    }

    /// Check if a version satisfies multiple ranges (all must be satisfied)
    pub fn satisfies_all_ranges(&self, version: &Version, ranges: &[VersionRange]) -> bool {
        ranges.iter().all(|range| self.is_in_range(version, range))
    }

    /// Check if a version satisfies any of the ranges (at least one must be satisfied)
    pub fn satisfies_any_range(&self, version: &Version, ranges: &[VersionRange]) -> bool {
        ranges.iter().any(|range| self.is_in_range(version, range))
    }
}

impl Default for VersionComparator {
    fn default() -> Self {
        Self::new()
    }
}

/// Service for aggregating vulnerability reports
pub struct ReportAggregator;

impl ReportAggregator {
    pub fn new() -> Self {
        Self
    }

    /// Combine vulnerability data from multiple sources, deduplicating by ID
    pub fn aggregate(&self, vulnerabilities: Vec<Vulnerability>) -> Vec<Vulnerability> {
        let mut deduplicated: HashMap<String, Vulnerability> = HashMap::new();

        for vulnerability in vulnerabilities {
            let id_str = vulnerability.id.as_str().to_string();

            match deduplicated.get_mut(&id_str) {
                Some(existing) => {
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

                    // Use higher severity
                    if vulnerability.severity > existing.severity {
                        existing.severity = vulnerability.severity;
                    }

                    // Merge affected packages
                    for affected_package in vulnerability.affected_packages {
                        // Check if we already have this package
                        let package_exists =
                            existing.affected_packages.iter().any(|existing_affected| {
                                existing_affected.package.matches(&affected_package.package)
                            });

                        if !package_exists {
                            existing.affected_packages.push(affected_package);
                        }
                    }
                }
                None => {
                    deduplicated.insert(id_str, vulnerability);
                }
            }
        }

        deduplicated.into_values().collect()
    }

    /// Group vulnerabilities by severity
    pub fn group_by_severity<'a>(
        &self,
        vulnerabilities: &'a [Vulnerability],
    ) -> HashMap<&'a super::Severity, Vec<&'a Vulnerability>> {
        let mut grouped = HashMap::new();

        for vulnerability in vulnerabilities {
            grouped
                .entry(&vulnerability.severity)
                .or_insert_with(Vec::new)
                .push(vulnerability);
        }

        grouped
    }

    /// Group vulnerabilities by source
    pub fn group_by_source<'a>(
        &self,
        vulnerabilities: &'a [Vulnerability],
    ) -> HashMap<&'a VulnerabilitySource, Vec<&'a Vulnerability>> {
        let mut grouped = HashMap::new();

        for vulnerability in vulnerabilities {
            for source in &vulnerability.sources {
                grouped
                    .entry(source)
                    .or_insert_with(Vec::new)
                    .push(vulnerability);
            }
        }

        grouped
    }

    /// Sort vulnerabilities by severity (Critical first)
    pub fn sort_by_severity(&self, mut vulnerabilities: Vec<Vulnerability>) -> Vec<Vulnerability> {
        vulnerabilities.sort_by(|a, b| b.severity.cmp(&a.severity));
        vulnerabilities
    }

    /// Filter vulnerabilities by minimum severity
    pub fn filter_by_minimum_severity<'a>(
        &self,
        vulnerabilities: &'a [Vulnerability],
        minimum_severity: &super::Severity,
    ) -> Vec<&'a Vulnerability> {
        vulnerabilities
            .iter()
            .filter(|vuln| &vuln.severity >= minimum_severity)
            .collect()
    }

    /// Count vulnerabilities by ecosystem
    pub fn count_by_ecosystem<'a>(
        &self,
        vulnerabilities: &'a [Vulnerability],
    ) -> HashMap<&'a super::Ecosystem, usize> {
        let mut counts = HashMap::new();

        for vulnerability in vulnerabilities {
            for affected_package in &vulnerability.affected_packages {
                *counts
                    .entry(&affected_package.package.ecosystem)
                    .or_insert(0) += 1;
            }
        }

        counts
    }
}

impl Default for ReportAggregator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        AffectedPackage, Ecosystem, Package, Severity, Version, VersionRange, Vulnerability,
        VulnerabilityId, VulnerabilitySource,
    };
    use chrono::Utc;

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

    fn create_unaffected_package() -> Package {
        Package::new(
            "lodash".to_string(),
            Version::parse("4.17.21").unwrap(),
            Ecosystem::Npm,
        )
        .unwrap()
    }

    #[test]
    fn test_vulnerability_matcher_is_affected() {
        let matcher = VulnerabilityMatcher::new();
        let vulnerability = create_test_vulnerability();
        let affected_package = create_test_package();
        let unaffected_package = create_unaffected_package();

        assert!(matcher.is_affected(&affected_package, &vulnerability));
        assert!(!matcher.is_affected(&unaffected_package, &vulnerability));
    }

    #[test]
    fn test_vulnerability_matcher_find_affecting_vulnerabilities() {
        let matcher = VulnerabilityMatcher::new();
        let vulnerability1 = create_test_vulnerability();
        let mut vulnerability2 = create_test_vulnerability();
        vulnerability2.id = VulnerabilityId::new("CVE-2022-25000".to_string()).unwrap();

        let vulnerabilities = vec![vulnerability1, vulnerability2];
        let affected_package = create_test_package();
        let unaffected_package = create_unaffected_package();

        let affecting = matcher.find_affecting_vulnerabilities(&affected_package, &vulnerabilities);
        assert_eq!(affecting.len(), 2);

        let not_affecting =
            matcher.find_affecting_vulnerabilities(&unaffected_package, &vulnerabilities);
        assert_eq!(not_affecting.len(), 0);
    }

    #[test]
    fn test_vulnerability_matcher_has_vulnerabilities() {
        let matcher = VulnerabilityMatcher::new();
        let vulnerability = create_test_vulnerability();
        let vulnerabilities = vec![vulnerability];
        let affected_package = create_test_package();
        let unaffected_package = create_unaffected_package();

        assert!(matcher.has_vulnerabilities(&affected_package, &vulnerabilities));
        assert!(!matcher.has_vulnerabilities(&unaffected_package, &vulnerabilities));
    }

    #[test]
    fn test_version_comparator_is_in_range() {
        let comparator = VersionComparator::new();
        let version = Version::parse("1.2.3").unwrap();

        let exact_range = VersionRange::exact(version.clone());
        assert!(comparator.is_in_range(&version, &exact_range));

        let at_least_range = VersionRange::at_least(Version::parse("1.2.0").unwrap());
        assert!(comparator.is_in_range(&version, &at_least_range));

        let less_than_range = VersionRange::less_than(Version::parse("1.3.0").unwrap());
        assert!(comparator.is_in_range(&version, &less_than_range));

        let out_of_range = VersionRange::less_than(Version::parse("1.2.0").unwrap());
        assert!(!comparator.is_in_range(&version, &out_of_range));
    }

    #[test]
    fn test_version_comparator_compare() {
        let comparator = VersionComparator::new();
        let v1 = Version::parse("1.2.3").unwrap();
        let v2 = Version::parse("1.2.4").unwrap();
        let v3 = Version::parse("1.2.3").unwrap();

        assert_eq!(comparator.compare(&v1, &v2), std::cmp::Ordering::Less);
        assert_eq!(comparator.compare(&v2, &v1), std::cmp::Ordering::Greater);
        assert_eq!(comparator.compare(&v1, &v3), std::cmp::Ordering::Equal);
    }

    #[test]
    fn test_version_comparator_is_greater_less() {
        let comparator = VersionComparator::new();
        let v1 = Version::parse("1.2.3").unwrap();
        let v2 = Version::parse("1.2.4").unwrap();

        assert!(comparator.is_greater(&v2, &v1));
        assert!(!comparator.is_greater(&v1, &v2));
        assert!(comparator.is_less(&v1, &v2));
        assert!(!comparator.is_less(&v2, &v1));
    }

    #[test]
    fn test_version_comparator_is_compatible() {
        let comparator = VersionComparator::new();
        let v1 = Version::parse("1.2.3").unwrap();
        let v2 = Version::parse("1.3.0").unwrap();
        let v3 = Version::parse("2.0.0").unwrap();

        assert!(comparator.is_compatible(&v1, &v2));
        assert!(!comparator.is_compatible(&v1, &v3));
    }

    #[test]
    fn test_version_comparator_find_latest() {
        let comparator = VersionComparator::new();
        let versions = vec![
            Version::parse("1.2.3").unwrap(),
            Version::parse("1.3.0").unwrap(),
            Version::parse("1.2.4").unwrap(),
        ];

        let latest = comparator.find_latest(&versions);
        assert_eq!(latest, Some(&Version::parse("1.3.0").unwrap()));
    }

    #[test]
    fn test_version_comparator_satisfies_ranges() {
        let comparator = VersionComparator::new();
        let version = Version::parse("1.2.3").unwrap();

        let ranges = vec![
            VersionRange::at_least(Version::parse("1.2.0").unwrap()),
            VersionRange::less_than(Version::parse("1.3.0").unwrap()),
        ];

        assert!(comparator.satisfies_all_ranges(&version, &ranges));
        assert!(comparator.satisfies_any_range(&version, &ranges));

        let failing_ranges = vec![
            VersionRange::at_least(Version::parse("1.3.0").unwrap()),
            VersionRange::less_than(Version::parse("1.2.0").unwrap()),
        ];

        assert!(!comparator.satisfies_all_ranges(&version, &failing_ranges));
        assert!(!comparator.satisfies_any_range(&version, &failing_ranges));
    }

    #[test]
    fn test_report_aggregator_aggregate_deduplication() {
        let aggregator = ReportAggregator::new();

        let vuln1 = create_test_vulnerability();
        let mut vuln2 = create_test_vulnerability(); // Same ID
        vuln2.sources.push(VulnerabilitySource::NVD); // Different source
        vuln2
            .references
            .push("https://example.com/another".to_string()); // Different reference

        let vulnerabilities = vec![vuln1, vuln2];
        let aggregated = aggregator.aggregate(vulnerabilities);

        assert_eq!(aggregated.len(), 1);
        let merged = &aggregated[0];
        assert_eq!(merged.sources.len(), 2); // OSV + NVD
        assert_eq!(merged.references.len(), 2); // Both references
    }

    #[test]
    fn test_report_aggregator_group_by_severity() {
        let aggregator = ReportAggregator::new();

        let mut vuln1 = create_test_vulnerability();
        vuln1.severity = Severity::Critical;
        let mut vuln2 = create_test_vulnerability();
        vuln2.severity = Severity::High;
        vuln2.id = VulnerabilityId::new("CVE-2022-25000".to_string()).unwrap();
        let mut vuln3 = create_test_vulnerability();
        vuln3.severity = Severity::Critical;
        vuln3.id = VulnerabilityId::new("CVE-2022-25001".to_string()).unwrap();

        let vulnerabilities = vec![vuln1, vuln2, vuln3];
        let grouped = aggregator.group_by_severity(&vulnerabilities);

        assert_eq!(grouped.get(&Severity::Critical).unwrap().len(), 2);
        assert_eq!(grouped.get(&Severity::High).unwrap().len(), 1);
        assert!(grouped.get(&Severity::Medium).is_none());
    }

    #[test]
    fn test_report_aggregator_group_by_source() {
        let aggregator = ReportAggregator::new();

        let mut vuln1 = create_test_vulnerability();
        vuln1.sources = vec![VulnerabilitySource::OSV];
        let mut vuln2 = create_test_vulnerability();
        vuln2.sources = vec![VulnerabilitySource::NVD, VulnerabilitySource::GHSA];
        vuln2.id = VulnerabilityId::new("CVE-2022-25000".to_string()).unwrap();

        let vulnerabilities = vec![vuln1, vuln2];
        let grouped = aggregator.group_by_source(&vulnerabilities);

        assert_eq!(grouped.get(&VulnerabilitySource::OSV).unwrap().len(), 1);
        assert_eq!(grouped.get(&VulnerabilitySource::NVD).unwrap().len(), 1);
        assert_eq!(grouped.get(&VulnerabilitySource::GHSA).unwrap().len(), 1);
    }

    #[test]
    fn test_report_aggregator_sort_by_severity() {
        let aggregator = ReportAggregator::new();

        let mut vuln1 = create_test_vulnerability();
        vuln1.severity = Severity::Low;
        let mut vuln2 = create_test_vulnerability();
        vuln2.severity = Severity::Critical;
        vuln2.id = VulnerabilityId::new("CVE-2022-25000".to_string()).unwrap();
        let mut vuln3 = create_test_vulnerability();
        vuln3.severity = Severity::Medium;
        vuln3.id = VulnerabilityId::new("CVE-2022-25001".to_string()).unwrap();

        let vulnerabilities = vec![vuln1, vuln2, vuln3];
        let sorted = aggregator.sort_by_severity(vulnerabilities);

        assert_eq!(sorted[0].severity, Severity::Critical);
        assert_eq!(sorted[1].severity, Severity::Medium);
        assert_eq!(sorted[2].severity, Severity::Low);
    }

    #[test]
    fn test_report_aggregator_filter_by_minimum_severity() {
        let aggregator = ReportAggregator::new();

        let mut vuln1 = create_test_vulnerability();
        vuln1.severity = Severity::Low;
        let mut vuln2 = create_test_vulnerability();
        vuln2.severity = Severity::Critical;
        vuln2.id = VulnerabilityId::new("CVE-2022-25000".to_string()).unwrap();
        let mut vuln3 = create_test_vulnerability();
        vuln3.severity = Severity::Medium;
        vuln3.id = VulnerabilityId::new("CVE-2022-25001".to_string()).unwrap();

        let vulnerabilities = vec![vuln1, vuln2, vuln3];
        let filtered = aggregator.filter_by_minimum_severity(&vulnerabilities, &Severity::Medium);

        assert_eq!(filtered.len(), 2); // Critical and Medium
        assert!(filtered.iter().all(|v| v.severity >= Severity::Medium));
    }

    #[test]
    fn test_report_aggregator_count_by_ecosystem() {
        let aggregator = ReportAggregator::new();

        let vuln1 = create_test_vulnerability(); // npm
        let mut vuln2 = create_test_vulnerability();
        vuln2.id = VulnerabilityId::new("CVE-2022-25000".to_string()).unwrap();
        // Add a Python package to vuln2
        let python_package = Package::new(
            "requests".to_string(),
            Version::parse("2.25.1").unwrap(),
            Ecosystem::PyPI,
        )
        .unwrap();
        let affected_python = AffectedPackage::new(
            python_package,
            vec![VersionRange::less_than(Version::parse("2.26.0").unwrap())],
            vec![Version::parse("2.26.0").unwrap()],
        );
        vuln2.affected_packages.push(affected_python);

        let vulnerabilities = vec![vuln1, vuln2];
        let counts = aggregator.count_by_ecosystem(&vulnerabilities);

        assert_eq!(*counts.get(&Ecosystem::Npm).unwrap(), 2); // Both vulns affect npm
        assert_eq!(*counts.get(&Ecosystem::PyPI).unwrap(), 1); // One vuln affects PyPI
    }

    #[test]
    fn test_default_implementations() {
        let _matcher = VulnerabilityMatcher::default();
        let _comparator = VersionComparator::default();
        let _aggregator = ReportAggregator::default();
    }
}
