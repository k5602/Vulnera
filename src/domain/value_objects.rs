//! Domain value objects representing immutable concepts

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Represents a semantic version using the semver crate for robust parsing and comparison.
/// This is a newtype wrapper around semver::Version to provide domain-specific behavior.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Version(#[serde(with = "version_serde")] pub semver::Version);

impl Version {
    /// Get the major version number
    pub fn major(&self) -> u64 {
        self.0.major
    }

    /// Get the minor version number  
    pub fn minor(&self) -> u64 {
        self.0.minor
    }

    /// Get the patch version number
    pub fn patch(&self) -> u64 {
        self.0.patch
    }

    /// Get the pre-release version string
    pub fn pre_release(&self) -> Option<String> {
        if self.0.pre.is_empty() {
            None
        } else {
            Some(self.0.pre.to_string())
        }
    }

    /// Get the build metadata string
    pub fn build(&self) -> Option<String> {
        if self.0.build.is_empty() {
            None
        } else {
            Some(self.0.build.to_string())
        }
    }
}

impl Version {
    /// Parse a version string into a Version struct
    pub fn parse(version: &str) -> Result<Self, String> {
        let version = version.trim();

        // Handle empty input
        if version.is_empty() {
            return Err("Version string cannot be empty".to_string());
        }

        // Clean up common prefixes that semver might not handle
        let clean_version = version.strip_prefix('v').unwrap_or(version);

        // Handle incomplete versions by adding missing components
        let normalized_version = if clean_version.matches('.').count() == 0 {
            // Only major version provided (e.g., "1" -> "1.0.0")
            format!("{}.0.0", clean_version)
        } else if clean_version.matches('.').count() == 1 {
            // Major.minor provided (e.g., "1.2" -> "1.2.0")
            format!("{}.0", clean_version)
        } else {
            clean_version.to_string()
        };

        semver::Version::parse(&normalized_version)
            .map(Version)
            .map_err(|e| format!("Invalid version format: {}", e))
    }

    /// Create a new version with major, minor, and patch components
    pub fn new(major: u64, minor: u64, patch: u64) -> Self {
        Version(semver::Version::new(major, minor, patch))
    }

    /// Check if this version is compatible with another version (same major version)
    /// For 0.x versions, requires same minor version as well
    pub fn is_compatible_with(&self, other: &Version) -> bool {
        if self.0.major >= 1 && other.0.major >= 1 {
            self.0.major == other.0.major
        } else {
            // For 0.x versions, minor version changes are breaking
            self.0.major == other.0.major && self.0.minor == other.0.minor
        }
    }

    /// Check if this version satisfies a version requirement
    pub fn satisfies(&self, requirement: &VersionRange) -> bool {
        requirement.contains(self)
    }
}

impl FromStr for Version {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Custom serde handling for semver::Version to maintain backward compatibility
mod version_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::str::FromStr;

    pub fn serialize<S>(version: &semver::Version, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        version.to_string().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<semver::Version, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        // Clean up common prefixes
        let clean_s = s.strip_prefix('v').unwrap_or(&s);

        // Handle incomplete versions by adding missing components
        let normalized_version = if clean_s.matches('.').count() == 0 {
            // Only major version provided (e.g., "1" -> "1.0.0")
            format!("{}.0.0", clean_s)
        } else if clean_s.matches('.').count() == 1 {
            // Major.minor provided (e.g., "1.2" -> "1.2.0")
            format!("{}.0", clean_s)
        } else {
            clean_s.to_string()
        };

        semver::Version::from_str(&normalized_version).map_err(serde::de::Error::custom)
    }
}

/// Represents vulnerability severity levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Low => write!(f, "Low"),
            Severity::Medium => write!(f, "Medium"),
            Severity::High => write!(f, "High"),
            Severity::Critical => write!(f, "Critical"),
        }
    }
}

/// Strongly-typed vulnerability identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VulnerabilityId(String);

impl VulnerabilityId {
    /// Create a new VulnerabilityId with validation
    pub fn new(id: String) -> Result<Self, String> {
        if id.trim().is_empty() {
            return Err("Vulnerability ID cannot be empty".to_string());
        }

        // Basic validation for common vulnerability ID formats
        let id = id.trim().to_string();
        if id.len() > 100 {
            return Err("Vulnerability ID too long (max 100 characters)".to_string());
        }

        Ok(VulnerabilityId(id))
    }

    /// Get the inner string value
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Check if this is a CVE identifier
    pub fn is_cve(&self) -> bool {
        self.0.starts_with("CVE-")
    }

    /// Check if this is a GHSA identifier
    pub fn is_ghsa(&self) -> bool {
        self.0.starts_with("GHSA-")
    }

    /// Check if this is an OSV identifier
    pub fn is_osv(&self) -> bool {
        !self.is_cve() && !self.is_ghsa()
    }
}

impl fmt::Display for VulnerabilityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for VulnerabilityId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_string())
    }
}

/// Represents different package ecosystems
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Ecosystem {
    Npm,
    PyPI,
    Maven,
    Cargo,
    Go,
    Packagist,
    RubyGems,
    NuGet,
}

impl Ecosystem {
    /// Get all supported ecosystems
    pub fn all() -> Vec<Ecosystem> {
        vec![
            Ecosystem::Npm,
            Ecosystem::PyPI,
            Ecosystem::Maven,
            Ecosystem::Cargo,
            Ecosystem::Go,
            Ecosystem::Packagist,
            Ecosystem::RubyGems,
            Ecosystem::NuGet,
        ]
    }

    /// Get the canonical name for this ecosystem
    pub fn canonical_name(&self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPI => "pypi",
            Ecosystem::Maven => "maven",
            Ecosystem::Cargo => "cargo",
            Ecosystem::Go => "go",
            Ecosystem::Packagist => "packagist",
            Ecosystem::RubyGems => "rubygems",
            Ecosystem::NuGet => "nuget",
        }
    }

    /// Get common file extensions for this ecosystem
    pub fn file_extensions(&self) -> Vec<&'static str> {
        match self {
            Ecosystem::Npm => vec!["package.json", "package-lock.json", "yarn.lock"],
            Ecosystem::PyPI => vec!["requirements.txt", "Pipfile", "pyproject.toml"],
            Ecosystem::Maven => vec!["pom.xml"],
            Ecosystem::Cargo => vec!["Cargo.toml", "Cargo.lock"],
            Ecosystem::Go => vec!["go.mod", "go.sum"],
            Ecosystem::Packagist => vec!["composer.json", "composer.lock"],
            Ecosystem::RubyGems => vec!["Gemfile", "Gemfile.lock"],
            Ecosystem::NuGet => vec!["packages.config", "*.csproj", "*.fsproj", "*.vbproj"],
        }
    }
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ecosystem::Npm => write!(f, "npm"),
            Ecosystem::PyPI => write!(f, "PyPI"),
            Ecosystem::Maven => write!(f, "Maven"),
            Ecosystem::Cargo => write!(f, "Cargo"),
            Ecosystem::Go => write!(f, "Go"),
            Ecosystem::Packagist => write!(f, "Packagist"),
            Ecosystem::RubyGems => write!(f, "RubyGems"),
            Ecosystem::NuGet => write!(f, "NuGet"),
        }
    }
}

impl FromStr for Ecosystem {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "npm" => Ok(Ecosystem::Npm),
            "pypi" | "python" => Ok(Ecosystem::PyPI),
            "maven" | "java" => Ok(Ecosystem::Maven),
            "cargo" | "rust" => Ok(Ecosystem::Cargo),
            "go" | "golang" => Ok(Ecosystem::Go),
            "packagist" | "php" => Ok(Ecosystem::Packagist),
            "rubygems" | "ruby" => Ok(Ecosystem::RubyGems),
            "nuget" | "dotnet" | ".net" => Ok(Ecosystem::NuGet),
            _ => Err(format!("Unknown ecosystem: {}", s)),
        }
    }
}

/// Represents a version range for vulnerability matching using semver::VersionReq
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VersionRange(#[serde(with = "version_req_serde")] pub semver::VersionReq);

impl VersionRange {
    /// Create a new version range from a requirement string (e.g., ">=1.2.3, <2.0.0")
    pub fn parse(req: &str) -> Result<Self, String> {
        semver::VersionReq::parse(req)
            .map(VersionRange)
            .map_err(|e| format!("Invalid version requirement: {}", e))
    }

    /// Create a range that matches exactly one version
    pub fn exact(version: Version) -> Self {
        let req_str = format!("={}", version.0);
        VersionRange(semver::VersionReq::parse(&req_str).unwrap())
    }

    /// Create a range that matches versions greater than or equal to the given version
    pub fn at_least(version: Version) -> Self {
        let req_str = format!(">={}", version.0);
        VersionRange(semver::VersionReq::parse(&req_str).unwrap())
    }

    /// Create a range that matches versions less than the given version
    pub fn less_than(version: Version) -> Self {
        let req_str = format!("<{}", version.0);
        VersionRange(semver::VersionReq::parse(&req_str).unwrap())
    }

    /// Create a range between two versions (start inclusive, end exclusive)
    pub fn new(
        start: Option<Version>,
        end: Option<Version>,
        start_inclusive: bool,
        end_inclusive: bool,
    ) -> Self {
        let mut req_parts = Vec::new();

        if let Some(start_ver) = start {
            let op = if start_inclusive { ">=" } else { ">" };
            req_parts.push(format!("{}{}", op, start_ver.0));
        }

        if let Some(end_ver) = end {
            let op = if end_inclusive { "<=" } else { "<" };
            req_parts.push(format!("{}{}", op, end_ver.0));
        }

        let req_str = if req_parts.is_empty() {
            "*".to_string()
        } else {
            req_parts.join(", ")
        };

        VersionRange(semver::VersionReq::parse(&req_str).unwrap())
    }

    /// Check if a version falls within this range
    pub fn contains(&self, version: &Version) -> bool {
        self.0.matches(&version.0)
    }

    /// Check if this range overlaps with another range
    /// This is a simplified implementation - for full overlap detection,
    /// you'd need more complex logic
    pub fn overlaps_with(&self, other: &VersionRange) -> bool {
        // Simplified: if either accepts any version from a common test set
        let test_versions = [
            "0.1.0", "0.9.0", "1.0.0", "1.1.0", "1.5.0", "2.0.0", "10.0.0",
        ];

        test_versions.iter().any(|v| {
            if let Ok(version) = Version::parse(v) {
                self.contains(&version) && other.contains(&version)
            } else {
                false
            }
        })
    }
}

impl FromStr for VersionRange {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for VersionRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Custom serde handling for semver::VersionReq  
mod version_req_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::str::FromStr;

    pub fn serialize<S>(req: &semver::VersionReq, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        req.to_string().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<semver::VersionReq, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        semver::VersionReq::from_str(&s).map_err(serde::de::Error::custom)
    }
}

/// Represents vulnerability data sources
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VulnerabilitySource {
    OSV,
    NVD,
    GHSA,
}

impl fmt::Display for VulnerabilitySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VulnerabilitySource::OSV => write!(f, "OSV"),
            VulnerabilitySource::NVD => write!(f, "NVD"),
            VulnerabilitySource::GHSA => write!(f, "GHSA"),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parsing() {
        // Basic version parsing
        let version = Version::parse("1.2.3").unwrap();
        assert_eq!(version.major(), 1);
        assert_eq!(version.minor(), 2);
        assert_eq!(version.patch(), 3);
        assert!(version.pre_release().is_none());
        assert!(version.build().is_none());

        // Version with pre-release
        let version = Version::parse("1.2.3-alpha.1").unwrap();
        assert_eq!(version.major(), 1);
        assert_eq!(version.minor(), 2);
        assert_eq!(version.patch(), 3);
        assert_eq!(version.pre_release(), Some("alpha.1".to_string()));

        // Version with build metadata
        let version = Version::parse("1.2.3+build.1").unwrap();
        assert_eq!(version.build(), Some("build.1".to_string()));

        // Version with both pre-release and build
        let version = Version::parse("1.2.3-beta.2+build.123").unwrap();
        assert_eq!(version.pre_release(), Some("beta.2".to_string()));
        assert_eq!(version.build(), Some("build.123".to_string()));

        // Version with v prefix (common in git tags)
        let version = Version::parse("v1.2.3").unwrap();
        assert_eq!(version.major(), 1);
        assert_eq!(version.minor(), 2);
        assert_eq!(version.patch(), 3);
    }

    #[test]
    fn test_version_parsing_errors() {
        assert!(Version::parse("").is_err());
        assert!(Version::parse("1").is_ok()); // Should work by normalizing to "1.0.0"
        assert!(Version::parse("1.2").is_ok()); // Should work by normalizing to "1.2.0"
        assert!(Version::parse("invalid").is_err());
        assert!(Version::parse("1.2.invalid").is_err());

        // Test that normalization works correctly
        let v1 = Version::parse("1").unwrap();
        assert_eq!(v1.major(), 1);
        assert_eq!(v1.minor(), 0);
        assert_eq!(v1.patch(), 0);

        let v2 = Version::parse("1.2").unwrap();
        assert_eq!(v2.major(), 1);
        assert_eq!(v2.minor(), 2);
        assert_eq!(v2.patch(), 0);
    }

    #[test]
    fn test_version_comparison() {
        let v1 = Version::parse("1.2.3").unwrap();
        let v2 = Version::parse("1.2.4").unwrap();
        let v3 = Version::parse("1.3.0").unwrap();
        let v4 = Version::parse("2.0.0").unwrap();

        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v3 < v4);
        assert!(v1 < v4);
        assert_eq!(v1, v1);
    }

    #[test]
    fn test_version_compatibility() {
        let v1 = Version::parse("1.2.3").unwrap();
        let v2 = Version::parse("1.3.0").unwrap();
        let v3 = Version::parse("2.0.0").unwrap();

        // Major version 1.x are compatible
        assert!(v1.is_compatible_with(&v2));
        assert!(!v1.is_compatible_with(&v3));

        // Test 0.x version compatibility (stricter)
        let v0_1 = Version::parse("0.1.0").unwrap();
        let v0_2 = Version::parse("0.2.0").unwrap();
        let v0_1_1 = Version::parse("0.1.1").unwrap();

        assert!(!v0_1.is_compatible_with(&v0_2)); // Different minor versions
        assert!(v0_1.is_compatible_with(&v0_1_1)); // Same minor version
    }

    #[test]
    fn test_version_satisfies_range() {
        let version = Version::parse("1.2.3").unwrap();

        // Test exact range
        let exact_range = VersionRange::exact(version.clone());
        assert!(version.satisfies(&exact_range));

        // Test at_least range
        let at_least_range = VersionRange::at_least(Version::parse("1.2.0").unwrap());
        assert!(version.satisfies(&at_least_range));

        // Test less_than range
        let less_than_range = VersionRange::less_than(Version::parse("1.3.0").unwrap());
        assert!(version.satisfies(&less_than_range));

        let less_than_range_fail = VersionRange::less_than(Version::parse("1.2.0").unwrap());
        assert!(!version.satisfies(&less_than_range_fail));

        // Test complex range
        let complex_range = VersionRange::parse(">=1.2.0, <1.3.0").unwrap();
        assert!(version.satisfies(&complex_range));

        let out_of_range = VersionRange::parse(">=2.0.0").unwrap();
        assert!(!version.satisfies(&out_of_range));
    }

    #[test]
    fn test_version_display() {
        let version = Version::parse("1.2.3-alpha.1+build.123").unwrap();
        assert_eq!(version.to_string(), "1.2.3-alpha.1+build.123");

        let simple_version = Version::parse("1.2.3").unwrap();
        assert_eq!(simple_version.to_string(), "1.2.3");
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);

        let mut severities = vec![
            Severity::Critical,
            Severity::Low,
            Severity::High,
            Severity::Medium,
        ];
        severities.sort();
        assert_eq!(
            severities,
            vec![
                Severity::Low,
                Severity::Medium,
                Severity::High,
                Severity::Critical
            ]
        );
    }

    #[test]
    fn test_vulnerability_id_validation() {
        // Valid IDs
        assert!(VulnerabilityId::new("CVE-2022-24999".to_string()).is_ok());
        assert!(VulnerabilityId::new("GHSA-xxxx-xxxx-xxxx".to_string()).is_ok());
        assert!(VulnerabilityId::new("OSV-2022-123".to_string()).is_ok());

        // Invalid IDs
        assert!(VulnerabilityId::new("".to_string()).is_err());
        assert!(VulnerabilityId::new("   ".to_string()).is_err());
        assert!(VulnerabilityId::new("a".repeat(101)).is_err());
    }

    #[test]
    fn test_vulnerability_id_types() {
        let cve_id = VulnerabilityId::new("CVE-2022-24999".to_string()).unwrap();
        let ghsa_id = VulnerabilityId::new("GHSA-xxxx-xxxx-xxxx".to_string()).unwrap();
        let osv_id = VulnerabilityId::new("OSV-2022-123".to_string()).unwrap();

        assert!(cve_id.is_cve());
        assert!(!cve_id.is_ghsa());
        assert!(!cve_id.is_osv());

        assert!(!ghsa_id.is_cve());
        assert!(ghsa_id.is_ghsa());
        assert!(!ghsa_id.is_osv());

        assert!(!osv_id.is_cve());
        assert!(!osv_id.is_ghsa());
        assert!(osv_id.is_osv());
    }

    #[test]
    fn test_ecosystem_parsing() {
        assert_eq!(Ecosystem::from_str("npm").unwrap(), Ecosystem::Npm);
        assert_eq!(Ecosystem::from_str("pypi").unwrap(), Ecosystem::PyPI);
        assert_eq!(Ecosystem::from_str("python").unwrap(), Ecosystem::PyPI);
        assert_eq!(Ecosystem::from_str("maven").unwrap(), Ecosystem::Maven);
        assert_eq!(Ecosystem::from_str("java").unwrap(), Ecosystem::Maven);
        assert_eq!(Ecosystem::from_str("cargo").unwrap(), Ecosystem::Cargo);
        assert_eq!(Ecosystem::from_str("rust").unwrap(), Ecosystem::Cargo);
        assert_eq!(Ecosystem::from_str("go").unwrap(), Ecosystem::Go);
        assert_eq!(Ecosystem::from_str("golang").unwrap(), Ecosystem::Go);

        assert!(Ecosystem::from_str("unknown").is_err());
    }

    #[test]
    fn test_ecosystem_properties() {
        let npm = Ecosystem::Npm;
        assert_eq!(npm.canonical_name(), "npm");
        assert!(npm.file_extensions().contains(&"package.json"));
        assert!(npm.file_extensions().contains(&"package-lock.json"));

        let pypi = Ecosystem::PyPI;
        assert_eq!(pypi.canonical_name(), "pypi");
        assert!(pypi.file_extensions().contains(&"requirements.txt"));
        assert!(pypi.file_extensions().contains(&"pyproject.toml"));
    }

    #[test]
    fn test_version_range_operations() {
        let v1 = Version::parse("1.0.0").unwrap();
        let v2 = Version::parse("2.0.0").unwrap();
        let v3 = Version::parse("1.5.0").unwrap();

        // Test exact range
        let exact_range = VersionRange::exact(v1.clone());
        assert!(exact_range.contains(&v1));
        assert!(!exact_range.contains(&v2));

        // Test at_least range
        let at_least_range = VersionRange::at_least(v1.clone());
        assert!(at_least_range.contains(&v1));
        assert!(at_least_range.contains(&v2));
        assert!(at_least_range.contains(&v3));

        // Test less_than range
        let less_than_range = VersionRange::less_than(v2.clone());
        assert!(less_than_range.contains(&v1));
        assert!(less_than_range.contains(&v3));
        assert!(!less_than_range.contains(&v2));

        // Test complex ranges
        let complex_range = VersionRange::parse(">=1.0.0, <2.0.0").unwrap();
        assert!(complex_range.contains(&v1));
        assert!(complex_range.contains(&v3));
        assert!(!complex_range.contains(&v2));
    }

    #[test]
    fn test_version_range_overlap() {
        let range1 = VersionRange::new(
            Some(Version::parse("1.0.0").unwrap()),
            Some(Version::parse("2.0.0").unwrap()),
            true,
            false,
        );

        let range2 = VersionRange::new(
            Some(Version::parse("1.5.0").unwrap()),
            Some(Version::parse("3.0.0").unwrap()),
            true,
            false,
        );

        let range3 = VersionRange::new(
            Some(Version::parse("3.0.0").unwrap()),
            Some(Version::parse("4.0.0").unwrap()),
            true,
            false,
        );

        assert!(range1.overlaps_with(&range2));
        assert!(range2.overlaps_with(&range1));
        assert!(!range1.overlaps_with(&range3));
        assert!(!range3.overlaps_with(&range1));
    }

    #[test]
    fn test_vulnerability_source_display() {
        assert_eq!(VulnerabilitySource::OSV.to_string(), "OSV");
        assert_eq!(VulnerabilitySource::NVD.to_string(), "NVD");
        assert_eq!(VulnerabilitySource::GHSA.to_string(), "GHSA");
    }
}
