//! Domain value objects representing immutable concepts

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Represents a semantic version
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub pre_release: Option<String>,
    pub build: Option<String>,
}

impl Version {
    /// Parse a version string into a Version struct
    pub fn parse(version: &str) -> Result<Self, String> {
        let version = version.trim();

        // Handle empty or invalid input
        if version.is_empty() {
            return Err("Version string cannot be empty".to_string());
        }

        // Split on '+' to separate build metadata
        let (version_part, build) = if let Some(pos) = version.find('+') {
            let (v, b) = version.split_at(pos);
            (v, Some(b[1..].to_string()))
        } else {
            (version, None)
        };

        // Split on '-' to separate pre-release
        let (core_version, pre_release) = if let Some(pos) = version_part.find('-') {
            let (v, p) = version_part.split_at(pos);
            (v, Some(p[1..].to_string()))
        } else {
            (version_part, None)
        };

        // Parse core version (major.minor.patch)
        let parts: Vec<&str> = core_version.split('.').collect();
        if parts.len() < 2 {
            return Err(format!("Invalid version format: {}", version));
        }

        let major = parts[0]
            .parse()
            .map_err(|_| format!("Invalid major version: {}", parts[0]))?;

        let minor = parts
            .get(1)
            .unwrap_or(&"0")
            .parse()
            .map_err(|_| format!("Invalid minor version: {}", parts.get(1).unwrap_or(&"0")))?;

        let patch = parts
            .get(2)
            .unwrap_or(&"0")
            .parse()
            .map_err(|_| format!("Invalid patch version: {}", parts.get(2).unwrap_or(&"0")))?;

        Ok(Version {
            major,
            minor,
            patch,
            pre_release,
            build,
        })
    }

    /// Create a new version with major, minor, and patch components
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
            pre_release: None,
            build: None,
        }
    }

    /// Check if this version is compatible with another version (same major version)
    pub fn is_compatible_with(&self, other: &Version) -> bool {
        self.major == other.major
    }

    /// Check if this version satisfies a version requirement
    pub fn satisfies(&self, requirement: &VersionRange) -> bool {
        let start_ok = match &requirement.start {
            Some(start) => {
                if requirement.start_inclusive {
                    self >= start
                } else {
                    self > start
                }
            }
            None => true,
        };

        let end_ok = match &requirement.end {
            Some(end) => {
                if requirement.end_inclusive {
                    self <= end
                } else {
                    self < end
                }
            }
            None => true,
        };

        start_ok && end_ok
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
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(ref pre) = self.pre_release {
            write!(f, "-{}", pre)?;
        }
        if let Some(ref build) = self.build {
            write!(f, "+{}", build)?;
        }
        Ok(())
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

/// Represents a version range for vulnerability matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionRange {
    pub start: Option<Version>,
    pub end: Option<Version>,
    pub start_inclusive: bool,
    pub end_inclusive: bool,
}

impl VersionRange {
    /// Create a new version range
    pub fn new(
        start: Option<Version>,
        end: Option<Version>,
        start_inclusive: bool,
        end_inclusive: bool,
    ) -> Self {
        Self {
            start,
            end,
            start_inclusive,
            end_inclusive,
        }
    }

    /// Create a range that matches exactly one version
    pub fn exact(version: Version) -> Self {
        Self {
            start: Some(version.clone()),
            end: Some(version),
            start_inclusive: true,
            end_inclusive: true,
        }
    }

    /// Create a range that matches versions greater than or equal to the given version
    pub fn at_least(version: Version) -> Self {
        Self {
            start: Some(version),
            end: None,
            start_inclusive: true,
            end_inclusive: false,
        }
    }

    /// Create a range that matches versions less than the given version
    pub fn less_than(version: Version) -> Self {
        Self {
            start: None,
            end: Some(version),
            start_inclusive: false,
            end_inclusive: false,
        }
    }

    /// Check if a version falls within this range
    pub fn contains(&self, version: &Version) -> bool {
        version.satisfies(self)
    }

    /// Check if this range overlaps with another range
    pub fn overlaps_with(&self, other: &VersionRange) -> bool {
        // If either range has no bounds, they overlap
        if self.start.is_none() && self.end.is_none() {
            return true;
        }
        if other.start.is_none() && other.end.is_none() {
            return true;
        }

        // Check for overlap
        let self_start_ok = match (&self.start, &other.end) {
            (Some(self_start), Some(other_end)) => {
                if other.end_inclusive && self.start_inclusive {
                    self_start <= other_end
                } else {
                    self_start < other_end
                }
            }
            _ => true,
        };

        let self_end_ok = match (&self.end, &other.start) {
            (Some(self_end), Some(other_start)) => {
                if self.end_inclusive && other.start_inclusive {
                    self_end >= other_start
                } else {
                    self_end > other_start
                }
            }
            _ => true,
        };

        self_start_ok && self_end_ok
    }
}

impl std::fmt::Display for VersionRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.start, &self.end) {
            (Some(start), Some(end)) => {
                let start_bracket = if self.start_inclusive { "[" } else { "(" };
                let end_bracket = if self.end_inclusive { "]" } else { ")" };
                write!(f, "{}{}, {}{}", start_bracket, start, end, end_bracket)
            }
            (Some(start), None) => {
                let bracket = if self.start_inclusive { ">=" } else { ">" };
                write!(f, "{}{}", bracket, start)
            }
            (None, Some(end)) => {
                let bracket = if self.end_inclusive { "<=" } else { "<" };
                write!(f, "{}{}", bracket, end)
            }
            (None, None) => write!(f, "*"),
        }
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
        assert_eq!(version.major, 1);
        assert_eq!(version.minor, 2);
        assert_eq!(version.patch, 3);
        assert!(version.pre_release.is_none());
        assert!(version.build.is_none());

        // Version with pre-release
        let version = Version::parse("1.2.3-alpha.1").unwrap();
        assert_eq!(version.major, 1);
        assert_eq!(version.minor, 2);
        assert_eq!(version.patch, 3);
        assert_eq!(version.pre_release, Some("alpha.1".to_string()));

        // Version with build metadata
        let version = Version::parse("1.2.3+build.1").unwrap();
        assert_eq!(version.build, Some("build.1".to_string()));

        // Version with both pre-release and build
        let version = Version::parse("1.2.3-beta.2+build.123").unwrap();
        assert_eq!(version.pre_release, Some("beta.2".to_string()));
        assert_eq!(version.build, Some("build.123".to_string()));
    }

    #[test]
    fn test_version_parsing_errors() {
        assert!(Version::parse("").is_err());
        assert!(Version::parse("1").is_err());
        assert!(Version::parse("1.2").is_ok()); // Should work with default patch
        assert!(Version::parse("invalid").is_err());
        assert!(Version::parse("1.2.invalid").is_err());
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

        assert!(v1.is_compatible_with(&v2));
        assert!(!v1.is_compatible_with(&v3));
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
