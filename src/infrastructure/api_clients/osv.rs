//! OSV API client implementation

use super::traits::{RawVulnerability, VulnerabilityApiClient};
use crate::application::errors::{ApiError, VulnerabilityError};
use crate::domain::Package;
use async_trait::async_trait;

/// Client for the OSV (Open Source Vulnerability) API
pub struct OsvClient;

impl Default for OsvClient {
    fn default() -> Self {
        OsvClient::new()
    }
}

impl OsvClient {
    /// Create a new OSV client
    pub fn new() -> Self {
        Self
    }

    /// Convert domain ecosystem to OSV ecosystem enum
    fn ecosystem_to_osv(ecosystem: &crate::domain::Ecosystem) -> osv::schema::Ecosystem {
        match ecosystem {
            crate::domain::Ecosystem::Npm => osv::schema::Ecosystem::Npm,
            crate::domain::Ecosystem::PyPI => osv::schema::Ecosystem::PyPI,
            crate::domain::Ecosystem::Maven => osv::schema::Ecosystem::Maven(String::new()),
            crate::domain::Ecosystem::Cargo => osv::schema::Ecosystem::CratesIO,
            crate::domain::Ecosystem::Go => osv::schema::Ecosystem::Go,
            crate::domain::Ecosystem::Packagist => osv::schema::Ecosystem::Packagist,
            crate::domain::Ecosystem::RubyGems => osv::schema::Ecosystem::RubyGems,
            crate::domain::Ecosystem::NuGet => osv::schema::Ecosystem::NuGet,
        }
    }

    /// Convert OSV vulnerability (osv::schema) to RawVulnerability
    fn convert_osv_vulnerability(osv_vuln: osv::schema::Vulnerability) -> RawVulnerability {
        use super::traits::{AffectedPackageData, PackageInfo, VersionEventData, VersionRangeData};
        use osv::schema::{
            Ecosystem as OsvEco, Event as OsvEvent, RangeType as OsvRangeType,
            SeverityType as OsvSevType,
        };

        // Prefer CVSS v4, then v3, then v2; and the fallback to first available
        let severity = osv_vuln
            .severity
            .as_ref()
            .and_then(|severities| {
                severities
                    .iter()
                    .find(|s| matches!(s.severity_type, OsvSevType::CVSSv4))
                    .or_else(|| {
                        severities
                            .iter()
                            .find(|s| matches!(s.severity_type, OsvSevType::CVSSv3))
                    })
                    .or_else(|| {
                        severities
                            .iter()
                            .find(|s| matches!(s.severity_type, OsvSevType::CVSSv2))
                    })
                    .or_else(|| severities.first())
            })
            .map(|s| s.score.clone());

        let references = osv_vuln
            .references
            .unwrap_or_default()
            .into_iter()
            .map(|r| r.url)
            .collect();

        // OSV schema provides RFC3339 DateTime<Utc>
        let published_at = osv_vuln.published;

        let affected_list = osv_vuln.affected;
        let affected = affected_list
            .into_iter()
            .map(|a| {
                // Map ecosystem enum to a string consistent with previous behavior
                let (name, ecosystem, purl) = if let Some(pkg) = a.package {
                    let eco_str = match pkg.ecosystem {
                        OsvEco::Npm => "npm".to_string(),
                        OsvEco::PyPI => "PyPI".to_string(),
                        OsvEco::CratesIO => "crates.io".to_string(),
                        OsvEco::Go => "Go".to_string(),
                        OsvEco::Maven(_) => "Maven".to_string(),
                        OsvEco::Packagist => "Packagist".to_string(),
                        OsvEco::RubyGems => "RubyGems".to_string(),
                        OsvEco::NuGet => "NuGet".to_string(),
                        // Fallback to debug string for unsupported ecosystems
                        other => format!("{:?}", other),
                    };
                    (pkg.name, eco_str, pkg.purl)
                } else {
                    (String::new(), String::new(), None)
                };

                let ranges = a.ranges.map(|ranges| {
                    ranges
                        .into_iter()
                        .map(|range| {
                            let range_type = match range.range_type {
                                OsvRangeType::Ecosystem => "ECOSYSTEM".to_string(),
                                OsvRangeType::Semver => "SEMVER".to_string(),
                                OsvRangeType::Git => "GIT".to_string(),
                                OsvRangeType::Unspecified => "UNSPECIFIED".to_string(),
                                _ => "UNSPECIFIED".to_string(),
                            };
                            let events = range
                                .events
                                .into_iter()
                                .map(|e| match e {
                                    OsvEvent::Introduced(v) => VersionEventData {
                                        event_type: "introduced".to_string(),
                                        value: v,
                                    },
                                    OsvEvent::Fixed(v) => VersionEventData {
                                        event_type: "fixed".to_string(),
                                        value: v,
                                    },
                                    OsvEvent::LastAffected(v) => VersionEventData {
                                        event_type: "last_affected".to_string(),
                                        value: v,
                                    },
                                    OsvEvent::Limit(v) => VersionEventData {
                                        event_type: "limit".to_string(),
                                        value: v,
                                    },
                                    _ => VersionEventData {
                                        event_type: "unknown".to_string(),
                                        value: String::new(),
                                    },
                                })
                                .collect();

                            VersionRangeData {
                                range_type,
                                repo: range.repo,
                                events,
                            }
                        })
                        .collect()
                });

                AffectedPackageData {
                    package: PackageInfo {
                        name,
                        ecosystem,
                        purl,
                    },
                    ranges,
                    versions: a.versions,
                }
            })
            .collect();

        RawVulnerability {
            id: osv_vuln.id,
            summary: osv_vuln.summary.unwrap_or_default(),
            description: osv_vuln.details.unwrap_or_default(),
            severity,
            references,
            published_at,
            affected,
        }
    }
}

#[async_trait]
impl VulnerabilityApiClient for OsvClient {
    async fn query_vulnerabilities(
        &self,
        package: &Package,
    ) -> Result<Vec<RawVulnerability>, VulnerabilityError> {
        let osv_eco = Self::ecosystem_to_osv(&package.ecosystem);
        let version = package.version.to_string();

        let vulns = osv::client::query_package(&package.name, &version, osv_eco)
            .await
            .map_err(|e| {
                VulnerabilityError::Api(ApiError::Http {
                    status: 500,
                    message: format!("OSV client error: {}", e),
                })
            })?
            .unwrap_or_default();

        let vulnerabilities = vulns
            .into_iter()
            .map(Self::convert_osv_vulnerability)
            .collect();

        Ok(vulnerabilities)
    }

    async fn get_vulnerability_details(
        &self,
        id: &str,
    ) -> Result<Option<RawVulnerability>, VulnerabilityError> {
        let osv_vuln = osv::client::vulnerability(id).await.map_err(|e| {
            VulnerabilityError::Api(ApiError::Http {
                status: 500,
                message: format!("OSV client error: {}", e),
            })
        })?;
        Ok(Some(Self::convert_osv_vulnerability(osv_vuln)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Ecosystem;
    use osv::schema::Ecosystem as OsvEco;

    #[tokio::test]
    async fn test_ecosystem_conversion() {
        assert!(matches!(
            OsvClient::ecosystem_to_osv(&Ecosystem::Npm),
            OsvEco::Npm
        ));
        assert!(matches!(
            OsvClient::ecosystem_to_osv(&Ecosystem::PyPI),
            OsvEco::PyPI
        ));
        assert!(matches!(
            OsvClient::ecosystem_to_osv(&Ecosystem::Maven),
            OsvEco::Maven(_)
        ));
        assert!(matches!(
            OsvClient::ecosystem_to_osv(&Ecosystem::Cargo),
            OsvEco::CratesIO
        ));
        assert!(matches!(
            OsvClient::ecosystem_to_osv(&Ecosystem::Go),
            OsvEco::Go
        ));
        assert!(matches!(
            OsvClient::ecosystem_to_osv(&Ecosystem::Packagist),
            OsvEco::Packagist
        ));
        assert!(matches!(
            OsvClient::ecosystem_to_osv(&Ecosystem::RubyGems),
            OsvEco::RubyGems
        ));
        assert!(matches!(
            OsvClient::ecosystem_to_osv(&Ecosystem::NuGet),
            OsvEco::NuGet
        ));
    }
}
