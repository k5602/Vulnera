//! OSV API client implementation

use super::traits::{RawVulnerability, VulnerabilityApiClient};
use crate::application::errors::{ApiError, VulnerabilityError};
use crate::domain::Package;
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Request payload for OSV query endpoint
#[derive(Debug, Serialize)]
struct OsvQueryRequest {
    package: OsvPackage,
}

#[derive(Debug, Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

/// Response from OSV query endpoint
#[derive(Debug, Deserialize)]
struct OsvQueryResponse {
    vulns: Vec<OsvVulnerability>,
}

/// OSV vulnerability data structure
#[derive(Debug, Deserialize)]
struct OsvVulnerability {
    id: String,
    summary: Option<String>,
    details: Option<String>,
    severity: Option<Vec<OsvSeverity>>,
    references: Option<Vec<OsvReference>>,
    published: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    severity_type: String,
    score: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvReference {
    #[serde(rename = "type")]
    #[allow(dead_code)]
    ref_type: String, // Future: reference type categorization
    url: String,
}

/// Client for the OSV (Open Source Vulnerability) API
pub struct OsvClient {
    client: Client,
    base_url: String,
}

impl OsvClient {
    /// Create a new OSV client with the given base URL
    pub fn new(base_url: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("vulnera-rust/0.1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self { client, base_url }
    }

    /// Create a new OSV client with default configuration
    pub fn default() -> Self {
        Self::new("https://api.osv.dev".to_string())
    }

    /// Convert domain ecosystem to OSV ecosystem string
    fn ecosystem_to_osv_string(ecosystem: &crate::domain::Ecosystem) -> &'static str {
        match ecosystem {
            crate::domain::Ecosystem::Npm => "npm",
            crate::domain::Ecosystem::PyPI => "PyPI",
            crate::domain::Ecosystem::Maven => "Maven",
            crate::domain::Ecosystem::Cargo => "crates.io",
            crate::domain::Ecosystem::Go => "Go",
            crate::domain::Ecosystem::Packagist => "Packagist",
            crate::domain::Ecosystem::RubyGems => "RubyGems",
            crate::domain::Ecosystem::NuGet => "NuGet",
        }
    }

    /// Convert OSV vulnerability to RawVulnerability
    fn convert_osv_vulnerability(osv_vuln: OsvVulnerability) -> RawVulnerability {
        let severity = osv_vuln
            .severity
            .as_ref()
            .and_then(|severities| {
                // Look for CVSS severity first, then any other severity
                severities
                    .iter()
                    .find(|s| s.severity_type == "CVSS_V3")
                    .or_else(|| severities.first())
            })
            .and_then(|s| s.score.clone());

        let references = osv_vuln
            .references
            .unwrap_or_default()
            .into_iter()
            .map(|r| r.url)
            .collect();

        let published_at = osv_vuln
            .published
            .and_then(|p| chrono::DateTime::parse_from_rfc3339(&p).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc));

        RawVulnerability {
            id: osv_vuln.id,
            summary: osv_vuln.summary.unwrap_or_default(),
            description: osv_vuln.details.unwrap_or_default(),
            severity,
            references,
            published_at,
        }
    }
}

#[async_trait]
impl VulnerabilityApiClient for OsvClient {
    async fn query_vulnerabilities(
        &self,
        package: &Package,
    ) -> Result<Vec<RawVulnerability>, VulnerabilityError> {
        let ecosystem = Self::ecosystem_to_osv_string(&package.ecosystem);

        let request_payload = OsvQueryRequest {
            package: OsvPackage {
                name: package.name.clone(),
                ecosystem: ecosystem.to_string(),
            },
        };

        let url = format!("{}/v1/query", self.base_url);

        let response = self.client.post(&url).json(&request_payload).send().await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let error_text = response.text().await.unwrap_or_default();
            return Err(VulnerabilityError::Api(ApiError::Http {
                status,
                message: format!("OSV API error: {}", error_text),
            }));
        }

        let osv_response: OsvQueryResponse = response.json().await?;

        let vulnerabilities = osv_response
            .vulns
            .into_iter()
            .map(Self::convert_osv_vulnerability)
            .collect();

        Ok(vulnerabilities)
    }

    async fn get_vulnerability_details(
        &self,
        id: &str,
    ) -> Result<Option<RawVulnerability>, VulnerabilityError> {
        let url = format!("{}/v1/vulns/{}", self.base_url, id);

        let response = self.client.get(&url).send().await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let error_text = response.text().await.unwrap_or_default();
            return Err(VulnerabilityError::Api(ApiError::Http {
                status,
                message: format!("OSV API error: {}", error_text),
            }));
        }

        let osv_vuln: OsvVulnerability = response.json().await?;
        let vulnerability = Self::convert_osv_vulnerability(osv_vuln);

        Ok(Some(vulnerability))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Ecosystem, Version};
    use mockito::Server;
    use serde_json::json;

    fn create_test_package() -> Package {
        Package::new(
            "express".to_string(),
            Version::parse("4.17.1").unwrap(),
            Ecosystem::Npm,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_query_vulnerabilities_success() {
        let mut server = Server::new_async().await;

        let mock_response = json!({
            "vulns": [
                {
                    "id": "OSV-2022-123",
                    "summary": "Test vulnerability",
                    "details": "A test vulnerability for unit testing",
                    "severity": [
                        {
                            "type": "CVSS_V3",
                            "score": "7.5"
                        }
                    ],
                    "references": [
                        {
                            "type": "ADVISORY",
                            "url": "https://example.com/advisory"
                        }
                    ],
                    "published": "2022-01-01T00:00:00Z"
                }
            ]
        });

        let mock = server
            .mock("POST", "/v1/query")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response.to_string())
            .expect(1)
            .create_async()
            .await;

        let client = OsvClient::new(server.url());
        let package = create_test_package();

        let result = client.query_vulnerabilities(&package).await;

        mock.assert_async().await;
        assert!(result.is_ok());

        let vulnerabilities = result.unwrap();
        assert_eq!(vulnerabilities.len(), 1);

        let vuln = &vulnerabilities[0];
        assert_eq!(vuln.id, "OSV-2022-123");
        assert_eq!(vuln.summary, "Test vulnerability");
        assert_eq!(vuln.severity, Some("7.5".to_string()));
        assert_eq!(vuln.references.len(), 1);
        assert!(vuln.published_at.is_some());
    }

    #[tokio::test]
    async fn test_query_vulnerabilities_empty_response() {
        let mut server = Server::new_async().await;

        let mock_response = json!({
            "vulns": []
        });

        let mock = server
            .mock("POST", "/v1/query")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response.to_string())
            .expect(1)
            .create_async()
            .await;

        let client = OsvClient::new(server.url());
        let package = create_test_package();

        let result = client.query_vulnerabilities(&package).await;

        mock.assert_async().await;
        assert!(result.is_ok());

        let vulnerabilities = result.unwrap();
        assert_eq!(vulnerabilities.len(), 0);
    }

    #[tokio::test]
    async fn test_query_vulnerabilities_http_error() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("POST", "/v1/query")
            .with_status(500)
            .with_body("Internal Server Error")
            .expect(1)
            .create_async()
            .await;

        let client = OsvClient::new(server.url());
        let package = create_test_package();

        let result = client.query_vulnerabilities(&package).await;

        mock.assert_async().await;
        assert!(result.is_err());

        match result.unwrap_err() {
            VulnerabilityError::Api(ApiError::Http { status, .. }) => {
                assert_eq!(status, 500);
            }
            _ => panic!("Expected HTTP error"),
        }
    }

    #[tokio::test]
    async fn test_get_vulnerability_details_success() {
        let mut server = Server::new_async().await;

        let mock_response = json!({
            "id": "OSV-2022-123",
            "summary": "Test vulnerability",
            "details": "A test vulnerability for unit testing",
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "7.5"
                }
            ],
            "references": [
                {
                    "type": "ADVISORY",
                    "url": "https://example.com/advisory"
                }
            ],
            "published": "2022-01-01T00:00:00Z"
        });

        let mock = server
            .mock("GET", "/v1/vulns/OSV-2022-123")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response.to_string())
            .expect(1)
            .create_async()
            .await;

        let client = OsvClient::new(server.url());

        let result = client.get_vulnerability_details("OSV-2022-123").await;

        mock.assert_async().await;
        assert!(result.is_ok());

        let vulnerability = result.unwrap();
        assert!(vulnerability.is_some());

        let vuln = vulnerability.unwrap();
        assert_eq!(vuln.id, "OSV-2022-123");
        assert_eq!(vuln.summary, "Test vulnerability");
        assert_eq!(vuln.severity, Some("7.5".to_string()));
    }

    #[tokio::test]
    async fn test_get_vulnerability_details_not_found() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", "/v1/vulns/NONEXISTENT")
            .with_status(404)
            .expect(1)
            .create_async()
            .await;

        let client = OsvClient::new(server.url());

        let result = client.get_vulnerability_details("NONEXISTENT").await;

        mock.assert_async().await;
        assert!(result.is_ok());

        let vulnerability = result.unwrap();
        assert!(vulnerability.is_none());
    }

    #[tokio::test]
    async fn test_ecosystem_conversion() {
        assert_eq!(OsvClient::ecosystem_to_osv_string(&Ecosystem::Npm), "npm");
        assert_eq!(OsvClient::ecosystem_to_osv_string(&Ecosystem::PyPI), "PyPI");
        assert_eq!(
            OsvClient::ecosystem_to_osv_string(&Ecosystem::Maven),
            "Maven"
        );
        assert_eq!(
            OsvClient::ecosystem_to_osv_string(&Ecosystem::Cargo),
            "crates.io"
        );
        assert_eq!(OsvClient::ecosystem_to_osv_string(&Ecosystem::Go), "Go");
        assert_eq!(
            OsvClient::ecosystem_to_osv_string(&Ecosystem::Packagist),
            "Packagist"
        );
        assert_eq!(
            OsvClient::ecosystem_to_osv_string(&Ecosystem::RubyGems),
            "RubyGems"
        );
        assert_eq!(
            OsvClient::ecosystem_to_osv_string(&Ecosystem::NuGet),
            "NuGet"
        );
    }

    #[tokio::test]
    async fn test_request_payload_serialization() {
        let package = create_test_package();
        let ecosystem = OsvClient::ecosystem_to_osv_string(&package.ecosystem);

        let request = OsvQueryRequest {
            package: OsvPackage {
                name: package.name.clone(),
                ecosystem: ecosystem.to_string(),
            },
        };

        let json_str = serde_json::to_string(&request).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["package"]["name"], "express");
        assert_eq!(parsed["package"]["ecosystem"], "npm");
    }
}
