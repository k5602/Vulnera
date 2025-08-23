//! GitHub Security Advisories API client implementation

use super::traits::{RawVulnerability, VulnerabilityApiClient};
use crate::application::errors::{ApiError, VulnerabilityError};
use crate::domain::Package;
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// Task-local request-scoped GHSA token.
// Middleware or handlers can scope a token for the lifetime of a request using
// `with_request_ghsa_token(token, async { ... }).await;`
tokio::task_local! {
    static GHSA_REQ_TOKEN: String;
}

/// Scope a request-scoped GHSA token for the duration of the provided future.
/// Any GHSA client calls within this future (and not crossing a task boundary)
/// will pick up the token via task-local storage.
pub async fn with_request_ghsa_token<F, T>(token: String, fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    GHSA_REQ_TOKEN.scope(token, fut).await
}

/// GraphQL query request structure
#[derive(Debug, Serialize)]
struct GraphQLRequest {
    query: String,
    variables: serde_json::Value,
}

/// GraphQL response structure
#[derive(Debug, Deserialize)]
struct GraphQLResponse<T> {
    data: Option<T>,
    errors: Option<Vec<GraphQLError>>,
}

#[derive(Debug, Deserialize)]
struct GraphQLError {
    message: String,
    #[serde(default)]
    #[allow(dead_code)]
    locations: Vec<GraphQLLocation>, // GraphQL error location info
}

#[derive(Debug, Deserialize)]
struct GraphQLLocation {
    #[allow(dead_code)]
    line: u32, // Line number in GraphQL query
    #[allow(dead_code)]
    column: u32, // Column number in GraphQL query
}

/// Security advisories query response
#[derive(Debug, Deserialize)]
struct SecurityAdvisoriesResponse {
    #[serde(rename = "securityAdvisories")]
    security_advisories: SecurityAdvisoriesConnection,
}

#[derive(Debug, Deserialize)]
pub struct SecurityAdvisoriesConnection {
    nodes: Vec<SecurityAdvisory>,
    #[serde(rename = "pageInfo")]
    page_info: PageInfo,
}

#[derive(Debug, Deserialize)]
struct PageInfo {
    #[serde(rename = "hasNextPage")]
    has_next_page: bool,
    #[serde(rename = "endCursor")]
    end_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SecurityAdvisory {
    #[serde(rename = "ghsaId")]
    ghsa_id: String,
    summary: String,
    description: String,
    severity: String,
    #[serde(rename = "publishedAt")]
    published_at: String,
    references: Vec<Reference>,
    #[allow(dead_code)]
    vulnerabilities: SecurityAdvisoryVulnerabilities, // Future: detailed vulnerability info
}

#[derive(Debug, Deserialize)]
struct Reference {
    url: String,
}

#[derive(Debug, Deserialize)]
struct SecurityAdvisoryVulnerabilities {
    #[allow(dead_code)]
    nodes: Vec<Vulnerability>, // Future: vulnerability nodes processing
}

#[derive(Debug, Deserialize)]
struct Vulnerability {
    #[allow(dead_code)]
    package: VulnerabilityPackage, // Future: package-specific vulnerability details
    #[serde(rename = "vulnerableVersionRange")]
    #[allow(dead_code)]
    vulnerable_version_range: Option<String>, // Future: version range analysis
    #[serde(rename = "firstPatchedVersion")]
    #[allow(dead_code)]
    first_patched_version: Option<FirstPatchedVersion>, // Future: patch version tracking
}

#[derive(Debug, Deserialize)]
struct VulnerabilityPackage {
    #[allow(dead_code)]
    name: String, // Future: package name processing
    #[allow(dead_code)]
    ecosystem: String, // Future: ecosystem-specific logic
}

#[derive(Debug, Deserialize)]
struct FirstPatchedVersion {
    #[allow(dead_code)]
    identifier: String, // Future: patch version identifier processing
}

/// Client for GitHub Security Advisories GraphQL API
pub struct GhsaClient {
    client: Client,
    token: String,
    graphql_url: String,
}

impl GhsaClient {
    /// Create a new GHSA client with the given token and GraphQL URL
    pub fn new(token: String, graphql_url: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("vulnera-rust/0.1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            token,
            graphql_url,
        }
    }

    /// Create a new GHSA client with default configuration
    pub fn default(token: String) -> Self {
        Self::new(token, "https://api.github.com/graphql".to_string())
    }

    /// Convert domain ecosystem to GHSA ecosystem string
    fn ecosystem_to_ghsa_string(ecosystem: &crate::domain::Ecosystem) -> &'static str {
        match ecosystem {
            crate::domain::Ecosystem::Npm => "NPM",
            crate::domain::Ecosystem::PyPI => "PIP",
            crate::domain::Ecosystem::Maven => "MAVEN",
            crate::domain::Ecosystem::Cargo => "RUST",
            crate::domain::Ecosystem::Go => "GO",
            crate::domain::Ecosystem::Packagist => "COMPOSER",
            crate::domain::Ecosystem::RubyGems => "RUBYGEMS",
            crate::domain::Ecosystem::NuGet => "NUGET",
        }
    }

    /// Execute a GraphQL query
    async fn execute_query<T>(
        &self,
        query: &str,
        variables: serde_json::Value,
    ) -> Result<T, VulnerabilityError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let request_body = GraphQLRequest {
            query: query.to_string(),
            variables,
        };

        // Determine token from environment at request time, falling back to configured token
        let token_opt = GHSA_REQ_TOKEN
            .try_with(|t| t.clone())
            .ok()
            .filter(|t| !t.is_empty())
            .or_else(|| {
                if !self.token.is_empty() {
                    Some(self.token.clone())
                } else {
                    None
                }
            });

        // Build request and add Authorization header only if token present
        let mut req = self
            .client
            .post(&self.graphql_url)
            .header("Content-Type", "application/json")
            .json(&request_body);

        if let Some(tok) = token_opt {
            req = req.header("Authorization", format!("Bearer {}", tok));
        } else {
            return Err(VulnerabilityError::Api(ApiError::Http {
                status: 401,
                message: "Missing GitHub token for GHSA lookups; set VULNERA__APIS__GHSA__TOKEN or provide Authorization/X-GHSA-Token".to_string(),
            }));
        }

        let response = req.send().await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let error_text = response.text().await.unwrap_or_default();
            return Err(VulnerabilityError::Api(ApiError::Http {
                status,
                message: format!("GitHub GraphQL API error: {}", error_text),
            }));
        }

        let graphql_response: GraphQLResponse<T> = response.json().await?;

        if let Some(errors) = graphql_response.errors {
            let error_messages: Vec<String> = errors.into_iter().map(|e| e.message).collect();
            return Err(VulnerabilityError::Api(ApiError::Http {
                status: 400,
                message: format!("GraphQL errors: {}", error_messages.join(", ")),
            }));
        }

        graphql_response.data.ok_or_else(|| {
            VulnerabilityError::Api(ApiError::Http {
                status: 500,
                message: "No data in GraphQL response".to_string(),
            })
        })
    }

    /// Query security advisories for a specific package
    pub async fn security_advisories(
        &self,
        package_name: &str,
        ecosystem: &str,
        first: u32,
        after: Option<&str>,
    ) -> Result<SecurityAdvisoriesConnection, VulnerabilityError> {
        let query = r#"
            query SecurityAdvisories($packageName: String!, $ecosystem: SecurityAdvisoryEcosystem!, $first: Int!, $after: String) {
                securityAdvisories(
                    first: $first
                    after: $after
                    orderBy: { field: PUBLISHED_AT, direction: DESC }
                    packageName: $packageName
                    ecosystem: $ecosystem
                ) {
                    nodes {
                        ghsaId
                        summary
                        description
                        severity
                        publishedAt
                        references {
                            url
                        }
                        vulnerabilities(first: 10) {
                            nodes {
                                package {
                                    name
                                    ecosystem
                                }
                                vulnerableVersionRange
                                firstPatchedVersion {
                                    identifier
                                }
                            }
                        }
                    }
                    pageInfo {
                        hasNextPage
                        endCursor
                    }
                }
            }
        "#;

        let mut variables = serde_json::json!({
            "packageName": package_name,
            "ecosystem": ecosystem,
            "first": first
        });

        if let Some(cursor) = after {
            variables["after"] = serde_json::Value::String(cursor.to_string());
        }

        let response: SecurityAdvisoriesResponse = self.execute_query(query, variables).await?;
        Ok(response.security_advisories)
    }

    /// Convert GHSA security advisory to RawVulnerability
    fn convert_ghsa_advisory(advisory: SecurityAdvisory) -> RawVulnerability {
        use super::traits::{AffectedPackageData, PackageInfo, VersionEventData, VersionRangeData};

        let references = advisory.references.into_iter().map(|r| r.url).collect();

        let published_at = chrono::DateTime::parse_from_rfc3339(&advisory.published_at)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc));

        // Map GHSA vulnerabilities to affected package data with fixed events
        let affected = advisory
            .vulnerabilities
            .nodes
            .into_iter()
            .map(|v| {
                // Map GHSA ecosystem values to strings understood by our aggregator
                // NPM -> "npm", PIP -> "PyPI", MAVEN -> "Maven", RUST -> "crates.io",
                // GO -> "Go", COMPOSER -> "Packagist", RUBYGEMS -> "RubyGems", NUGET -> "NuGet"
                let ecosystem = match v.package.ecosystem.as_str() {
                    "NPM" => "npm".to_string(),
                    "PIP" => "PyPI".to_string(),
                    "MAVEN" => "Maven".to_string(),
                    "RUST" => "crates.io".to_string(),
                    "GO" => "Go".to_string(),
                    "COMPOSER" => "Packagist".to_string(),
                    "RUBYGEMS" => "RubyGems".to_string(),
                    "NUGET" => "NuGet".to_string(),
                    other => other.to_string(),
                };

                // Build events: use an "introduced" sentinel when we have a vulnerable range,
                // and add a "fixed" event when firstPatchedVersion is present.
                let mut events: Vec<VersionEventData> = Vec::new();
                if v.vulnerable_version_range.as_ref().is_some() {
                    events.push(VersionEventData {
                        event_type: "introduced".to_string(),
                        value: "0".to_string(), // sentinel lower bound when not explicitly provided
                    });
                }
                if let Some(fp) = v.first_patched_version.as_ref() {
                    events.push(VersionEventData {
                        event_type: "fixed".to_string(),
                        value: fp.identifier.clone(),
                    });
                }

                let ranges = if events.is_empty() {
                    None
                } else {
                    Some(vec![VersionRangeData {
                        range_type: "SEMVER".to_string(),
                        repo: None,
                        events,
                    }])
                };

                AffectedPackageData {
                    package: PackageInfo {
                        name: v.package.name,
                        ecosystem,
                        purl: None,
                    },
                    ranges,
                    versions: None,
                }
            })
            .collect();

        RawVulnerability {
            id: advisory.ghsa_id,
            summary: advisory.summary,
            description: advisory.description,
            severity: Some(advisory.severity),
            references,
            published_at,
            affected,
        }
    }

    /// Get all security advisories for a package with pagination
    async fn get_all_advisories_for_package(
        &self,
        package: &Package,
    ) -> Result<Vec<SecurityAdvisory>, VulnerabilityError> {
        let ecosystem = Self::ecosystem_to_ghsa_string(&package.ecosystem);
        let mut all_advisories = Vec::new();
        let mut cursor: Option<String> = None;
        let page_size = 50; // GitHub's maximum

        loop {
            let connection = self
                .security_advisories(&package.name, ecosystem, page_size, cursor.as_deref())
                .await?;

            all_advisories.extend(connection.nodes);

            if !connection.page_info.has_next_page {
                break;
            }

            cursor = connection.page_info.end_cursor;
        }

        Ok(all_advisories)
    }
}

#[async_trait]
impl VulnerabilityApiClient for GhsaClient {
    async fn query_vulnerabilities(
        &self,
        package: &Package,
    ) -> Result<Vec<RawVulnerability>, VulnerabilityError> {
        let advisories = self.get_all_advisories_for_package(package).await?;

        let vulnerabilities = advisories
            .into_iter()
            .map(Self::convert_ghsa_advisory)
            .collect();

        Ok(vulnerabilities)
    }

    async fn get_vulnerability_details(
        &self,
        id: &str,
    ) -> Result<Option<RawVulnerability>, VulnerabilityError> {
        // GHSA IDs are in format GHSA-xxxx-xxxx-xxxx
        if !id.starts_with("GHSA-") {
            return Ok(None);
        }

        let query = r#"
            query SecurityAdvisory($ghsaId: String!) {
                securityAdvisory(ghsaId: $ghsaId) {
                    ghsaId
                    summary
                    description
                    severity
                    publishedAt
                    references {
                        url
                    }
                    vulnerabilities(first: 10) {
                        nodes {
                            package {
                                name
                                ecosystem
                            }
                            vulnerableVersionRange
                            firstPatchedVersion {
                                identifier
                            }
                        }
                    }
                }
            }
        "#;

        let variables = serde_json::json!({
            "ghsaId": id
        });

        #[derive(Debug, Deserialize)]
        struct SecurityAdvisoryResponse {
            #[serde(rename = "securityAdvisory")]
            security_advisory: Option<SecurityAdvisory>,
        }

        let response: SecurityAdvisoryResponse = self.execute_query(query, variables).await?;

        if let Some(advisory) = response.security_advisory {
            let vulnerability = Self::convert_ghsa_advisory(advisory);
            Ok(Some(vulnerability))
        } else {
            Ok(None)
        }
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
    async fn test_security_advisories_success() {
        let mut server = Server::new_async().await;

        let mock_response = json!({
            "data": {
                "securityAdvisories": {
                    "nodes": [
                        {
                            "ghsaId": "GHSA-xxxx-xxxx-xxxx",
                            "summary": "Test vulnerability",
                            "description": "A test vulnerability for unit testing",
                            "severity": "HIGH",
                            "publishedAt": "2022-01-01T00:00:00Z",
                            "references": [
                                {
                                    "url": "https://example.com/advisory"
                                }
                            ],
                            "vulnerabilities": {
                                "nodes": [
                                    {
                                        "package": {
                                            "name": "express",
                                            "ecosystem": "NPM"
                                        },
                                        "vulnerableVersionRange": "< 4.18.0",
                                        "firstPatchedVersion": {
                                            "identifier": "4.18.0"
                                        }
                                    }
                                ]
                            }
                        }
                    ],
                    "pageInfo": {
                        "hasNextPage": false,
                        "endCursor": null
                    }
                }
            }
        });

        let mock = server
            .mock("POST", "/graphql")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response.to_string())
            .expect(1)
            .create_async()
            .await;

        let client = GhsaClient::new(
            "test-token".to_string(),
            format!("{}/graphql", server.url()),
        );

        let result = client.security_advisories("express", "NPM", 50, None).await;

        mock.assert_async().await;
        assert!(result.is_ok());

        let connection = result.unwrap();
        assert_eq!(connection.nodes.len(), 1);

        let advisory = &connection.nodes[0];
        assert_eq!(advisory.ghsa_id, "GHSA-xxxx-xxxx-xxxx");
        assert_eq!(advisory.summary, "Test vulnerability");
        assert_eq!(advisory.severity, "HIGH");
        assert!(!connection.page_info.has_next_page);
    }

    #[tokio::test]
    async fn test_query_vulnerabilities_success() {
        let mut server = Server::new_async().await;

        let mock_response = json!({
            "data": {
                "securityAdvisories": {
                    "nodes": [
                        {
                            "ghsaId": "GHSA-xxxx-xxxx-xxxx",
                            "summary": "Test vulnerability",
                            "description": "A test vulnerability for unit testing",
                            "severity": "HIGH",
                            "publishedAt": "2022-01-01T00:00:00Z",
                            "references": [
                                {
                                    "url": "https://example.com/advisory"
                                }
                            ],
                            "vulnerabilities": {
                                "nodes": []
                            }
                        }
                    ],
                    "pageInfo": {
                        "hasNextPage": false,
                        "endCursor": null
                    }
                }
            }
        });

        let mock = server
            .mock("POST", "/graphql")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response.to_string())
            .expect(1)
            .create_async()
            .await;

        let client = GhsaClient::new(
            "test-token".to_string(),
            format!("{}/graphql", server.url()),
        );
        let package = create_test_package();

        let result = client.query_vulnerabilities(&package).await;

        mock.assert_async().await;
        assert!(result.is_ok());

        let vulnerabilities = result.unwrap();
        assert_eq!(vulnerabilities.len(), 1);

        let vuln = &vulnerabilities[0];
        assert_eq!(vuln.id, "GHSA-xxxx-xxxx-xxxx");
        assert_eq!(vuln.summary, "Test vulnerability");
        assert_eq!(vuln.severity, Some("HIGH".to_string()));
        assert_eq!(vuln.references.len(), 1);
        assert!(vuln.published_at.is_some());
    }

    #[tokio::test]
    async fn test_get_vulnerability_details_success() {
        let mut server = Server::new_async().await;

        let mock_response = json!({
            "data": {
                "securityAdvisory": {
                    "ghsaId": "GHSA-xxxx-xxxx-xxxx",
                    "summary": "Test vulnerability",
                    "description": "A test vulnerability for unit testing",
                    "severity": "HIGH",
                    "publishedAt": "2022-01-01T00:00:00Z",
                    "references": [
                        {
                            "url": "https://example.com/advisory"
                        }
                    ],
                    "vulnerabilities": {
                        "nodes": []
                    }
                }
            }
        });

        let mock = server
            .mock("POST", "/graphql")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response.to_string())
            .expect(1)
            .create_async()
            .await;

        let client = GhsaClient::new(
            "test-token".to_string(),
            format!("{}/graphql", server.url()),
        );

        let result = client
            .get_vulnerability_details("GHSA-xxxx-xxxx-xxxx")
            .await;

        mock.assert_async().await;
        assert!(result.is_ok());

        let vulnerability = result.unwrap();
        assert!(vulnerability.is_some());

        let vuln = vulnerability.unwrap();
        assert_eq!(vuln.id, "GHSA-xxxx-xxxx-xxxx");
        assert_eq!(vuln.summary, "Test vulnerability");
        assert_eq!(vuln.severity, Some("HIGH".to_string()));
    }

    #[tokio::test]
    async fn test_get_vulnerability_details_not_found() {
        let mut server = Server::new_async().await;

        let mock_response = json!({
            "data": {
                "securityAdvisory": null
            }
        });

        let mock = server
            .mock("POST", "/graphql")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response.to_string())
            .expect(1)
            .create_async()
            .await;

        let client = GhsaClient::new(
            "test-token".to_string(),
            format!("{}/graphql", server.url()),
        );

        let result = client
            .get_vulnerability_details("GHSA-nonexistent-xxxx")
            .await;

        mock.assert_async().await;
        assert!(result.is_ok());

        let vulnerability = result.unwrap();
        assert!(vulnerability.is_none());
    }

    #[tokio::test]
    async fn test_get_vulnerability_details_invalid_id() {
        let client = GhsaClient::new(
            "test-token".to_string(),
            "https://api.github.com/graphql".to_string(),
        );

        let result = client.get_vulnerability_details("CVE-2022-24999").await;

        assert!(result.is_ok());
        let vulnerability = result.unwrap();
        assert!(vulnerability.is_none());
    }

    #[tokio::test]
    async fn test_security_advisories_requires_token() {
        let server = Server::new_async().await;

        // Minimal GraphQL error response isn't needed; client returns 401 before calling server
        let client = GhsaClient::new("".to_string(), format!("{}/graphql", server.url()));

        let result = client.security_advisories("express", "NPM", 1, None).await;

        // Expect a 401 error due to missing token
        assert!(result.is_err());
        match result.unwrap_err() {
            VulnerabilityError::Api(ApiError::Http { status, message }) => {
                assert_eq!(status, 401);
                assert!(
                    message.contains("Missing GitHub token"),
                    "unexpected message: {}",
                    message
                );
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_with_request_scoped_token_applies_authorization_header() {
        let mut server = Server::new_async().await;

        let mock_response = json!({
            "data": {
                "securityAdvisories": {
                    "nodes": [],
                    "pageInfo": {
                        "hasNextPage": false,
                        "endCursor": null
                    }
                }
            }
        });

        let mock = server
            .mock("POST", "/graphql")
            .match_header("authorization", "Bearer scoped-token-123")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response.to_string())
            .expect(1)
            .create_async()
            .await;

        let client = GhsaClient::new("".to_string(), format!("{}/graphql", server.url()));

        let result = crate::infrastructure::api_clients::ghsa::with_request_ghsa_token(
            "scoped-token-123".to_string(),
            async { client.security_advisories("express", "NPM", 1, None).await },
        )
        .await;

        mock.assert_async().await;
        assert!(result.is_ok());
        let connection = result.unwrap();
        assert_eq!(connection.nodes.len(), 0);
        assert!(!connection.page_info.has_next_page);
    }

    #[tokio::test]
    async fn test_graphql_error_handling() {
        let mut server = Server::new_async().await;

        let mock_response = json!({
            "errors": [
                {
                    "message": "Field 'invalidField' doesn't exist on type 'Query'",
                    "locations": [
                        {
                            "line": 2,
                            "column": 3
                        }
                    ]
                }
            ]
        });

        let mock = server
            .mock("POST", "/graphql")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response.to_string())
            .expect(1)
            .create_async()
            .await;

        let client = GhsaClient::new(
            "test-token".to_string(),
            format!("{}/graphql", server.url()),
        );

        let result = client.security_advisories("express", "NPM", 50, None).await;

        mock.assert_async().await;
        assert!(result.is_err());

        match result.unwrap_err() {
            VulnerabilityError::Api(ApiError::Http { message, .. }) => {
                assert!(message.contains("GraphQL errors"));
                assert!(message.contains("Field 'invalidField' doesn't exist"));
            }
            _ => panic!("Expected GraphQL error"),
        }
    }

    #[test]
    fn test_ecosystem_conversion() {
        assert_eq!(GhsaClient::ecosystem_to_ghsa_string(&Ecosystem::Npm), "NPM");
        assert_eq!(
            GhsaClient::ecosystem_to_ghsa_string(&Ecosystem::PyPI),
            "PIP"
        );
        assert_eq!(
            GhsaClient::ecosystem_to_ghsa_string(&Ecosystem::Maven),
            "MAVEN"
        );
        assert_eq!(
            GhsaClient::ecosystem_to_ghsa_string(&Ecosystem::Cargo),
            "RUST"
        );
        assert_eq!(GhsaClient::ecosystem_to_ghsa_string(&Ecosystem::Go), "GO");
        assert_eq!(
            GhsaClient::ecosystem_to_ghsa_string(&Ecosystem::Packagist),
            "COMPOSER"
        );
        assert_eq!(
            GhsaClient::ecosystem_to_ghsa_string(&Ecosystem::RubyGems),
            "RUBYGEMS"
        );
        assert_eq!(
            GhsaClient::ecosystem_to_ghsa_string(&Ecosystem::NuGet),
            "NUGET"
        );
    }

    #[test]
    fn test_convert_ghsa_advisory() {
        let advisory = SecurityAdvisory {
            ghsa_id: "GHSA-xxxx-xxxx-xxxx".to_string(),
            summary: "Test vulnerability".to_string(),
            description: "A test vulnerability for unit testing".to_string(),
            severity: "HIGH".to_string(),
            published_at: "2022-01-01T00:00:00Z".to_string(),
            references: vec![Reference {
                url: "https://example.com".to_string(),
            }],
            vulnerabilities: SecurityAdvisoryVulnerabilities { nodes: vec![] },
        };

        let raw_vuln = GhsaClient::convert_ghsa_advisory(advisory);

        assert_eq!(raw_vuln.id, "GHSA-xxxx-xxxx-xxxx");
        assert_eq!(raw_vuln.summary, "Test vulnerability");
        assert_eq!(
            raw_vuln.description,
            "A test vulnerability for unit testing"
        );
        assert_eq!(raw_vuln.severity, Some("HIGH".to_string()));
        assert_eq!(raw_vuln.references.len(), 1);
        assert!(raw_vuln.published_at.is_some());
    }
}
