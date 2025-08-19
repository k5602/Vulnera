//! GitHub Security Advisories API client implementation

use super::traits::{RawVulnerability, VulnerabilityApiClient};
use crate::application::errors::{ApiError, VulnerabilityError};
use crate::domain::Package;
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

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
    locations: Vec<GraphQLLocation>,
}

#[derive(Debug, Deserialize)]
struct GraphQLLocation {
    #[allow(dead_code)]
    line: u32,
    #[allow(dead_code)]
    column: u32,
}

/// Security advisories query response
#[derive(Debug, Deserialize)]
struct SecurityAdvisoriesResponse {
    #[serde(rename = "securityAdvisories")]
    security_advisories: SecurityAdvisoriesConnection,
}

#[derive(Debug, Deserialize)]
pub struct SecurityAdvisoriesConnection {
    pub nodes: Vec<SecurityAdvisory>,
    #[serde(rename = "pageInfo")]
    pub page_info: PageInfo,
}

#[derive(Debug, Deserialize)]
pub struct PageInfo {
    #[serde(rename = "hasNextPage")]
    pub has_next_page: bool,
    #[serde(rename = "endCursor")]
    pub end_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SecurityAdvisory {
    #[serde(rename = "ghsaId")]
    ghsa_id: String,
    summary: String,
    description: String,
    severity: String,
    #[serde(rename = "publishedAt")]
    published_at: String,
    references: Vec<Reference>,
    #[allow(dead_code)]
    vulnerabilities: SecurityAdvisoryVulnerabilities,
}

#[derive(Debug, Deserialize)]
struct Reference {
    url: String,
}

#[derive(Debug, Deserialize)]
struct SecurityAdvisoryVulnerabilities {
    #[allow(dead_code)]
    nodes: Vec<Vulnerability>,
}

#[derive(Debug, Deserialize)]
struct Vulnerability {
    #[allow(dead_code)]
    package: VulnerabilityPackage,
    #[serde(rename = "vulnerableVersionRange")]
    #[allow(dead_code)]
    vulnerable_version_range: Option<String>,
    #[serde(rename = "firstPatchedVersion")]
    #[allow(dead_code)]
    first_patched_version: Option<FirstPatchedVersion>,
}

#[derive(Debug, Deserialize)]
struct VulnerabilityPackage {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct FirstPatchedVersion {
    #[allow(dead_code)]
    identifier: String,
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

        let response = self
            .client
            .post(&self.graphql_url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await?;

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
        let references = advisory.references.into_iter().map(|r| r.url).collect();

        let published_at = chrono::DateTime::parse_from_rfc3339(&advisory.published_at)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc));

        RawVulnerability {
            id: advisory.ghsa_id,
            summary: advisory.summary,
            description: advisory.description,
            severity: Some(advisory.severity),
            references,
            published_at,
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
