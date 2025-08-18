//! NVD API client implementation

use super::traits::{RawVulnerability, VulnerabilityApiClient};
use crate::application::errors::{ApiError, VulnerabilityError};
use crate::domain::Package;
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Rate limiter for NVD API requests
#[derive(Debug)]
pub struct RateLimiter {
    /// Maximum number of requests allowed in the time window
    max_requests: u32,
    /// Time window for rate limiting (in seconds)
    window_seconds: u64,
    /// Request timestamps within the current window
    request_times: Arc<Mutex<Vec<Instant>>>,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(max_requests: u32, window_seconds: u64) -> Self {
        Self {
            max_requests,
            window_seconds,
            request_times: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Create rate limiter for NVD without API key (5 requests per 30 seconds)
    pub fn without_api_key() -> Self {
        Self::new(5, 30)
    }

    /// Create rate limiter for NVD with API key (50 requests per 30 seconds)
    pub fn with_api_key() -> Self {
        Self::new(50, 30)
    }

    /// Wait until a request can be made according to rate limits
    pub async fn wait_for_request(&self) -> Result<(), VulnerabilityError> {
        loop {
            let mut times = self.request_times.lock().await;
            let now = Instant::now();
            let window_start = now - Duration::from_secs(self.window_seconds);

            // Remove requests outside the current window
            times.retain(|&time| time > window_start);

            // Check if we can make a request
            if times.len() >= self.max_requests as usize {
                // Calculate how long to wait
                let oldest_request = times[0];
                let wait_until = oldest_request + Duration::from_secs(self.window_seconds);
                let wait_duration = wait_until.saturating_duration_since(now);

                if wait_duration > Duration::ZERO {
                    drop(times); // Release the lock before sleeping
                    tokio::time::sleep(wait_duration).await;
                    continue; // Try again after waiting
                }
            }

            // Record this request and exit
            times.push(now);
            break;
        }
        Ok(())
    }
}

/// NVD API response for CVE search
#[derive(Debug, Deserialize)]
struct NvdSearchResponse {
    #[serde(rename = "vulnerabilities")]
    vulnerabilities: Vec<NvdVulnerabilityWrapper>,
    #[serde(rename = "totalResults")]
    total_results: u32,
}

#[derive(Debug, Deserialize)]
struct NvdVulnerabilityWrapper {
    cve: NvdCve,
}

#[derive(Debug, Deserialize)]
struct NvdCve {
    id: String,
    #[serde(rename = "sourceIdentifier")]
    source_identifier: Option<String>,
    published: Option<String>,
    #[serde(rename = "lastModified")]
    last_modified: Option<String>,
    #[serde(rename = "vulnStatus")]
    vuln_status: Option<String>,
    descriptions: Option<Vec<NvdDescription>>,
    metrics: Option<NvdMetrics>,
    references: Option<Vec<NvdReference>>,
}

#[derive(Debug, Deserialize)]
struct NvdDescription {
    lang: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct NvdMetrics {
    #[serde(rename = "cvssMetricV31")]
    cvss_v31: Option<Vec<NvdCvssMetric>>,
    #[serde(rename = "cvssMetricV30")]
    cvss_v30: Option<Vec<NvdCvssMetric>>,
    #[serde(rename = "cvssMetricV2")]
    cvss_v2: Option<Vec<NvdCvssMetricV2>>,
}

#[derive(Debug, Deserialize)]
struct NvdCvssMetric {
    source: String,
    #[serde(rename = "type")]
    metric_type: String,
    #[serde(rename = "cvssData")]
    cvss_data: NvdCvssData,
}

#[derive(Debug, Deserialize)]
struct NvdCvssMetricV2 {
    source: String,
    #[serde(rename = "type")]
    metric_type: String,
    #[serde(rename = "cvssData")]
    cvss_data: NvdCvssDataV2,
}

#[derive(Debug, Deserialize)]
struct NvdCvssData {
    version: String,
    #[serde(rename = "baseScore")]
    base_score: f64,
    #[serde(rename = "baseSeverity")]
    base_severity: String,
}

#[derive(Debug, Deserialize)]
struct NvdCvssDataV2 {
    version: String,
    #[serde(rename = "baseScore")]
    base_score: f64,
}

#[derive(Debug, Deserialize)]
struct NvdReference {
    url: String,
    source: Option<String>,
}

/// Client for the NVD (National Vulnerability Database) API
pub struct NvdClient {
    client: Client,
    base_url: String,
    api_key: Option<String>,
    rate_limiter: RateLimiter,
}

impl NvdClient {
    /// Create a new NVD client with the given configuration
    pub fn new(base_url: String, api_key: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("vulnera-rust/0.1.0")
            .build()
            .expect("Failed to create HTTP client");

        let rate_limiter = if api_key.is_some() {
            RateLimiter::with_api_key()
        } else {
            RateLimiter::without_api_key()
        };

        Self {
            client,
            base_url,
            api_key,
            rate_limiter,
        }
    }

    /// Create a new NVD client with default configuration
    pub fn default() -> Self {
        Self::new("https://services.nvd.nist.gov/rest/json".to_string(), None)
    }

    /// Create a new NVD client with API key
    pub fn with_api_key(api_key: String) -> Self {
        Self::new(
            "https://services.nvd.nist.gov/rest/json".to_string(),
            Some(api_key),
        )
    }

    /// Search for CVEs using keyword search
    pub async fn search_cves(
        &self,
        keyword: &str,
    ) -> Result<Vec<RawVulnerability>, VulnerabilityError> {
        self.rate_limiter.wait_for_request().await?;

        let url = format!("{}/cves/2.0", self.base_url);
        let query_params = vec![
            ("keywordSearch", keyword),
            ("resultsPerPage", "50"), // Maximum allowed by NVD
        ];

        let mut request = self.client.get(&url);

        // Add query parameters
        for (key, value) in query_params {
            request = request.query(&[(key, value)]);
        }

        // Add API key if available
        if let Some(ref api_key) = self.api_key {
            request = request.header("apiKey", api_key);
        }

        let response = self.execute_with_retry(request).await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let error_text = response.text().await.unwrap_or_default();
            return Err(VulnerabilityError::Api(ApiError::Http {
                status,
                message: format!("NVD API error: {}", error_text),
            }));
        }

        let nvd_response: NvdSearchResponse = response.json().await?;

        let vulnerabilities = nvd_response
            .vulnerabilities
            .into_iter()
            .map(|wrapper| Self::convert_nvd_vulnerability(wrapper.cve))
            .collect();

        Ok(vulnerabilities)
    }

    /// Execute request with exponential backoff retry logic
    async fn execute_with_retry(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, VulnerabilityError> {
        let mut attempts = 0;
        let max_attempts = 3;
        let mut delay = Duration::from_millis(1000);

        loop {
            attempts += 1;

            // Clone the request for retry attempts
            let req = request.try_clone().ok_or_else(|| {
                VulnerabilityError::Api(ApiError::Http {
                    status: 0,
                    message: "Failed to clone request for retry".to_string(),
                })
            })?;

            match req.send().await {
                Ok(response) => {
                    // Check for rate limiting or server errors that should be retried
                    if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS
                        || response.status() == reqwest::StatusCode::INTERNAL_SERVER_ERROR
                        || response.status() == reqwest::StatusCode::BAD_GATEWAY
                        || response.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE
                        || response.status() == reqwest::StatusCode::GATEWAY_TIMEOUT
                    {
                        if attempts >= max_attempts {
                            return Ok(response); // Return the error response
                        }

                        tokio::time::sleep(delay).await;
                        delay *= 2; // Exponential backoff
                        continue;
                    }

                    return Ok(response);
                }
                Err(e) => {
                    if attempts >= max_attempts {
                        return Err(VulnerabilityError::Network(e));
                    }

                    tokio::time::sleep(delay).await;
                    delay *= 2; // Exponential backoff
                }
            }
        }
    }

    /// Convert NVD CVE to RawVulnerability
    fn convert_nvd_vulnerability(nvd_cve: NvdCve) -> RawVulnerability {
        // Extract description (prefer English)
        let description = nvd_cve
            .descriptions
            .as_ref()
            .and_then(|descriptions| {
                descriptions
                    .iter()
                    .find(|desc| desc.lang == "en")
                    .or_else(|| descriptions.first())
            })
            .map(|desc| desc.value.clone())
            .unwrap_or_default();

        // Extract CVSS score and severity
        let severity = nvd_cve.metrics.as_ref().and_then(|metrics| {
            // Prefer CVSS v3.1, then v3.0, then v2
            metrics
                .cvss_v31
                .as_ref()
                .and_then(|v31| v31.first())
                .map(|metric| metric.cvss_data.base_score.to_string())
                .or_else(|| {
                    metrics
                        .cvss_v30
                        .as_ref()
                        .and_then(|v30| v30.first())
                        .map(|metric| metric.cvss_data.base_score.to_string())
                })
                .or_else(|| {
                    metrics
                        .cvss_v2
                        .as_ref()
                        .and_then(|v2| v2.first())
                        .map(|metric| metric.cvss_data.base_score.to_string())
                })
        });

        // Extract references
        let references = nvd_cve
            .references
            .unwrap_or_default()
            .into_iter()
            .map(|r| r.url)
            .collect();

        // Parse published date - NVD uses ISO-8601 format
        let published_at = nvd_cve
            .published
            .and_then(|p| {
                // Try parsing with different ISO-8601 formats that NVD uses
                chrono::DateTime::parse_from_rfc3339(&p)
                    .or_else(|_| {
                        // Try with Z suffix (UTC) - with milliseconds
                        chrono::DateTime::parse_from_str(&p, "%Y-%m-%dT%H:%M:%S%.3fZ")
                    })
                    .or_else(|_| {
                        // Try with Z suffix (UTC) - without milliseconds
                        chrono::DateTime::parse_from_str(&p, "%Y-%m-%dT%H:%M:%SZ")
                    })
                    .or_else(|_| {
                        // Try without timezone info, assume UTC
                        chrono::NaiveDateTime::parse_from_str(&p, "%Y-%m-%dT%H:%M:%S%.3f")
                            .or_else(|_| {
                                chrono::NaiveDateTime::parse_from_str(&p, "%Y-%m-%dT%H:%M:%S")
                            })
                            .map(|dt| dt.and_utc().fixed_offset())
                    })
                    .ok()
            })
            .map(|dt| dt.with_timezone(&chrono::Utc));

        RawVulnerability {
            id: nvd_cve.id,
            summary: description.clone(), // NVD doesn't separate summary from description
            description,
            severity,
            references,
            published_at,
        }
    }
}

#[async_trait]
impl VulnerabilityApiClient for NvdClient {
    async fn query_vulnerabilities(
        &self,
        package: &Package,
    ) -> Result<Vec<RawVulnerability>, VulnerabilityError> {
        // Search for vulnerabilities using package name as keyword
        self.search_cves(&package.name).await
    }

    async fn get_vulnerability_details(
        &self,
        id: &str,
    ) -> Result<Option<RawVulnerability>, VulnerabilityError> {
        self.rate_limiter.wait_for_request().await?;
        let url = format!("{}/cves/2.0", self.base_url);
        let mut request = self.client.get(&url).query(&[("cveId", id)]);

        // Add API key if available
        if let Some(ref api_key) = self.api_key {
            request = request.header("apiKey", api_key);
        }

        let response = self.execute_with_retry(request).await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let error_text = response.text().await.unwrap_or_default();
            return Err(VulnerabilityError::Api(ApiError::Http {
                status,
                message: format!("NVD API error: {}", error_text),
            }));
        }

        let nvd_response: NvdSearchResponse = response.json().await?;

        if let Some(wrapper) = nvd_response.vulnerabilities.into_iter().next() {
            let vulnerability = Self::convert_nvd_vulnerability(wrapper.cve);
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
    use mockito::{Matcher, Server};
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
    async fn test_rate_limiter_without_api_key() {
        let rate_limiter = RateLimiter::without_api_key();

        // Should allow 5 requests quickly
        for _ in 0..5 {
            let result = rate_limiter.wait_for_request().await;
            assert!(result.is_ok());
        }

        // The 6th request should be delayed, but i won't wait for it in the test
        // I will just use it to verify the rate limiter structure is correct
        assert_eq!(rate_limiter.max_requests, 5);
        assert_eq!(rate_limiter.window_seconds, 30);
    }

    #[tokio::test]
    async fn test_rate_limiter_with_api_key() {
        let rate_limiter = RateLimiter::with_api_key();

        assert_eq!(rate_limiter.max_requests, 50);
        assert_eq!(rate_limiter.window_seconds, 30);
    }

    #[tokio::test]
    async fn test_search_cves_success() {
        let mut server = Server::new_async().await;

        let mock_response = json!({
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2022-24999",
                        "sourceIdentifier": "cve@mitre.org",
                        "published": "2022-01-01T00:00:00.000Z",
                        "lastModified": "2022-01-02T00:00:00.000Z",
                        "vulnStatus": "Analyzed",
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "A test vulnerability for unit testing"
                            }
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "source": "nvd@nist.gov",
                                    "type": "Primary",
                                    "cvssData": {
                                        "version": "3.1",
                                        "baseScore": 7.5,
                                        "baseSeverity": "HIGH"
                                    }
                                }
                            ]
                        },
                        "references": [
                            {
                                "url": "https://example.com/advisory",
                                "source": "example.com"
                            }
                        ]
                    }
                }
            ],
            "totalResults": 1
        });

        let mock = server
            .mock("GET", "/cves/2.0")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("keywordSearch".into(), "express".into()),
                mockito::Matcher::UrlEncoded("resultsPerPage".into(), "50".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response.to_string())
            .expect(1)
            .create_async()
            .await;

        let client = NvdClient::new(server.url(), None);

        let result = client.search_cves("express").await;

        mock.assert_async().await;
        assert!(result.is_ok());

        let vulnerabilities = result.unwrap();
        assert_eq!(vulnerabilities.len(), 1);

        let vuln = &vulnerabilities[0];
        assert_eq!(vuln.id, "CVE-2022-24999");
        assert_eq!(vuln.description, "A test vulnerability for unit testing");
        assert_eq!(vuln.severity, Some("7.5".to_string()));
        assert_eq!(vuln.references.len(), 1);
        assert!(vuln.published_at.is_some());
    }

    #[tokio::test]
    async fn test_search_cves_empty_response() {
        let mut server = Server::new_async().await;

        let mock_response = json!({
            "vulnerabilities": [],
            "totalResults": 0
        });

        let mock = server
            .mock("GET", "/cves/2.0")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("keywordSearch".into(), "nonexistent".into()),
                mockito::Matcher::UrlEncoded("resultsPerPage".into(), "50".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response.to_string())
            .expect(1)
            .create_async()
            .await;

        let client = NvdClient::new(server.url(), None);

        let result = client.search_cves("nonexistent").await;

        mock.assert_async().await;
        assert!(result.is_ok());

        let vulnerabilities = result.unwrap();
        assert_eq!(vulnerabilities.len(), 0);
    }

    #[tokio::test]
    async fn test_get_vulnerability_details_success() {
        let mut server = Server::new_async().await;

        let mock_response = json!({
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2022-24999",
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "A test vulnerability for unit testing"
                            }
            ],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "source": "nvd@nist.gov",
                                    "type": "Primary",
                                    "cvssData": {
                                        "version": "3.1",
                                        "baseScore": 7.5,
                                        "baseSeverity": "HIGH"
                               }
                                }
                            ]
                        },
                        "references": [
                            {
                                "url": "https://example.com/advisory"
                            }
                        ],
                        "published": "2022-01-01T00:00:00.000Z"
                    }
                }
            ],
            "totalResults": 1
        });

        let mock = server
            .mock("GET", "/cves/2.0")
            .match_query(mockito::Matcher::UrlEncoded(
                "cveId".into(),
                "CVE-2022-24999".into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response.to_string())
            .expect(1)
            .create_async()
            .await;

        let client = NvdClient::new(server.url(), None);

        let result = client.get_vulnerability_details("CVE-2022-24999").await;

        mock.assert_async().await;
        assert!(result.is_ok());

        let vulnerability = result.unwrap();
        assert!(vulnerability.is_some());

        let vuln = vulnerability.unwrap();
        assert_eq!(vuln.id, "CVE-2022-24999");
        assert_eq!(vuln.description, "A test vulnerability for unit testing");
        assert_eq!(vuln.severity, Some("7.5".to_string()));
    }

    #[tokio::test]
    async fn test_get_vulnerability_details_not_found() {
        let mut server = Server::new_async().await;

        let mock_response = json!({
            "vulnerabilities": [],
            "totalResults": 0
        });

        let mock = server
            .mock("GET", "/cves/2.0")
            .match_query(mockito::Matcher::UrlEncoded(
                "cveId".into(),
                "CVE-NONEXISTENT".into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response.to_string())
            .expect(1)
            .create_async()
            .await;

        let client = NvdClient::new(server.url(), None);

        let result = client.get_vulnerability_details("CVE-NONEXISTENT").await;

        mock.assert_async().await;
        assert!(result.is_ok());

        let vulnerability = result.unwrap();
        assert!(vulnerability.is_none());
    }

    #[tokio::test]
    async fn test_query_vulnerabilities_via_trait() {
        let mut server = Server::new_async().await;

        let mock_response = json!({
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2022-24999",
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "Express vulnerability"
                            }
                        ]
                    }
                }
            ],
            "totalResults": 1
        });

        let mock = server
            .mock("GET", "/cves/2.0")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("keywordSearch".into(), "express".into()),
                mockito::Matcher::UrlEncoded("resultsPerPage".into(), "50".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response.to_string())
            .expect(1)
            .create_async()
            .await;

        let client = NvdClient::new(server.url(), None);
        let package = create_test_package();

        let result = client.query_vulnerabilities(&package).await;

        mock.assert_async().await;
        assert!(result.is_ok());

        let vulnerabilities = result.unwrap();
        assert_eq!(vulnerabilities.len(), 1);
        assert_eq!(vulnerabilities[0].id, "CVE-2022-24999");
    }

    #[tokio::test]
    async fn test_client_with_api_key() {
        let client = NvdClient::with_api_key("test-api-key".to_string());
        assert_eq!(client.api_key, Some("test-api-key".to_string()));
        assert_eq!(client.rate_limiter.max_requests, 50); // With API key
    }

    #[tokio::test]
    async fn test_client_without_api_key() {
        let client = NvdClient::default();
        assert_eq!(client.api_key, None);
        assert_eq!(client.rate_limiter.max_requests, 5); // Without API key
    }

    #[test]
    fn test_convert_nvd_vulnerability() {
        let nvd_cve = NvdCve {
            id: "CVE-2022-24999".to_string(),
            source_identifier: Some("cve@mitre.org".to_string()),
            published: Some("2022-01-01T00:00:00.000Z".to_string()),
            last_modified: Some("2022-01-02T00:00:00.000".to_string()),
            vuln_status: Some("Analyzed".to_string()),
            descriptions: Some(vec![NvdDescription {
                lang: "en".to_string(),
                value: "Test vulnerability".to_string(),
            }]),
            metrics: Some(NvdMetrics {
                cvss_v31: Some(vec![NvdCvssMetric {
                    source: "nvd@nist.gov".to_string(),
                    metric_type: "Primary".to_string(),
                    cvss_data: NvdCvssData {
                        version: "3.1".to_string(),
                        base_score: 7.5,
                        base_severity: "HIGH".to_string(),
                    },
                }]),
                cvss_v30: None,
                cvss_v2: None,
            }),
            references: Some(vec![NvdReference {
                url: "https://example.com".to_string(),
                source: Some("example.com".to_string()),
            }]),
        };

        let raw_vuln = NvdClient::convert_nvd_vulnerability(nvd_cve);

        assert_eq!(raw_vuln.id, "CVE-2022-24999");
        assert_eq!(raw_vuln.description, "Test vulnerability");
        assert_eq!(raw_vuln.severity, Some("7.5".to_string()));
        assert_eq!(raw_vuln.references.len(), 1);
        assert!(raw_vuln.published_at.is_some());
    }
}
