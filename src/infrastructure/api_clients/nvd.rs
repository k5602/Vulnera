use super::traits::{RawVulnerability, VulnerabilityApiClient};
use crate::application::errors::{ApiError, VulnerabilityError};
use crate::domain::Package;
use async_trait::async_trait;
use chrono::{Datelike, Utc};
use nvd_cve::client::BlockingHttpClient;
use nvd_cve::{
    cache::{CacheConfig, search_by_id, search_description, sync_blocking},
    client::ReqwestBlockingClient,
    cve::CveFeed,
};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use tokio::task;
use tokio::time::sleep;

/// NVD client backed by a local `nvd_cve` SQLite cache.
/// - The cache database is placed inside the configured cache directory:
/// - Uses env var VULNERA__CACHE__DIRECTORY if set, otherwise defaults to ".vulnera_cache".
/// - On first use (if db missing) it will sync the NVD feeds locally using a blocking reqwest client
/// - on a blocking thread to avoid stalling the async runtime.
pub struct NvdClient {
    /// Mirror base for NVD CVE 1.1 feeds
    feed_base_url: String,
    /// REST base for NVD JSON API v2.0
    rest_base_url: String,
    /// Absolute path to the SQLite database file managed by `nvd_cve`
    db_path: PathBuf,
    /// Feed names to sync
    feeds: Vec<String>,
    /// Show sync progress
    show_progress: bool,
    /// Path to sidecar CVSS index mapping (id -> base score)
    cvss_index_path: PathBuf,
    /// Optional NVD API key for REST requests (higher rate limits when present)
    api_key: Option<String>,
}

impl NvdClient {
    /// Construct a new NVD client.
    ///
    /// The `base_url` parameter is treated as the NVD CVE 1.1 feeds base if it looks like a feed root.
    /// If a REST API URL (e.g., "https://services.nvd.nist.gov/rest/json") is provided, REST base will
    /// be taken from it while the feeds base falls back to the official 1.1 feeds mirror.
    ///
    /// If `api_key` is not provided, VULNERA__APIS__NVD__API_KEY will be used when present to unlock higher REST rate limits.
    pub fn new(base_url: String, api_key: Option<String>) -> Self {
        // Determine cache directory
        let cache_dir = std::env::var("VULNERA__CACHE__DIRECTORY")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(".vulnera_cache"));

        // Ensure cache directory exists (sync at construction time is fine)
        if let Err(e) = std::fs::create_dir_all(&cache_dir) {
            tracing::warn!(error=?e, dir=?cache_dir, "Failed to create cache directory, continuing");
        }

        // Compute feeds base and REST base
        // nvd_cve expects the 1.1 feed base url; if we were passed the REST API URL, replace it
        let (feed_base_url, rest_base_url) = if base_url.contains("/rest/json") {
            (
                "https://nvd.nist.gov/feeds/json/cve/1.1".to_string(),
                base_url,
            )
        } else {
            (
                base_url,
                "https://services.nvd.nist.gov/rest/json".to_string(),
            )
        };

        let db_path = cache_dir.join("nvd_cve.sqlite");

        // Build a reasonable default set of feeds:
        // last 5 years + "recent" + "modified" (recent/modified last to avoid overwriting)
        let mut feeds = Self::default_year_feeds(5);
        feeds.push("recent".to_string());
        feeds.push("modified".to_string());

        // Resolve API key from param or environment
        let api_key = api_key
            .or_else(|| std::env::var("VULNERA__APIS__NVD__API_KEY").ok())
            .filter(|s| !s.is_empty());

        tracing::info!(
            feed_base_url=%feed_base_url,
            rest_base_url=%rest_base_url,
            db_path=%db_path.display(),
            feeds=?feeds,
            has_api_key=%api_key.is_some(),
            "Initialized NvdClient with local cache and optional REST enrichment"
        );

        let client = Self {
            feed_base_url,
            rest_base_url,
            db_path,
            feeds,
            show_progress: false,
            cvss_index_path: cache_dir.join("nvd_cvss_index.json"),
            api_key,
        };
        // Start periodic sync + CVSS index refresh (fire-and-forget)
        client.start_periodic_sync();
        client
    }

    /// Construct with the official feeds base and default env-based cache directory
    pub fn default() -> Self {
        Self::new("https://nvd.nist.gov/feeds/json/cve/1.1".to_string(), None)
    }

    /// Compatibility constructor signature; api key unused in local-cache mode
    pub fn with_api_key(api_key: String) -> Self {
        Self::new(
            "https://nvd.nist.gov/feeds/json/cve/1.1".to_string(),
            Some(api_key),
        )
    }

    /// Generate a vector of year feed names, from (current_year - years_back) to current_year.
    fn default_year_feeds(years_back: i32) -> Vec<String> {
        let now = Utc::now();
        let current_year = now.year();
        let start_year = current_year.saturating_sub(years_back.max(0));
        (start_year..=current_year).map(|y| y.to_string()).collect()
    }

    /// Build a fresh `nvd_cve::cache::CacheConfig` from our fields.
    fn build_cache_config(&self) -> CacheConfig {
        let mut cfg = CacheConfig::new();
        cfg.url = self.feed_base_url.clone();
        cfg.feeds = self.feeds.clone();
        cfg.db = self.db_path.to_string_lossy().to_string();
        cfg.show_progress = self.show_progress;
        cfg.force_update = false;
        cfg
    }

    /// Ensure the local database exists; if it does not, run a blocking sync in a blocking thread.
    async fn ensure_synced(&self) -> Result<(), VulnerabilityError> {
        if self.db_path.exists() {
            // Ensure CVSS index exists even if DB already present
            let cfg = self.build_cache_config();
            if !self.cvss_index_path.exists() {
                let _ = self.regenerate_cvss_index(&cfg).await;
            }
            return Ok(());
        }

        let cfg = self.build_cache_config();

        tracing::info!(
            db=%self.db_path.display(),
            url=%cfg.url,
            feeds=?cfg.feeds,
            "NVD local DB not found; syncing feeds (one-time)"
        );

        // Perform the sync on a blocking thread
        let res = task::spawn_blocking(move || {
            let client =
                <ReqwestBlockingClient as BlockingHttpClient>::new(&cfg.url, None, None, None);
            sync_blocking(&cfg, client)
        })
        .await;

        match res {
            Ok(Ok(())) => {
                tracing::info!(db=%self.db_path.display(), "NVD local cache sync completed");
                // Build CVSS index after initial sync
                let cfg2 = self.build_cache_config();
                let _ = self.regenerate_cvss_index(&cfg2).await;
                Ok(())
            }
            Ok(Err(err)) => Err(VulnerabilityError::Api(ApiError::Http {
                status: 500,
                message: format!("NVD local cache sync failed: {:?}", err),
            })),
            Err(join_err) => Err(VulnerabilityError::Api(ApiError::Http {
                status: 500,
                message: format!("NVD local cache sync join error: {}", join_err),
            })),
        }
    }

    fn convert_cve_to_raw(&self, c: nvd_cve::cve::Cve) -> RawVulnerability {
        // ID
        let id = c.cve_data_meta.id;

        // Description (prefer English)
        let description = c
            .description
            .description_data
            .iter()
            .find(|d| d.lang == "en")
            .or_else(|| c.description.description_data.first())
            .map(|d| d.value.clone())
            .unwrap_or_default();

        // References
        let references = c
            .references
            .reference_data
            .into_iter()
            .map(|r| r.url)
            .collect::<Vec<_>>();

        // Severity is populated from the sidecar CVSS index in the async callers to avoid blocking IO here
        let severity = None;

        // Published date not available from Cve-only record
        let published_at = None;

        RawVulnerability {
            id,
            summary: description.clone(),
            description,
            severity,
            references,
            published_at,
            affected: vec![], // Not extracted from NVD CPE data in this phase
        }
    }

    /// Try to parse a base score (CVSS) from the `impact` JSON object.
    /// Prefers v3 over v2 when both are present.
    #[allow(dead_code)]
    fn extract_base_score_from_impact(impact: &Value) -> Option<f64> {
        // NVD 1.1 frequently uses "baseMetricV3" and "baseMetricV2"
        impact
            .get("baseMetricV3")
            .and_then(|v| v.get("cvssV3"))
            .and_then(|v| v.get("baseScore"))
            .and_then(|v| v.as_f64())
            .or_else(|| {
                impact
                    .get("baseMetricV2")
                    .and_then(|v| v.get("cvssV2"))
                    .and_then(|v| v.get("baseScore"))
                    .and_then(|v| v.as_f64())
            })
    }

    #[allow(dead_code)]
    // Load CVSS base score for a CVE from the sidecar index file
    fn load_cvss_score(&self, id: &str) -> Option<f64> {
        let data = fs::read_to_string(&self.cvss_index_path).ok()?;
        let map: HashMap<String, f64> = serde_json::from_str(&data).ok()?;
        map.get(id).copied()
    }

    // Load the full CVSS sidecar index asynchronously (avoid blocking IO on async paths)
    async fn load_cvss_index_async(&self) -> Option<HashMap<String, f64>> {
        let data = tokio::fs::read(&self.cvss_index_path).await.ok()?;
        serde_json::from_slice::<HashMap<String, f64>>(&data).ok()
    }

    // Fetch CVSS base score via NVD REST (v2.0) if API key available; returns best score if found
    pub(crate) async fn fetch_cvss_base_score_via_rest(&self, cve_id: &str) -> Option<f64> {
        let base = self.rest_base_url.trim_end_matches('/');
        let url = format!("{}/cves/2.0?cveId={}", base, cve_id);

        let client = reqwest::Client::new();
        let mut req = client.get(url);
        if let Some(key) = &self.api_key {
            req = req.header("apiKey", key);
        }

        let resp = req.send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let json: serde_json::Value = resp.json().await.ok()?;

        let items = json.get("vulnerabilities").and_then(|v| v.as_array())?;
        for item in items {
            let cve = item.get("cve").unwrap_or(item);
            if let Some(metrics) = cve.get("metrics") {
                // CVSS v3.1
                if let Some(v) = metrics
                    .get("cvssMetricV31")
                    .and_then(|a| a.as_array())
                    .and_then(|a| a.first())
                    .and_then(|m| m.get("cvssData"))
                    .and_then(|d| d.get("baseScore"))
                    .and_then(|s| s.as_f64())
                {
                    return Some(v);
                }
                // CVSS v3.0
                if let Some(v) = metrics
                    .get("cvssMetricV30")
                    .and_then(|a| a.as_array())
                    .and_then(|a| a.first())
                    .and_then(|m| m.get("cvssData"))
                    .and_then(|d| d.get("baseScore"))
                    .and_then(|s| s.as_f64())
                {
                    return Some(v);
                }
                // CVSS v2.0 (sometimes baseScore is nested or at the metric level)
                if let Some(v) = metrics
                    .get("cvssMetricV2")
                    .and_then(|a| a.as_array())
                    .and_then(|a| a.first())
                    .and_then(|m| {
                        m.get("cvssData")
                            .and_then(|d| d.get("baseScore"))
                            .or_else(|| m.get("baseScore"))
                    })
                    .and_then(|s| s.as_f64())
                {
                    return Some(v);
                }
            }
        }
        None
    }

    // Persist a single CVSS score into the sidecar index asynchronously (best-effort)
    async fn upsert_cvss_index_entry_async(&self, cve_id: &str, score: f64) {
        if let Some(mut map) = self.load_cvss_index_async().await {
            map.insert(cve_id.to_string(), score);
            if let Ok(json) = serde_json::to_vec(&map) {
                let _ = tokio::fs::write(&self.cvss_index_path, json).await;
            }
        } else {
            // Create a fresh index when missing/corrupt
            let mut map = HashMap::new();
            map.insert(cve_id.to_string(), score);
            if let Ok(json) = serde_json::to_vec(&map) {
                let _ = tokio::fs::write(&self.cvss_index_path, json).await;
            }
        }
    }

    // Regenerate the sidecar CVSS index by walking current feeds and extracting CVSS from impact

    async fn regenerate_cvss_index(&self, cfg: &CacheConfig) -> Result<(), VulnerabilityError> {
        let url = cfg.url.clone();
        let feeds = cfg.feeds.clone();
        let index_path = self.cvss_index_path.clone();

        let res = task::spawn_blocking(move || {
            let client = <ReqwestBlockingClient as BlockingHttpClient>::new(&url, None, None, None);
            let mut map: HashMap<String, f64> = HashMap::new();

            for feed in feeds {
                if let Ok(cve_feed) = CveFeed::from_blocking_http_client(&client, &feed) {
                    for item in cve_feed.cve_items {
                        if let Some(score) = NvdClient::extract_base_score_from_impact(&item.impact)
                        {
                            map.insert(item.cve.cve_data_meta.id.clone(), score);
                        }
                    }
                }
            }

            if let Some(parent) = index_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let json = serde_json::to_string(&map).unwrap_or_else(|_| "{}".to_string());
            fs::write(index_path, json)
                .map_err(|e| format!("Failed to write CVSS index: {}", e))?;
            Ok::<(), String>(())
        })
        .await;

        match res {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(VulnerabilityError::Api(ApiError::Http {
                status: 500,
                message: e,
            })),
            Err(join_err) => Err(VulnerabilityError::Api(ApiError::Http {
                status: 500,
                message: format!("CVSS index task error: {}", join_err),
            })),
        }
    }
    #[allow(dead_code)]
    // Force a sync now (optionally with force_update), to be used in future admin endpoints
    async fn sync_now(&self, force_update: bool) -> Result<(), VulnerabilityError> {
        // Build a config snapshot for this sync
        let mut cfg = self.build_cache_config();
        cfg.force_update = force_update;

        // Extract values we need inside the blocking task
        let url = cfg.url.clone();
        let feeds = cfg.feeds.clone();
        let db = cfg.db.clone();
        let show_progress = cfg.show_progress;
        let force_update_val = cfg.force_update;

        // Perform sync using an internal local config to avoid moving `cfg`
        let res = task::spawn_blocking(move || {
            let mut cfg_local = CacheConfig::new();
            cfg_local.url = url;
            cfg_local.feeds = feeds;
            cfg_local.db = db;
            cfg_local.show_progress = show_progress;
            cfg_local.force_update = force_update_val;

            let client = <ReqwestBlockingClient as BlockingHttpClient>::new(
                &cfg_local.url,
                None,
                None,
                None,
            );
            sync_blocking(&cfg_local, client)
        })
        .await;

        // After sync completes, rebuild CVSS index using a fresh config snapshot
        match res {
            Ok(Ok(())) => {
                let cfg2 = self.build_cache_config();
                self.regenerate_cvss_index(&cfg2).await
            }
            Ok(Err(err)) => Err(VulnerabilityError::Api(ApiError::Http {
                status: 500,
                message: format!("NVD local cache sync failed: {:?}", err),
            })),
            Err(join_err) => Err(VulnerabilityError::Api(ApiError::Http {
                status: 500,
                message: format!("NVD local cache sync join error: {}", join_err),
            })),
        }
    }

    /// Determine sync interval from env var VULNERA__CACHE__TTL_HOURS (default 24 hours)
    fn sync_interval() -> Duration {
        let hours = std::env::var("VULNERA__CACHE__TTL_HOURS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|h| *h > 0)
            .unwrap_or(24);
        Duration::from_secs(hours * 3600)
    }

    // Start a periodic background task to refresh the local DB and CVSS index
    fn start_periodic_sync(&self) {
        // Disable in tests to avoid background tasks and port usage
        if cfg!(test) {
            tracing::info!("NVD periodic sync disabled in tests");
            return;
        }
        // Optional enable flag: VULNERA__NVD__ENABLE_PERIODIC_SYNC=true|false (default true)
        let enabled = std::env::var("VULNERA__NVD__ENABLE_PERIODIC_SYNC")
            .ok()
            .map(|v| v.to_lowercase())
            .map(|v| v == "1" || v == "true" || v == "yes")
            .unwrap_or(true);
        if !enabled {
            tracing::info!("NVD periodic sync disabled via VULNERA__NVD__ENABLE_PERIODIC_SYNC");
            return;
        }

        let feed_base_url = self.feed_base_url.clone();
        let db_path = self.db_path.clone();
        let feeds = self.feeds.clone();
        let index_path = self.cvss_index_path.clone();

        tokio::spawn(async move {
            loop {
                // Build config and force a refresh
                let mut cfg = CacheConfig::new();
                cfg.url = feed_base_url.clone();
                cfg.feeds = feeds.clone();
                cfg.db = db_path.to_string_lossy().to_string();
                cfg.show_progress = false;
                cfg.force_update = true;

                // Prepare clones for both sync and index before moving into closures
                let url_sync = cfg.url.clone();
                let feeds_sync = cfg.feeds.clone();
                let db_sync = cfg.db.clone();
                let show_progress_sync = cfg.show_progress;
                let force_update_sync = cfg.force_update;

                // Run sync using a local CacheConfig to avoid moving `cfg`
                let _ = task::spawn_blocking(move || {
                    let mut cfg_local = CacheConfig::new();
                    cfg_local.url = url_sync;
                    cfg_local.feeds = feeds_sync;
                    cfg_local.db = db_sync;
                    cfg_local.show_progress = show_progress_sync;
                    cfg_local.force_update = force_update_sync;

                    let client = <ReqwestBlockingClient as BlockingHttpClient>::new(
                        &cfg_local.url,
                        None,
                        None,
                        None,
                    );
                    sync_blocking(&cfg_local, client)
                })
                .await;

                // Rebuild CVSS index (use pre-cloned values from cfg)
                let url2 = cfg.url.clone();
                let feeds2 = cfg.feeds.clone();
                let index2 = index_path.clone();
                let _ = task::spawn_blocking(move || {
                    let client =
                        <ReqwestBlockingClient as BlockingHttpClient>::new(&url2, None, None, None);
                    let mut map: HashMap<String, f64> = HashMap::new();
                    for feed in feeds2 {
                        if let Ok(cve_feed) = CveFeed::from_blocking_http_client(&client, &feed) {
                            for item in cve_feed.cve_items {
                                if let Some(score) =
                                    NvdClient::extract_base_score_from_impact(&item.impact)
                                {
                                    map.insert(item.cve.cve_data_meta.id.clone(), score);
                                }
                            }
                        }
                    }
                    if let Some(parent) = index2.parent() {
                        let _ = fs::create_dir_all(parent);
                    }
                    let json = serde_json::to_string(&map).unwrap_or_else(|_| "{}".to_string());
                    let _ = fs::write(index2, json);
                    Ok::<(), ()>(())
                })
                .await;

                // Sleep for configured interval (default from VULNERA__CACHE__TTL_HOURS or 24h)
                sleep(Self::sync_interval()).await;
            }
        });
    }
}

#[async_trait]
impl VulnerabilityApiClient for NvdClient {
    async fn query_vulnerabilities(
        &self,
        package: &Package,
    ) -> Result<Vec<RawVulnerability>, VulnerabilityError> {
        self.ensure_synced().await?;

        let cfg = self.build_cache_config();
        let name = package.name.clone();

        // Execute blocking sqlite queries on a blocking thread
        let cves = task::spawn_blocking(move || {
            // 1) search in descriptions for the package name -> CVE IDs
            let ids = search_description(&cfg, &name).unwrap_or_default();

            // 2) fetch each CVE and return Cve objects
            let mut out = Vec::with_capacity(ids.len());
            for id in ids {
                if let Ok(c) = search_by_id(&cfg, &id) {
                    out.push(c);
                }
            }
            out
        })
        .await
        .map_err(|e| {
            VulnerabilityError::Api(ApiError::Http {
                status: 500,
                message: format!("NVD local search join error: {}", e),
            })
        })?;

        // removed unused cvss_index preload
        // Convert CVEs to raw vulns
        let mut res: Vec<RawVulnerability> = cves
            .into_iter()
            .map(|c| self.convert_cve_to_raw(c))
            .collect();

        // Enrich severity from local CVSS sidecar index
        if let Some(index) = self.load_cvss_index_async().await {
            for v in &mut res {
                if v.severity.is_none() {
                    if let Some(score) = index.get(&v.id) {
                        v.severity = Some(score.to_string());
                    }
                }
            }
        }

        // If still missing and API key is available, enrich via NVD REST (best-effort)
        if self.api_key.is_some() {
            for v in &mut res {
                if v.severity.is_none() {
                    if let Some(score) = self.fetch_cvss_base_score_via_rest(&v.id).await {
                        v.severity = Some(score.to_string());
                        // Persist to sidecar for future lookups
                        self.upsert_cvss_index_entry_async(&v.id, score).await;
                    }
                }
            }
        }

        Ok(res)
    }

    async fn get_vulnerability_details(
        &self,
        id: &str,
    ) -> Result<Option<RawVulnerability>, VulnerabilityError> {
        self.ensure_synced().await?;

        let cfg = self.build_cache_config();
        let id = id.to_string();

        let res = task::spawn_blocking(move || search_by_id(&cfg, &id))
            .await
            .map_err(|e| {
                VulnerabilityError::Api(ApiError::Http {
                    status: 500,
                    message: format!("NVD local fetch join error: {}", e),
                })
            })?;

        let cvss_index = self.load_cvss_index_async().await;
        match res {
            Ok(c) => {
                let mut v = self.convert_cve_to_raw(c);
                if let Some(index) = cvss_index.as_ref() {
                    if v.severity.is_none() {
                        if let Some(score) = index.get(&v.id) {
                            v.severity = Some(score.to_string());
                        }
                    }
                }
                Ok(Some(v))
            }
            Err(_e) => {
                // Not found or DB error. Treat as not-found to align with previous contract.
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::NvdClient;
    use mockito::{Matcher, Server};

    #[tokio::test]
    async fn test_fetch_cvss_v31_parsing() {
        let mut server = Server::new_async().await;
        let cve_id = "CVE-2024-0001";
        let body = r#"{
          "vulnerabilities": [
            {
              "cve": {
                "metrics": {
                  "cvssMetricV31": [
                    { "cvssData": { "baseScore": 9.8 } }
                  ]
                }
              }
            }
          ]
        }"#;

        let _m = server
            .mock("GET", "/rest/json/cves/2.0")
            .match_query(Matcher::UrlEncoded("cveId".into(), cve_id.into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create();

        let base = format!("{}/rest/json", server.url());
        let client = NvdClient::new(base, Some("dummy-key".to_string()));

        let score = client.fetch_cvss_base_score_via_rest(cve_id).await;
        assert_eq!(score, Some(9.8));
    }

    #[tokio::test]
    async fn test_fetch_cvss_v30_parsing() {
        let mut server = Server::new_async().await;
        let cve_id = "CVE-2024-0002";
        let body = r#"{
          "vulnerabilities": [
            {
              "cve": {
                "metrics": {
                  "cvssMetricV30": [
                    { "cvssData": { "baseScore": 8.1 } }
                  ]
                }
              }
            }
          ]
        }"#;

        let _m = server
            .mock("GET", "/rest/json/cves/2.0")
            .match_query(Matcher::UrlEncoded("cveId".into(), cve_id.into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create();

        let base = format!("{}/rest/json", server.url());
        let client = NvdClient::new(base, Some("dummy-key".to_string()));

        let score = client.fetch_cvss_base_score_via_rest(cve_id).await;
        assert_eq!(score, Some(8.1));
    }

    #[tokio::test]
    async fn test_fetch_cvss_v2_parsing() {
        let mut server = Server::new_async().await;
        let cve_id = "CVE-2024-0003";
        // Base score may be nested under cvssData or directly under the metric object; test nested variant
        let body = r#"{
          "vulnerabilities": [
            {
              "cve": {
                "metrics": {
                  "cvssMetricV2": [
                    { "cvssData": { "baseScore": 5.0 } }
                  ]
                }
              }
            }
          ]
        }"#;

        let _m = server
            .mock("GET", "/rest/json/cves/2.0")
            .match_query(Matcher::UrlEncoded("cveId".into(), cve_id.into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create();

        let base = format!("{}/rest/json", server.url());
        let client = NvdClient::new(base, Some("dummy-key".to_string()));

        let score = client.fetch_cvss_base_score_via_rest(cve_id).await;
        assert_eq!(score, Some(5.0));
    }
}
