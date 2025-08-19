//! HTTP cache middleware for response caching and request deduplication

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, error, warn};

use crate::{
    application::{ApplicationError, CacheService},
    infrastructure::cache::cache_service_wrapper::CacheServiceWrapper,
    presentation::AppState,
};

/// HTTP cache configuration
#[derive(Debug, Clone)]
pub struct HttpCacheConfig {
    pub enabled: bool,
    pub default_ttl: Duration,
    pub max_cache_size: usize,
    pub cache_control_header: bool,
    pub etag_header: bool,
    pub vary_headers: Vec<String>,
    pub cacheable_methods: Vec<String>,
    pub cacheable_status_codes: Vec<u16>,
}

impl Default for HttpCacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_ttl: Duration::from_secs(300), // 5 minutes
            max_cache_size: 1000,
            cache_control_header: true,
            etag_header: true,
            vary_headers: vec!["Accept".to_string(), "Accept-Encoding".to_string()],
            cacheable_methods: vec!["GET".to_string(), "HEAD".to_string()],
            cacheable_status_codes: vec![200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501],
        }
    }
}

/// Cached HTTP response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub created_at: u64,
    pub expires_at: u64,
    pub etag: Option<String>,
}

/// Request deduplication entry
#[derive(Debug)]
#[allow(dead_code)]
struct DeduplicationEntry {
    response: Option<Response>,
    waiters: Vec<tokio::sync::oneshot::Sender<Response>>,
    created_at: SystemTime,
}

/// HTTP cache middleware
pub struct HttpCacheMiddleware {
    cache: Arc<CacheServiceWrapper>,
    config: HttpCacheConfig,
    #[allow(dead_code)]
    in_flight_requests: Arc<RwLock<HashMap<String, Arc<tokio::sync::Mutex<DeduplicationEntry>>>>>,
}

impl HttpCacheMiddleware {
    /// Create a new HTTP cache middleware
    pub fn new(cache: Arc<CacheServiceWrapper>, config: HttpCacheConfig) -> Self {
        Self {
            cache,
            config,
            in_flight_requests: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate cache key for request
    fn generate_cache_key(&self, request: &Request) -> String {
        let uri = request.uri();
        let method = request.method();
        let query = uri.query().unwrap_or("");
        
        // Include vary headers in cache key
        let mut vary_values = Vec::new();
        for header_name in &self.config.vary_headers {
            if let Ok(header_name) = HeaderName::try_from(header_name) {
                if let Some(header_value) = request.headers().get(&header_name) {
                    if let Ok(value_str) = header_value.to_str() {
                        vary_values.push(format!("{}:{}", header_name, value_str));
                    }
                }
            }
        }
        
        format!(
            "http_cache:{}:{}:{}:{}",
            method,
            uri.path(),
            query,
            vary_values.join("|")
        )
    }

    /// Generate ETag for response
    fn generate_etag(&self, body: &[u8]) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        body.hash(&mut hasher);
        format!("\"{}\"", hasher.finish())
    }

    /// Check if request is cacheable
    fn is_cacheable_request(&self, request: &Request) -> bool {
        if !self.config.enabled {
            return false;
        }

        let method = request.method().as_str();
        self.config.cacheable_methods.contains(&method.to_string())
    }

    /// Check if response is cacheable
    fn is_cacheable_response(&self, response: &Response) -> bool {
        let status = response.status().as_u16();
        self.config.cacheable_status_codes.contains(&status)
    }

    /// Get current timestamp
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Add cache headers to response
    fn add_cache_headers(&self, response: &mut Response, cached_response: &CachedResponse) {
        let headers = response.headers_mut();

        if self.config.cache_control_header {
            let max_age = cached_response.expires_at.saturating_sub(Self::current_timestamp());
            let cache_control = format!("public, max-age={}", max_age);
            if let Ok(value) = HeaderValue::try_from(cache_control) {
                headers.insert("cache-control", value);
            }
        }

        if self.config.etag_header {
            if let Some(etag) = &cached_response.etag {
                if let Ok(value) = HeaderValue::try_from(etag) {
                    headers.insert("etag", value);
                }
            }
        }

        // Add Last-Modified header
        let last_modified = httpdate::fmt_http_date(
            UNIX_EPOCH + Duration::from_secs(cached_response.created_at)
        );
        if let Ok(value) = HeaderValue::try_from(last_modified) {
            headers.insert("last-modified", value);
        }

        // Add Vary headers
        if !self.config.vary_headers.is_empty() {
            let vary_value = self.config.vary_headers.join(", ");
            if let Ok(value) = HeaderValue::try_from(vary_value) {
                headers.insert("vary", value);
            }
        }
    }

    /// Handle conditional requests (If-None-Match, If-Modified-Since)
    fn handle_conditional_request(
        &self,
        request: &Request,
        cached_response: &CachedResponse,
    ) -> Option<Response> {
        // Handle If-None-Match (ETag)
        if let Some(if_none_match) = request.headers().get("if-none-match") {
            if let (Ok(client_etag), Some(cached_etag)) = (if_none_match.to_str(), &cached_response.etag) {
                if client_etag == cached_etag || client_etag == "*" {
                    let mut response = Response::builder()
                        .status(StatusCode::NOT_MODIFIED)
                        .body(Body::empty())
                        .unwrap();
                    
                    self.add_cache_headers(&mut response, cached_response);
                    return Some(response);
                }
            }
        }

        // Handle If-Modified-Since
        if let Some(if_modified_since) = request.headers().get("if-modified-since") {
            if let Ok(client_date_str) = if_modified_since.to_str() {
                if let Ok(client_date) = httpdate::parse_http_date(client_date_str) {
                    let cached_date = UNIX_EPOCH + Duration::from_secs(cached_response.created_at);
                    if cached_date <= client_date {
                        let mut response = Response::builder()
                            .status(StatusCode::NOT_MODIFIED)
                            .body(Body::empty())
                            .unwrap();
                        
                        self.add_cache_headers(&mut response, cached_response);
                        return Some(response);
                    }
                }
            }
        }

        None
    }

    /// Convert cached response to HTTP response
    fn cached_response_to_http(&self, cached_response: CachedResponse) -> Response {
        let mut builder = Response::builder().status(cached_response.status);

        // Add headers
        for (name, value) in &cached_response.headers {
            if let (Ok(header_name), Ok(header_value)) = (
                HeaderName::try_from(name),
                HeaderValue::try_from(value),
            ) {
                builder = builder.header(header_name, header_value);
            }
        }

        let body = cached_response.body.clone();
        let mut response = builder.body(Body::from(body)).unwrap();
        self.add_cache_headers(&mut response, &cached_response);
        response
    }

    /// Convert HTTP response to cached response
    async fn http_response_to_cached(&self, response: Response) -> Result<CachedResponse, ApplicationError> {
        let (parts, body) = response.into_parts();
        
        // Read body
        let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
            Ok(bytes) => bytes.to_vec(),
            Err(e) => {
                error!("Failed to read response body: {}", e);
                return Err(ApplicationError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to read response body: {}", e),
                )));
            }
        };

        // Convert headers
        let mut headers = HashMap::new();
        for (name, value) in parts.headers {
            if let Some(name) = name {
                if let Ok(value_str) = value.to_str() {
                    headers.insert(name.to_string(), value_str.to_string());
                }
            }
        }

        let now = Self::current_timestamp();
        let etag = if self.config.etag_header {
            Some(self.generate_etag(&body_bytes))
        } else {
            None
        };

        Ok(CachedResponse {
            status: parts.status.as_u16(),
            headers,
            body: body_bytes,
            created_at: now,
            expires_at: now + self.config.default_ttl.as_secs(),
            etag,
        })
    }

    /// Clean up expired in-flight requests
    #[allow(dead_code)]
    async fn cleanup_expired_requests(&self) {
        let mut in_flight = self.in_flight_requests.write().await;
        let now = SystemTime::now();
        
        in_flight.retain(|_, entry_mutex| {
            // Try to lock without blocking
            if let Ok(entry) = entry_mutex.try_lock() {
                now.duration_since(entry.created_at).unwrap_or_default() < Duration::from_secs(30)
            } else {
                true // Keep if we can't check
            }
        });
    }
}

/// Cache middleware function
pub async fn cache_middleware(
    State(app_state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    // For now, we'll create a simple cache middleware
    // In a full implementation, you would inject the HttpCacheMiddleware
    let cache_config = HttpCacheConfig::default();
    let middleware = HttpCacheMiddleware::new(
        app_state.cache_service.clone(),
        cache_config,
    );

    if !middleware.is_cacheable_request(&request) {
        return Ok(next.run(request).await);
    }

    let cache_key = middleware.generate_cache_key(&request);
    
    // Try to get from cache
    match middleware.cache.get::<CachedResponse>(&cache_key).await {
        Ok(Some(cached_response)) => {
            // Check if expired
            if cached_response.expires_at > HttpCacheMiddleware::current_timestamp() {
                // Handle conditional requests
                if let Some(conditional_response) = middleware.handle_conditional_request(&request, &cached_response) {
                    debug!("Returning 304 Not Modified for cache key: {}", cache_key);
                    return Ok(conditional_response);
                }

                debug!("Cache hit for key: {}", cache_key);
                return Ok(middleware.cached_response_to_http(cached_response));
            }
        }
        Ok(None) => {
            debug!("Cache miss for key: {}", cache_key);
        }
        Err(e) => {
            warn!("Cache error for key {}: {}", cache_key, e);
        }
    }

    // Cache miss or expired - get fresh response
    let response = next.run(request).await;

    let is_cacheable = middleware.is_cacheable_response(&response);

    if is_cacheable {
        // Cache the response
        match middleware.http_response_to_cached(response).await {
            Ok(cached_response) => {
                let cache_response = middleware.cached_response_to_http(cached_response.clone());

                // Store in cache (fire and forget)
                let cache_clone = middleware.cache.clone();
                let key_clone = cache_key.clone();
                let ttl = middleware.config.default_ttl;
                tokio::spawn(async move {
                    if let Err(e) = cache_clone.set(&key_clone, &cached_response, ttl).await {
                        warn!("Failed to cache response for key {}: {}", key_clone, e);
                    }
                });

                debug!("Cached response for key: {}", cache_key);
                Ok(cache_response)
            }
            Err(_e) => {
                // If caching fails, we need to recreate the response since we consumed it
                // For now, return an error response
                Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("Internal server error"))
                    .unwrap())
            }
        }
    } else {
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;

    #[test]
    fn test_cache_key_generation() {
        let cache = Arc::new(CacheServiceWrapper::file(Arc::new(
            crate::infrastructure::cache::file_cache::FileCacheRepository::new(
                std::path::PathBuf::from("/tmp"),
                Duration::from_secs(3600),
            )
        )));
        
        let middleware = HttpCacheMiddleware::new(cache, HttpCacheConfig::default());
        
        let request = Request::builder()
            .method(Method::GET)
            .uri("/api/vulnerabilities?page=1")
            .body(Body::empty())
            .unwrap();
        
        let cache_key = middleware.generate_cache_key(&request);
        assert!(cache_key.contains("GET"));
        assert!(cache_key.contains("/api/vulnerabilities"));
        assert!(cache_key.contains("page=1"));
    }

    #[test]
    fn test_etag_generation() {
        let cache = Arc::new(CacheServiceWrapper::file(Arc::new(
            crate::infrastructure::cache::file_cache::FileCacheRepository::new(
                std::path::PathBuf::from("/tmp"),
                Duration::from_secs(3600),
            )
        )));
        
        let middleware = HttpCacheMiddleware::new(cache, HttpCacheConfig::default());
        
        let body = b"test response body";
        let etag1 = middleware.generate_etag(body);
        let etag2 = middleware.generate_etag(body);
        
        assert_eq!(etag1, etag2);
        assert!(etag1.starts_with('"') && etag1.ends_with('"'));
    }
}
