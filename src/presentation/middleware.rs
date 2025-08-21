//! HTTP middleware for the web server

use axum::{
    Json,
    extract::Request,
    http::{HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use chrono::Utc;
use std::time::Instant;
use uuid::Uuid;

use crate::application::errors::ApplicationError;
use crate::presentation::models::ErrorResponse;

/// Error handling middleware with environment-aware error sanitization
impl IntoResponse for ApplicationError {
    fn into_response(self) -> Response {
        // Get the configuration to determine if we should sanitize errors
        // Note: In a real implementation, you'd pass this through middleware state
        let sanitize_errors = std::env::var("ENV").unwrap_or_default() == "production";

        let (status, code, message) = match self {
            ApplicationError::Domain(_) => (
                StatusCode::BAD_REQUEST,
                "DOMAIN_ERROR",
                "Invalid input provided",
            ),
            ApplicationError::RateLimited { .. } => (
                StatusCode::TOO_MANY_REQUESTS,
                "RATE_LIMITED",
                "Upstream rate limit exceeded. Please retry later.",
            ),
            ApplicationError::Parse(_) => (
                StatusCode::BAD_REQUEST,
                "PARSE_ERROR",
                "Failed to parse dependency file",
            ),
            ApplicationError::InvalidEcosystem { .. } => (
                StatusCode::BAD_REQUEST,
                "INVALID_ECOSYSTEM",
                "Unsupported ecosystem specified",
            ),
            ApplicationError::UnsupportedFormat { .. } => (
                StatusCode::BAD_REQUEST,
                "UNSUPPORTED_FORMAT",
                "File format not supported",
            ),
            ApplicationError::Configuration { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "CONFIGURATION_ERROR",
                if sanitize_errors {
                    "Service temporarily unavailable"
                } else {
                    "Service configuration error"
                },
            ),
            ApplicationError::NotFound { .. } => {
                (StatusCode::NOT_FOUND, "NOT_FOUND", "Resource not found")
            }
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                if sanitize_errors {
                    "An internal error occurred"
                } else {
                    "An internal error occurred"
                },
            ),
        };

        let error_response = ErrorResponse {
            code: code.to_string(),
            message: message.to_string(),
            details: if sanitize_errors {
                None // Don't expose internal details in production
            } else {
                Some(serde_json::json!({ "error": self.to_string() }))
            },
            request_id: Uuid::new_v4(),
            timestamp: Utc::now(),
        };

        (status, Json(error_response)).into_response()
    }
}

/// Security headers middleware
pub async fn security_headers_middleware(
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;

    // Add security headers
    let headers = response.headers_mut();

    // Strict-Transport-Security (HSTS)
    headers.insert(
        "strict-transport-security",
        HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
    );

    // X-Frame-Options (prevent clickjacking)
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));

    // X-Content-Type-Options (prevent MIME sniffing)
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );

    // X-XSS-Protection (XSS protection)
    headers.insert(
        "x-xss-protection",
        HeaderValue::from_static("1; mode=block"),
    );

    // Referrer-Policy (control referrer information)
    headers.insert(
        "referrer-policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );

    // Content-Security-Policy (CSP)
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; img-src 'self' data: https:; font-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; connect-src 'self' https:; frame-ancestors 'none';"),
    );

    // Permissions-Policy (control browser features)
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), interest-cohort=()"),
    );

    response
}

/// HTTPS enforcement middleware
pub async fn https_enforcement_middleware(
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    // Check if request is coming over HTTPS
    let is_https = request
        .headers()
        .get("x-forwarded-proto")
        .and_then(|h| h.to_str().ok())
        .map(|proto| proto == "https")
        .unwrap_or_else(|| {
            // Fallback: check the URI scheme (though this won't work behind a proxy)
            request.uri().scheme_str() == Some("https")
        });

    if !is_https {
        // Get the host header
        if let Some(host) = request.headers().get("host").and_then(|h| h.to_str().ok()) {
            let https_url = format!(
                "https://{}{}",
                host,
                request
                    .uri()
                    .path_and_query()
                    .map(|pq| pq.as_str())
                    .unwrap_or("/")
            );

            // Return a redirect to HTTPS
            return Redirect::permanent(&https_url).into_response();
        }
    }

    // Continue with the request if HTTPS or if we can't determine
    next.run(request).await
}

/// Request logging middleware with timing and request ID
pub async fn logging_middleware(request: Request<axum::body::Body>, next: Next) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let request_id = Uuid::new_v4();
    let start_time = Instant::now();

    tracing::info!(
        request_id = %request_id,
        method = %method,
        uri = %uri,
        "Processing request"
    );

    let response = next.run(request).await;
    let duration = start_time.elapsed();

    tracing::info!(
        request_id = %request_id,
        method = %method,
        uri = %uri,
        status = %response.status(),
        duration_ms = duration.as_millis(),
        "Request completed"
    );

    response
}
