//! HTTP middleware for the web server

use axum::{
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use chrono::Utc;
use std::time::Instant;
use uuid::Uuid;

use crate::application::errors::ApplicationError;
use crate::presentation::models::ErrorResponse;

/// Error handling middleware
impl IntoResponse for ApplicationError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
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
                "Service configuration error",
            ),
            ApplicationError::NotFound { .. } => {
                (StatusCode::NOT_FOUND, "NOT_FOUND", "Resource not found")
            }
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "An internal error occurred",
            ),
        };

        let error_response = ErrorResponse {
            code: code.to_string(),
            message: message.to_string(),
            details: Some(serde_json::json!({ "error": self.to_string() })),
            request_id: Uuid::new_v4(),
            timestamp: Utc::now(),
        };

        (status, Json(error_response)).into_response()
    }
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
