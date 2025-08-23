//! Route definitions and server setup

use crate::Config;
use axum::{
    Router, middleware,
    routing::{get, post},
};
use std::time::Duration;
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::presentation::{
    controllers::{
        analysis::{
            AppState, analyze_dependencies, get_analysis_report, get_vulnerability,
            list_vulnerabilities, refresh_vulnerability_cache,
        },
        health::{health_check, metrics},
    },
    middleware::{
        ghsa_token_middleware, https_enforcement_middleware, logging_middleware,
        security_headers_middleware,
    },
    models::*,
};
use axum::{
    http::{StatusCode, header},
    response::Response,
};

/// OpenAPI documentation
#[derive(OpenApi)]
#[openapi(
    paths(
        crate::presentation::controllers::analysis::analyze_dependencies,
    crate::presentation::controllers::analysis::analyze_repository,
        crate::presentation::controllers::analysis::get_vulnerability,
        crate::presentation::controllers::analysis::list_vulnerabilities,
        crate::presentation::controllers::analysis::refresh_vulnerability_cache,
        crate::presentation::controllers::analysis::get_analysis_report,
        crate::presentation::controllers::health::health_check,
        crate::presentation::controllers::health::metrics
    ),
    components(
        schemas(
            AnalysisRequest,
            AnalysisResponse,
            VulnerabilityDto,
            VulnerabilityListResponse,
            AffectedPackageDto,
            AnalysisMetadataDto,
            SeverityBreakdownDto,
            PaginationDto,
            ErrorResponse,
            HealthResponse,
            VersionRecommendationDto,
            RepositoryAnalysisRequest,
            RepositoryAnalysisResponse,
            RepositoryFileResultDto,
            RepositoryPackageDto,
            RepositoryAnalysisMetadataDto,
            RepositoryConfigCapsDto,
            RepositoryDescriptorDto
        )
    ),
    tags(
    (name = "analysis", description = "Vulnerability analysis endpoints for dependency files and repositories"),
        (name = "vulnerabilities", description = "Vulnerability information and lookup endpoints"),
        (name = "health", description = "System health monitoring and metrics endpoints")
    ),
    info(
        title = "Vulnera API",
        version = "1.0.0",
        description = "A comprehensive vulnerability analysis API for multiple programming language ecosystems. Supports analysis of dependency files from npm, PyPI, Maven, Cargo, Go modules, and Composer ecosystems.",
        license(
            name = "AGPL-3.0",
            url = "https://www.gnu.org/licenses/agpl-3.0.html"
        )
    ),
    servers(
        (url = "http://localhost:3000", description = "Local development server"),

        (url = "VULNERA__SERVER__HOST", description = "Production server")
    ),
    external_docs(
        description = "Find more information about Vulnera",
        url = "https://github.com/k5602/Vulnera"
    )
)]
pub struct ApiDoc;

/// Create the application router with comprehensive middleware stack
pub fn create_router(app_state: AppState, config: &Config) -> Router {
    let api_routes = Router::new()
        .route("/analyze", post(analyze_dependencies))
        .route(
            "/analyze/repository",
            post(crate::presentation::controllers::analysis::analyze_repository),
        )
        .route("/vulnerabilities", get(list_vulnerabilities))
        .route(
            "/vulnerabilities/refresh-cache",
            post(refresh_vulnerability_cache),
        )
        .route("/vulnerabilities/{id}", get(get_vulnerability))
        .route("/reports/{id}", get(get_analysis_report));

    let health_routes = Router::new()
        .route("/health", get(health_check))
        .route("/metrics", get(metrics));

    // Build CORS layer from configuration
    let cors_layer =
        if config.server.allowed_origins.len() == 1 && config.server.allowed_origins[0] == "*" {
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::PUT,
                    axum::http::Method::DELETE,
                    axum::http::Method::OPTIONS,
                ])
                .allow_headers([
                    axum::http::header::CONTENT_TYPE,
                    axum::http::header::AUTHORIZATION,
                    axum::http::header::ACCEPT,
                    axum::http::header::USER_AGENT,
                    axum::http::header::ORIGIN,
                    axum::http::header::ACCESS_CONTROL_REQUEST_METHOD,
                    axum::http::header::ACCESS_CONTROL_REQUEST_HEADERS,
                    axum::http::HeaderName::from_static("x-ghsa-token"),
                    axum::http::HeaderName::from_static("x-github-token"),
                ])
                .allow_credentials(false)
                .max_age(Duration::from_secs(3600))
        } else {
            let mut layer = CorsLayer::new();
            for origin in &config.server.allowed_origins {
                match axum::http::HeaderValue::from_str(origin) {
                    Ok(origin_header) => {
                        layer = layer.allow_origin(origin_header);
                    }
                    Err(_) => {
                        tracing::warn!(origin, "Invalid CORS origin in config; skipping");
                    }
                }
            }
            layer
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::PUT,
                    axum::http::Method::DELETE,
                    axum::http::Method::OPTIONS,
                ])
                .allow_headers([
                    axum::http::header::CONTENT_TYPE,
                    axum::http::header::AUTHORIZATION,
                    axum::http::header::ACCEPT,
                    axum::http::header::USER_AGENT,
                    axum::http::header::ORIGIN,
                    axum::http::header::ACCESS_CONTROL_REQUEST_METHOD,
                    axum::http::header::ACCESS_CONTROL_REQUEST_HEADERS,
                    axum::http::HeaderName::from_static("x-ghsa-token"),
                    axum::http::HeaderName::from_static("x-github-token"),
                ])
                .allow_credentials(false)
                .max_age(Duration::from_secs(3600))
        };
    let mut router = Router::new()
        .nest("/api/v1", api_routes)
        .merge(health_routes);

    // Conditionally expose Swagger UI based on configuration (avoid leaking docs in production).
    if config.server.enable_docs {
        router =
            router.merge(SwaggerUi::new("/docs").url("/api-docs/openapi.json", ApiDoc::openapi()));
    }

    let service_builder = ServiceBuilder::new()
        // HTTP tracing
        .layer(TraceLayer::new_for_http())
        // CORS handling
        .layer(cors_layer)
        // Request timeout (30 seconds)
        .layer(TimeoutLayer::new(Duration::from_secs(
            config.server.request_timeout_seconds,
        )))
        // Per-request GHSA token middleware (must run before handlers)
        .layer(middleware::from_fn(ghsa_token_middleware))
        // Custom logging middleware
        .layer(middleware::from_fn(logging_middleware));

    // Conditionally add security headers middleware
    if config.server.security.enable_security_headers {
        router = router.layer(middleware::from_fn(security_headers_middleware));
    }

    // Conditionally add HTTPS enforcement middleware
    if config.server.security.enforce_https {
        router = router.layer(middleware::from_fn(https_enforcement_middleware));
    }

    router
        // Serve documentation resources
        .route("/docs/examples", get(serve_api_examples))
        .route("/docs/versioning", get(serve_versioning_info))
        .layer(service_builder)
        .with_state(app_state)
}

/// Serve API examples and usage guide
async fn serve_api_examples() -> Response {
    let examples_content = include_str!("../../docs/api-examples.md");

    // Convert markdown to HTML (basic conversion for now)
    let html_content = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnera API Examples</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
            color: #333;
        }}
        h1, h2, h3 {{ color: #2563eb; }}
        pre {{
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 6px;
            overflow-x: auto;
            border-left: 4px solid #2563eb;
        }}
        code {{
            background: #f1f5f9;
            padding: 0.2rem 0.4rem;
            border-radius: 3px;
            font-family: 'Monaco', 'Consolas', monospace;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }}
        th, td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #e5e7eb;
        }}
        th {{
            background-color: #f8fafc;
            font-weight: 600;
        }}
        .nav {{
            background: #2563eb;
            color: white;
            padding: 1rem;
            margin: -2rem -2rem 2rem -2rem;
            border-radius: 0;
        }}
        .nav a {{
            color: white;
            text-decoration: none;
            margin-right: 1rem;
        }}
        .nav a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="nav">
        <a href="/docs">← Back to API Documentation</a>
        <a href="/health">Health Check</a>
        <a href="/metrics">Metrics</a>
    </div>
    <pre>{}</pre>
</body>
</html>"#,
        examples_content.replace("<", "&lt;").replace(">", "&gt;")
    );

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "public, max-age=3600")
        .body(html_content.into())
        .unwrap()
}

/// Serve API versioning and deprecation information
async fn serve_versioning_info() -> Response {
    let versioning_content = include_str!("../../docs/api-versioning.md");

    let html_content = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnera API Versioning</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
            color: #333;
        }}
        h1, h2, h3 {{ color: #2563eb; }}
        h1 {{ border-bottom: 2px solid #2563eb; padding-bottom: 0.5rem; }}
        pre {{
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 6px;
            overflow-x: auto;
            border-left: 4px solid #2563eb;
        }}
        code {{
            background: #f1f5f9;
            padding: 0.2rem 0.4rem;
            border-radius: 3px;
            font-family: 'Monaco', 'Consolas', monospace;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        th, td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #e5e7eb;
        }}
        th {{
            background-color: #2563eb;
            color: white;
            font-weight: 600;
        }}
        tr:hover {{
            background-color: #f8fafc;
        }}
        .nav {{
            background: #2563eb;
            color: white;
            padding: 1rem;
            margin: -2rem -2rem 2rem -2rem;
            border-radius: 0;
        }}
        .nav a {{
            color: white;
            text-decoration: none;
            margin-right: 1rem;
        }}
        .nav a:hover {{
            text-decoration: underline;
        }}
        .version-badge {{
            display: inline-block;
            background: #10b981;
            color: white;
            padding: 0.25rem 0.5rem;
            border-radius: 12px;
            font-size: 0.875rem;
            font-weight: bold;
        }}
        .deprecated-badge {{
            background: #ef4444;
        }}
        .warning {{
            background: #fef3c7;
            border: 1px solid #f59e0b;
            border-radius: 6px;
            padding: 1rem;
            margin: 1rem 0;
        }}
        .info {{
            background: #dbeafe;
            border: 1px solid #3b82f6;
            border-radius: 6px;
            padding: 1rem;
            margin: 1rem 0;
        }}
    </style>
</head>
<body>
    <div class="nav">
        <a href="/docs">← Back to API Documentation</a>
        <a href="/docs/examples">API Examples</a>
        <a href="/health">Health Check</a>
    </div>
    <div class="version-badge">Current: v1.0.0</div>
    <pre>{}</pre>
</body>
</html>"#,
        versioning_content.replace("<", "&lt;").replace(">", "&gt;")
    );

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "public, max-age=3600")
        .header("API-Version", "1.0.0")
        .header("Supported-Versions", "1.0")
        .body(html_content.into())
        .unwrap()
}
