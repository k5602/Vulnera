# Axum Web Framework Research

## Overview
Axum is an ergonomic and modular web framework built with Tokio, Tower, and Hyper. It focuses on providing a macro-free API for building web applications with excellent performance and developer experience.

## Key Features

### Architecture
- Built on top of Tower ecosystem for middleware
- Uses Hyper for HTTP implementation
- Fully async with Tokio runtime
- Macro-free API design

### Routing System
- Declarative routing with `Router::new()`
- Support for path parameters: `/{id}`, `/{*path}`
- Method-specific handlers: `get()`, `post()`, `put()`, `delete()`
- Route merging and nesting capabilities
- Fallback handlers for unmatched routes

### Middleware Integration
- Tower middleware ecosystem compatibility
- Multiple application points:
  - `Router::layer()` - applies to all routes
  - `Router::route_layer()` - applies only to matched routes
  - `MethodRouter::layer()` - applies to specific method handlers
- ServiceBuilder for composing multiple middleware layers

### State Management
- Type-safe state injection with `State<T>` extractor
- `Router::with_state()` for providing application state
- State can be any `Clone` type

### Error Handling
- `HandleErrorLayer` for converting middleware errors to responses
- Custom error types with `IntoResponse` trait
- Graceful error propagation through middleware stack

## Code Examples

### Basic Server Setup
```rust
use axum::{
    routing::{get, post},
    http::StatusCode,
    Json, Router,
};
use serde::{Deserialize, Serialize};

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(root))
        .route("/users", post(create_user));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

### Middleware Application
```rust
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

let app = Router::new()
    .route("/", get(handler))
    .layer(
        ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            .layer(Extension(State {}))
    );
```

### Route Parameters
```rust
use axum::extract::Path;

async fn show_user(Path(id): Path<u64>) -> String {
    format!("User ID: {}", id)
}

async fn user_action(Path((version, id)): Path<(String, u64)>) -> String {
    format!("Version: {}, User ID: {}", version, id)
}

let app = Router::new()
    .route("/users/{id}", get(show_user))
    .route("/api/{version}/users/{id}", get(user_action));
```

## Performance Characteristics
- Sub-millisecond response times for simple handlers
- Efficient connection pooling with Hyper
- Zero-cost abstractions for extractors
- Minimal memory overhead

## Integration Points
- Works seamlessly with Tower middleware
- Compatible with tower-http middleware collection
- Integrates with tracing for observability
- Supports various body types and extractors

## Best Practices
1. Use `ServiceBuilder` for multiple middleware layers
2. Apply middleware at appropriate levels (router vs route vs handler)
3. Leverage type-safe extractors for request data
4. Use `HandleErrorLayer` for fallible middleware
5. Structure applications with nested routers for modularity

## Dependencies Required
```toml
[dependencies]
axum = "0.8.4"
axum-serde = "0.9.0"
axum-tasks = "0.1.0"
tokio = { version = "1.47", features = ["full"] }
tower = "0.4"
axum-prometheus = "0.9.0"
axum-valid = "0.24.0"
tower-http = "0.5"
axum_doc = "0.1.1"
axum-restful = "0.5.0"
axum-test = "17.3.0"
serde = { version = "1.0.219", features = ["derive"] }
serde_valid = "1.0.5"
```