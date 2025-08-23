//! Infrastructure Layer - External concerns and implementations
//!
//! This module handles external systems like APIs, file systems, and databases.

pub mod api_clients;
pub mod cache;
pub mod parsers;
pub mod registries;
pub mod repositories;
pub mod repository_source;
pub mod resilience;

// Re-export specific items to avoid ambiguous glob conflicts
pub use api_clients::traits::VulnerabilityApiClient;
pub use api_clients::{GhsaClient, NvdClient, OsvClient};
pub use cache::*;
pub use parsers::ParserFactory;
pub use parsers::traits::PackageFileParser;
pub use repositories::*;
pub use repository_source::*;
pub use resilience::*;
