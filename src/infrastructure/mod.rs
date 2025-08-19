//! Infrastructure Layer - External concerns and implementations
//!
//! This module handles external systems like APIs, file systems, and databases.

pub mod api_clients;
pub mod cache;
pub mod parsers;
pub mod repositories;
pub mod resilience;

// Re-export specific items to avoid ambiguous glob re-exports
pub use api_clients::{
    GhsaClient, NvdClient, OsvClient,
    VulnerabilityApiClient, RawVulnerability
};
pub use cache::*;
pub use parsers::{
    // Go parsers
    GoModParser, GoSumParser,
    // Java parsers
    MavenParser, GradleParser,
    // JavaScript parsers
    NpmParser, PackageLockParser, YarnLockParser,
    // PHP parsers
    ComposerParser, ComposerLockParser,
    // Python parsers
    RequirementsTxtParser, PipfileParser, PyProjectTomlParser,
    // Rust parsers
    CargoParser, CargoLockParser,
    // Traits and factory
    PackageFileParser, ParserFactory
};
pub use repositories::*;
pub use resilience::*;
