//! Infrastructure Layer - External concerns and implementations
//!
//! This module handles external systems like APIs, file systems, and databases.

pub mod api_clients;
pub mod cache;
pub mod parsers;
pub mod repositories;
pub mod resilience;

pub use api_clients::*;
pub use cache::*;
pub use parsers::*;
pub use repositories::*;
pub use resilience::*;
