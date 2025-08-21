//! Repository Source Abstractions
//!
//! Provides a trait for fetching repository trees and raw file contents from a source (e.g. GitHub).
//! The concrete implementation (GitHubRepositoryClient) will live alongside this trait.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod github_client;
pub mod url_parser;
pub use github_client::GitHubRepositoryClient;
pub use url_parser::{ParsedRepositoryUrl, parse_github_repo_url};

use crate::domain::{Ecosystem, Package};

#[derive(Debug, Error)]
pub enum RepositorySourceError {
    #[error("network error: {0}")]
    Network(String),
    #[error("rate limited: retry_after={retry_after:?} message={message}")]
    RateLimited {
        retry_after: Option<u64>,
        message: String,
    },
    #[error("not found: {0}")]
    NotFound(String),
    #[error("access denied: {0}")]
    AccessDenied(String),
    #[error("validation error: {0}")]
    Validation(String),
    #[error("tree truncated (limit reached)")]
    TreeTruncated,
    #[error("unsupported or binary file: {0}")]
    UnsupportedFile(String),
    #[error("decode error: {0}")]
    Decode(String),
    #[error("internal: {0}")]
    Internal(String),
    #[error("configuration error: {0}")]
    Configuration(String),
}

pub type RepositorySourceResult<T> = Result<T, RepositorySourceError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryFile {
    pub path: String,
    pub size: u64,
    pub is_text: bool,
}

#[derive(Debug, Clone)]
pub struct FetchedFileContent {
    pub path: String,
    pub content: String,
}

/// Represents an extracted package list from a file (parser output)
#[derive(Debug, Clone)]
pub struct ParsedFilePackages {
    pub path: String,
    pub ecosystem: Option<Ecosystem>,
    pub packages: Vec<Package>,
    pub error: Option<String>,
}

#[async_trait]
pub trait RepositorySourceClient: Send + Sync {
    async fn list_repository_files(
        &self,
        owner: &str,
        repo: &str,
        r#ref: Option<&str>,
        max_files: u32,
        max_bytes: u64,
    ) -> RepositorySourceResult<Vec<RepositoryFile>>;

    async fn fetch_file_contents(
        &self,
        owner: &str,
        repo: &str,
        files: &[RepositoryFile],
        r#ref: Option<&str>,
        single_file_max_bytes: u64,
        concurrent_limit: usize,
    ) -> RepositorySourceResult<Vec<FetchedFileContent>>;
}
