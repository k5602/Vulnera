//! GitHub repository source client implementation (skeleton)

use async_trait::async_trait;
use octocrab::Octocrab;
use tracing::{debug, instrument};

use super::{FetchedFileContent, RepositoryFile, RepositorySourceClient, RepositorySourceError, RepositorySourceResult};

/// GitHub repository client (initial stub)
pub struct GitHubRepositoryClient {
    octo: Octocrab,
    base_url: String,
    reuse_token_for_ghsa: bool,
    timeout_seconds: u64,
}

impl GitHubRepositoryClient {
    pub fn new(octo: Octocrab, base_url: String, reuse_token_for_ghsa: bool, timeout_seconds: u64) -> Self {
        Self { octo, base_url, reuse_token_for_ghsa, timeout_seconds }
    }

    pub fn from_token(token: Option<String>, base_url: Option<String>, timeout_seconds: u64, reuse_token_for_ghsa: bool) -> Result<Self, RepositorySourceError> {
        let mut builder = Octocrab::builder();
    if let Some(url) = &base_url { builder = builder.base_uri(url).map_err(|e| RepositorySourceError::Configuration(e.to_string()))?; }
        if let Some(t) = token { builder = builder.personal_token(t); }
        let octo = builder.build().map_err(|e| RepositorySourceError::Internal(e.to_string()))?;
        Ok(Self { octo, base_url: base_url.unwrap_or_else(|| "https://api.github.com".into()), reuse_token_for_ghsa, timeout_seconds })
    }
}

#[async_trait]
impl RepositorySourceClient for GitHubRepositoryClient {
    #[instrument(skip(self))]
    async fn list_repository_files(&self, owner: &str, repo: &str, r#ref: Option<&str>, max_files: u32, _max_bytes: u64) -> RepositorySourceResult<Vec<RepositoryFile>> {
        // Placeholder: in final version we'll walk the git tree via the Git Data API
        debug!(owner, repo, ?r#ref, max_files, "list_repository_files (stub)");
        Ok(vec![])
    }

    #[instrument(skip(self, files))]
    async fn fetch_file_contents(&self, owner: &str, repo: &str, files: &[RepositoryFile], r#ref: Option<&str>, _single_file_max_bytes: u64, _concurrent_limit: usize) -> RepositorySourceResult<Vec<FetchedFileContent>> {
        debug!(owner, repo, file_count = files.len(), ?r#ref, "fetch_file_contents (stub)");
        Ok(vec![])
    }
}
