//! GitHub repository source client implementation (skeleton)

use async_trait::async_trait;
use base64::Engine;
use octocrab::Octocrab;
use serde_json::Value;
use tracing::{debug, instrument};

use super::{
    FetchedFileContent, RepositoryFile, RepositorySourceClient, RepositorySourceError,
    RepositorySourceResult,
};

/// GitHub repository client (initial stub)
pub struct GitHubRepositoryClient {
    octo: Octocrab,
    base_url: String,
    reuse_token_for_ghsa: bool,
    timeout_seconds: u64,
}

impl GitHubRepositoryClient {
    pub fn new(
        octo: Octocrab,
        base_url: String,
        reuse_token_for_ghsa: bool,
        timeout_seconds: u64,
    ) -> Self {
        Self {
            octo,
            base_url,
            reuse_token_for_ghsa,
            timeout_seconds,
        }
    }

    pub async fn from_token(
        token: Option<String>,
        base_url: Option<String>,
        timeout_seconds: u64,
        reuse_token_for_ghsa: bool,
    ) -> Result<Self, RepositorySourceError> {
        let mut builder = Octocrab::builder();
        if let Some(url) = &base_url {
            builder = builder
                .base_uri(url)
                .map_err(|e| RepositorySourceError::Configuration(e.to_string()))?;
        }
        if let Some(t) = token {
            builder = builder.personal_token(t);
        }
        let octo = match builder.build() {
            Ok(o) => o,
            Err(e) => {
                return Err(RepositorySourceError::Internal(e.to_string()));
            }
        };
        Ok(Self {
            octo,
            base_url: base_url.unwrap_or_else(|| "https://api.github.com".into()),
            reuse_token_for_ghsa,
            timeout_seconds,
        })
    }
}

#[async_trait]
impl RepositorySourceClient for GitHubRepositoryClient {
    #[instrument(skip(self))]
    async fn list_repository_files(
        &self,
        owner: &str,
        repo: &str,
        r#ref: Option<&str>,
        max_files: u32,
        _max_bytes: u64,
    ) -> RepositorySourceResult<Vec<RepositoryFile>> {
        debug!(
            owner,
            repo,
            ?r#ref,
            max_files,
            "list_repository_files start"
        );
        let reference = r#ref.unwrap_or("HEAD");
        // Use git trees API (recursive)
        let path = format!(
            "repos/{}/{}/git/trees/{}?recursive=1",
            owner, repo, reference
        );
        let resp: Value = self
            .octo
            .get(path, None::<&()>)
            .await
            .map_err(|e| RepositorySourceError::Network(e.to_string()))?;
        let mut files = Vec::new();
        if let Some(entries) = resp.get("tree").and_then(|t| t.as_array()) {
            for entry in entries {
                if files.len() as u32 >= max_files {
                    break;
                }
                if entry.get("type").and_then(|v| v.as_str()) == Some("blob") {
                    if let (Some(path), Some(size)) = (
                        entry.get("path").and_then(|v| v.as_str()),
                        entry.get("size").and_then(|v| v.as_u64()),
                    ) {
                        files.push(RepositoryFile {
                            path: path.to_string(),
                            size,
                            is_text: true,
                        });
                    }
                }
            }
        }
        Ok(files)
    }

    #[instrument(skip(self, files))]
    async fn fetch_file_contents(
        &self,
        owner: &str,
        repo: &str,
        files: &[RepositoryFile],
        r#ref: Option<&str>,
        _single_file_max_bytes: u64,
        _concurrent_limit: usize,
    ) -> RepositorySourceResult<Vec<FetchedFileContent>> {
        debug!(
            owner,
            repo,
            file_count = files.len(),
            ?r#ref,
            "fetch_file_contents start"
        );
        let mut results = Vec::with_capacity(files.len());
        for file in files {
            let path = format!("repos/{}/{}/contents/{}", owner, repo, file.path);
            let content_json: Value = self
                .octo
                .get(path, None::<&()>)
                .await
                .map_err(|e| RepositorySourceError::Network(e.to_string()))?;
            if let Some(encoded) = content_json.get("content").and_then(|v| v.as_str()) {
                // GitHub returns base64 with newlines
                let cleaned: String = encoded.chars().filter(|c| !c.is_whitespace()).collect();
                let engine = base64::engine::general_purpose::STANDARD;
                match engine.decode(cleaned.as_bytes()) {
                    Ok(bytes) => {
                        if let Ok(text) = String::from_utf8(bytes) {
                            results.push(FetchedFileContent {
                                path: file.path.clone(),
                                content: text,
                            });
                        }
                    }
                    Err(e) => debug!(error=?e, file=%file.path, "base64 decode failed"),
                }
            }
        }
        Ok(results)
    }
}
