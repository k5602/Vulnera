//! GitHub repository source client implementation (skeleton)

use async_trait::async_trait;
use base64::Engine;
use octocrab::Octocrab;
use serde_json::Value;
use std::sync::Arc;
use tokio::{sync::Semaphore, task::JoinSet};
use tracing::{debug, instrument, warn};

use super::{
    FetchedFileContent, RepositoryFile, RepositorySourceClient, RepositorySourceError,
    RepositorySourceResult,
};

/// GitHub repository client (initial stub)
#[allow(dead_code)]
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
            if !t.trim().is_empty() {
                builder = builder.personal_token(t);
            }
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

        // Resolve reference: use provided ref or fetch repository default branch
        let reference = if let Some(r) = r#ref {
            r.to_string()
        } else {
            let repo_info: Value = self
                .octo
                .get(format!("repos/{}/{}", owner, repo), None::<&()>)
                .await
                .map_err(classify_octocrab_error)?;
            repo_info
                .get("default_branch")
                .and_then(|v| v.as_str())
                .ok_or_else(|| RepositorySourceError::Validation("missing default_branch".into()))?
                .to_string()
        };

        // Use git trees API (recursive)
        let path = format!("repos/{}/{}/git/trees/{}", owner, repo, reference);
        let resp: Value = self
            .octo
            .get(path, Some(&[("recursive", "1")]))
            .await
            .map_err(classify_octocrab_error)?;
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
        concurrent_limit: usize,
    ) -> RepositorySourceResult<Vec<FetchedFileContent>> {
        debug!(
            owner,
            repo,
            file_count = files.len(),
            ?r#ref,
            concurrent_limit,
            "fetch_file_contents start"
        );
        if files.is_empty() {
            return Ok(vec![]);
        }

        let semaphore = Arc::new(Semaphore::new(concurrent_limit.max(1)));
        let mut join_set: JoinSet<(String, Result<Option<String>, RepositorySourceError>)> =
            JoinSet::new();

        for file in files.iter() {
            let permit = semaphore.clone().acquire_owned().await.expect("semaphore");
            let octo = self.octo.clone();
            let path_string = file.path.clone();
            let mut req_path = format!("repos/{}/{}/contents/{}", owner, repo, path_string);
            if let Some(r) = r#ref {
                req_path.push_str(&format!("?ref={}", r));
            }
            join_set.spawn(async move {
                let _p = permit; // hold permit until task ends
                let res: Result<Option<String>, RepositorySourceError> = async {
                    let content_json: Value = octo
                        .get(req_path, None::<&()>)
                        .await
                        .map_err(classify_octocrab_error)?;
                    if let Some(encoded) = content_json.get("content").and_then(|v| v.as_str()) {
                        let cleaned: String =
                            encoded.chars().filter(|c| !c.is_whitespace()).collect();
                        let engine = base64::engine::general_purpose::STANDARD;
                        match engine.decode(cleaned.as_bytes()) {
                            Ok(bytes) => {
                                if let Ok(text) = String::from_utf8(bytes) {
                                    return Ok(Some(text));
                                }
                            }
                            Err(e) => debug!(error=?e, file=%path_string, "base64 decode failed"),
                        }
                    }
                    Ok(None)
                }
                .await;
                (path_string, res)
            });
        }

        let mut results = Vec::with_capacity(files.len());
        while let Some(res) = join_set.join_next().await {
            match res {
                Ok((path, Ok(Some(content)))) => results.push(FetchedFileContent { path, content }),
                Ok((_path, Ok(None))) => {}
                Ok((path, Err(e))) => match e {
                    RepositorySourceError::RateLimited {
                        retry_after,
                        message,
                    } => {
                        warn!(file=%path, ?retry_after, %message, "rate limited fetching file");
                        return Err(RepositorySourceError::RateLimited {
                            retry_after,
                            message,
                        });
                    }
                    other => {
                        debug!(file=%path, error=?other, "file fetch error");
                    }
                },
                Err(join_err) => debug!(error=%join_err, "join error during fetch"),
            }
        }

        Ok(results)
    }
}

fn classify_octocrab_error(e: octocrab::Error) -> RepositorySourceError {
    // Improve classification using message heuristics; fall back to Network
    let msg = e.to_string();
    let lower = msg.to_lowercase();
    if lower.contains("rate limit exceeded") || lower.contains("api rate limit exceeded") {
        return RepositorySourceError::RateLimited {
            retry_after: None,
            message: msg,
        };
    }
    if lower.contains("not found") || lower.contains("404") {
        return RepositorySourceError::NotFound(msg);
    }
    if lower.contains("forbidden")
        || lower.contains("requires authentication")
        || lower.contains("unauthorized")
        || lower.contains("bad credentials")
        || lower.contains("401")
        || lower.contains("403")
    {
        return RepositorySourceError::AccessDenied(msg);
    }
    if lower.contains("unprocessable entity") || lower.contains("422") {
        return RepositorySourceError::Validation(msg);
    }
    RepositorySourceError::Network(msg)
}
