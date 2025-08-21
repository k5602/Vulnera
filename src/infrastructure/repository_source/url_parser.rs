//! Utility for parsing GitHub repository URLs into owner/repo and optional ref

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRepositoryUrl {
    pub owner: String,
    pub repo: String,
    pub r#ref: Option<String>,
}

/// Parse common GitHub URL forms:
/// - https://github.com/owner/repo
/// - https://github.com/owner/repo/
/// - https://github.com/owner/repo.git
/// - git@github.com:owner/repo.git
/// - https://github.com/owner/repo/tree/main
/// - https://github.com/owner/repo/tree/main/path (ref = main)
pub fn parse_github_repo_url(input: &str) -> Option<ParsedRepositoryUrl> {
    let trimmed = input.trim();
    if !(trimmed.starts_with("http://github.com")
        || trimmed.starts_with("https://github.com")
        || trimmed.starts_with("git@github.com:"))
    {
        return None;
    }

    if let Some(part) = trimmed.strip_prefix("git@github.com:") {
        let without_git = part.strip_suffix(".git").unwrap_or(part);
        let mut segs = without_git.split('/');
        let owner = segs.next()?.to_string();
        let repo = segs.next()?.to_string();
        if owner.is_empty() || repo.is_empty() {
            return None;
        }
        return Some(ParsedRepositoryUrl {
            owner,
            repo,
            r#ref: None,
        });
    }

    let after = trimmed.split_once("github.com/")?.1;
    let mut parts: Vec<&str> = after.split('/').collect();
    if parts.len() < 2 {
        return None;
    }

    if let Some(pos) = parts.last().and_then(|s| s.find(['?', '#'])) {
        if let Some(last) = parts.last_mut() {
            *last = &last[..pos];
        }
    }

    let owner = parts[0];
    let repo_raw = parts[1];
    if owner.is_empty() || repo_raw.is_empty() {
        return None;
    }
    let repo = repo_raw.strip_suffix(".git").unwrap_or(repo_raw);

    let mut reference: Option<String> = None;
    if parts.len() >= 4 && parts[2] == "tree" {
        reference = Some(parts[3].to_string());
    }

    Some(ParsedRepositoryUrl {
        owner: owner.to_string(),
        repo: repo.to_string(),
        r#ref: reference,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn basic_https() {
        let p = parse_github_repo_url("https://github.com/rust-lang/cargo").unwrap();
        assert_eq!(p.owner, "rust-lang");
        assert_eq!(p.repo, "cargo");
        assert!(p.r#ref.is_none());
    }
    #[test]
    fn with_git_suffix() {
        let p = parse_github_repo_url("https://github.com/rust-lang/cargo.git").unwrap();
        assert_eq!(p.repo, "cargo");
    }
    #[test]
    fn ssh_form() {
        let p = parse_github_repo_url("git@github.com:rust-lang/cargo.git").unwrap();
        assert_eq!(p.owner, "rust-lang");
    }
    #[test]
    fn tree_ref() {
        let p = parse_github_repo_url("https://github.com/rust-lang/cargo/tree/main").unwrap();
        assert_eq!(p.r#ref.as_deref(), Some("main"));
    }
}
