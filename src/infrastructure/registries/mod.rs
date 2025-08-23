/*
 Infrastructure: Package Registry Clients

 This module defines the core abstractions and types to query package registries
 (npm, PyPI, Maven Central, crates.io, Go proxy, Packagist, RubyGems, NuGet, ...).
 Implementations should live in sibling files/modules and conform to the DDD layering:

 - Domain:    Version/Ecosystem types live in crate::domain
 - Application: A VersionResolutionService will orchestrate calls to this trait
 - Infrastructure: Concrete registry clients implement the trait below
*/

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::domain::{Ecosystem, Version};

/// Information about a single published version in a package registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    /// Semantic version (normalized to our domain Version).
    pub version: Version,
    /// Whether this is a pre-release (alpha/beta/rc).
    pub is_prerelease: bool,
    /// Whether this version is yanked/withdrawn/unlisted (when the registry exposes this).
    pub yanked: bool,
    /// Publish timestamp if available from the registry.
    pub published_at: Option<DateTime<Utc>>,
}

impl VersionInfo {
    /// Helper to construct VersionInfo inferring prerelease flag from semver metadata.
    pub fn new(version: Version, yanked: bool, published_at: Option<DateTime<Utc>>) -> Self {
        // semver::Version has `pre` identifiers; non-empty means pre-release
        let is_prerelease = !version.0.pre.is_empty();
        Self {
            version,
            is_prerelease,
            yanked,
            published_at,
        }
    }
}

/// Error type for registry operations.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// HTTP/network-level error (optional status code).
    #[error("registry HTTP error: {message}, status={status:?}")]
    Http {
        message: String,
        status: Option<u16>,
    },

    /// Registry rate-limited the request (consider retry/backoff).
    #[error("registry rate limited the request")]
    RateLimited,

    /// Package not found (or deleted).
    #[error("package not found")]
    NotFound,

    /// Parsing/conversion error (e.g., invalid version format).
    #[error("registry parse error: {0}")]
    Parse(String),

    /// This registry does not support the requested ecosystem.
    #[error("unsupported ecosystem: {0}")]
    UnsupportedEcosystem(Ecosystem),

    /// Any other error condition.
    #[error("registry error: {0}")]
    Other(String),
}

/// Trait for querying package registries for available versions.
/// - Implementations should:
///   - Normalize versions to domain `Version`
///   - Set `is_prerelease` based on semver pre identifiers
///   - Set `yanked`/`unlisted` where supported by the registry (default false if unknown)
///   - Respect rate limits and apply centralized resilience (retry/backoff)
#[async_trait]
pub trait PackageRegistryClient: Send + Sync {
    /// List available versions for a package in a given ecosystem.
    ///
    /// Requirements:
    /// - Return at least all published versions (yanked/unlisted MAY be filtered out by the impl).
    /// - Prefer ascending sort (callers can re-sort as needed).
    /// - Normalize formats to our domain `Version` using best-effort cleaning where ecosystems differ.
    async fn list_versions(
        &self,
        ecosystem: Ecosystem,
        name: &str,
    ) -> Result<Vec<VersionInfo>, RegistryError>;
}

/// Optional blanket helpers for implementations
pub mod helpers {
    use super::*;

    /// Infer `is_prerelease` directly from a domain `Version`.
    #[inline]
    pub fn is_prerelease(version: &Version) -> bool {
        !version.0.pre.is_empty()
    }

    /// Make a VersionInfo from a Version with sane defaults.
    #[inline]
    pub fn make_version_info(version: Version) -> VersionInfo {
        VersionInfo::new(version, false, None)
    }
}

/// Internal: best-effort version parsing with lenient handling for 4-segment versions.
fn parse_version_lenient(s: &str) -> Option<Version> {
    if let Ok(v) = Version::parse(s) {
        return Some(v);
    }
    // Truncate 4th numeric segment if present: e.g., 4.2.11.1 -> 4.2.11
    let parts: Vec<&str> = s.split('-').collect();
    let core = parts[0];
    let pre = if parts.len() > 1 {
        Some(parts[1])
    } else {
        None
    };
    let nums: Vec<&str> = core.split('.').collect();
    if nums.len() > 3 {
        let mut base = format!("{}.{}.{}", nums[0], nums[1], nums[2]);
        if let Some(preid) = pre {
            if !preid.is_empty() {
                base = format!("{}-{}", base, preid);
            }
        }
        Version::parse(&base).ok()
    } else {
        None
    }
}

/// NPM Registry client (https://registry.npmjs.org/{name})
pub struct NpmRegistryClient;

#[async_trait]
impl PackageRegistryClient for NpmRegistryClient {
    async fn list_versions(
        &self,
        ecosystem: Ecosystem,
        name: &str,
    ) -> Result<Vec<VersionInfo>, RegistryError> {
        if ecosystem != Ecosystem::Npm {
            return Err(RegistryError::UnsupportedEcosystem(ecosystem));
        }
        let url = format!("https://registry.npmjs.org/{}", name);
        let resp = reqwest::get(&url).await.map_err(|e| RegistryError::Http {
            message: e.to_string(),
            status: None,
        })?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(RegistryError::NotFound);
        }
        if !resp.status().is_success() {
            return Err(RegistryError::Http {
                message: format!("status {}", resp.status()),
                status: Some(resp.status().as_u16()),
            });
        }

        let json: Value = resp
            .json()
            .await
            .map_err(|e| RegistryError::Parse(e.to_string()))?;
        let versions_obj = json
            .get("versions")
            .and_then(|v| v.as_object())
            .ok_or_else(|| RegistryError::Parse("missing versions object".to_string()))?;

        let mut out: Vec<VersionInfo> = Vec::new();
        for (ver_str, _meta) in versions_obj.iter() {
            if let Some(v) = parse_version_lenient(ver_str).or_else(|| Version::parse(ver_str).ok())
            {
                out.push(VersionInfo::new(v, false, None));
            }
        }
        out.sort_by(|a, b| a.version.cmp(&b.version));
        Ok(out)
    }
}

/// PyPI Registry client (https://pypi.org/pypi/{name}/json)
pub struct PyPiRegistryClient;

#[async_trait]
impl PackageRegistryClient for PyPiRegistryClient {
    async fn list_versions(
        &self,
        ecosystem: Ecosystem,
        name: &str,
    ) -> Result<Vec<VersionInfo>, RegistryError> {
        if ecosystem != Ecosystem::PyPI {
            return Err(RegistryError::UnsupportedEcosystem(ecosystem));
        }
        let url = format!("https://pypi.org/pypi/{}/json", name);
        let resp = reqwest::get(&url).await.map_err(|e| RegistryError::Http {
            message: e.to_string(),
            status: None,
        })?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(RegistryError::NotFound);
        }
        if !resp.status().is_success() {
            return Err(RegistryError::Http {
                message: format!("status {}", resp.status()),
                status: Some(resp.status().as_u16()),
            });
        }

        let json: Value = resp
            .json()
            .await
            .map_err(|e| RegistryError::Parse(e.to_string()))?;
        let releases = json
            .get("releases")
            .and_then(|v| v.as_object())
            .ok_or_else(|| RegistryError::Parse("missing releases".to_string()))?;

        let mut out: Vec<VersionInfo> = Vec::new();
        for (ver_str, files) in releases.iter() {
            let v = match Version::parse(ver_str) {
                Ok(v) => v,
                Err(_) => match parse_version_lenient(ver_str) {
                    Some(v) => v,
                    None => continue,
                },
            };
            // Determine yanked: if all files are yanked true; otherwise false (best-effort)
            let yanked = files
                .as_array()
                .map(|arr| {
                    !arr.is_empty()
                        && arr
                            .iter()
                            .all(|f| f.get("yanked").and_then(|y| y.as_bool()).unwrap_or(false))
                })
                .unwrap_or(false);
            out.push(VersionInfo::new(v, yanked, None));
        }
        out.sort_by(|a, b| a.version.cmp(&b.version));
        Ok(out)
    }
}

/// RubyGems Registry client (https://rubygems.org/api/v1/versions/{name}.json)
pub struct RubyGemsRegistryClient;

#[async_trait]
impl PackageRegistryClient for RubyGemsRegistryClient {
    async fn list_versions(
        &self,
        ecosystem: Ecosystem,
        name: &str,
    ) -> Result<Vec<VersionInfo>, RegistryError> {
        if ecosystem != Ecosystem::RubyGems {
            return Err(RegistryError::UnsupportedEcosystem(ecosystem));
        }
        let url = format!("https://rubygems.org/api/v1/versions/{}.json", name);
        let resp = reqwest::get(&url).await.map_err(|e| RegistryError::Http {
            message: e.to_string(),
            status: None,
        })?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(RegistryError::NotFound);
        }
        if !resp.status().is_success() {
            return Err(RegistryError::Http {
                message: format!("status {}", resp.status()),
                status: Some(resp.status().as_u16()),
            });
        }

        let json: Value = resp
            .json()
            .await
            .map_err(|e| RegistryError::Parse(e.to_string()))?;
        let arr = json
            .as_array()
            .ok_or_else(|| RegistryError::Parse("expected array".to_string()))?;

        let mut out: Vec<VersionInfo> = Vec::new();
        for item in arr {
            let ver_str = item
                .get("number")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if ver_str.is_empty() {
                continue;
            }
            let version = match Version::parse(ver_str) {
                Ok(v) => v,
                Err(_) => match parse_version_lenient(ver_str) {
                    Some(v) => v,
                    None => continue,
                },
            };
            // RubyGems API exposes "prerelease": bool; we derive from semver pre instead
            let yanked = item
                .get("yanked")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            out.push(VersionInfo::new(version, yanked, None));
        }
        out.sort_by(|a, b| a.version.cmp(&b.version));
        Ok(out)
    }
}

/// NuGet Registry client (https://api.nuget.org/v3-flatcontainer/{package}/index.json)
pub struct NuGetRegistryClient;

#[async_trait]
impl PackageRegistryClient for NuGetRegistryClient {
    async fn list_versions(
        &self,
        ecosystem: Ecosystem,
        name: &str,
    ) -> Result<Vec<VersionInfo>, RegistryError> {
        if ecosystem != Ecosystem::NuGet {
            return Err(RegistryError::UnsupportedEcosystem(ecosystem));
        }
        let lower = name.to_ascii_lowercase();
        let url = format!(
            "https://api.nuget.org/v3-flatcontainer/{}/index.json",
            lower
        );
        let resp = reqwest::get(&url).await.map_err(|e| RegistryError::Http {
            message: e.to_string(),
            status: None,
        })?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(RegistryError::NotFound);
        }
        if !resp.status().is_success() {
            return Err(RegistryError::Http {
                message: format!("status {}", resp.status()),
                status: Some(resp.status().as_u16()),
            });
        }

        let json: Value = resp
            .json()
            .await
            .map_err(|e| RegistryError::Parse(e.to_string()))?;
        let arr = json
            .get("versions")
            .and_then(|v| v.as_array())
            .ok_or_else(|| RegistryError::Parse("missing versions".to_string()))?;

        let mut out: Vec<VersionInfo> = Vec::new();
        for v in arr {
            if let Some(ver_str) = v.as_str() {
                if let Some(vv) =
                    parse_version_lenient(ver_str).or_else(|| Version::parse(ver_str).ok())
                {
                    out.push(VersionInfo::new(vv, false, None));
                }
            }
        }
        out.sort_by(|a, b| a.version.cmp(&b.version));
        Ok(out)
    }
}

/// crates.io Registry client (https://crates.io/api/v1/crates/{name})
pub struct CratesIoRegistryClient;

#[async_trait]
impl PackageRegistryClient for CratesIoRegistryClient {
    async fn list_versions(
        &self,
        ecosystem: Ecosystem,
        name: &str,
    ) -> Result<Vec<VersionInfo>, RegistryError> {
        if ecosystem != Ecosystem::Cargo {
            return Err(RegistryError::UnsupportedEcosystem(ecosystem));
        }
        let url = format!("https://crates.io/api/v1/crates/{}", name);
        let resp = reqwest::get(&url).await.map_err(|e| RegistryError::Http {
            message: e.to_string(),
            status: None,
        })?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(RegistryError::NotFound);
        }
        if !resp.status().is_success() {
            return Err(RegistryError::Http {
                message: format!("status {}", resp.status()),
                status: Some(resp.status().as_u16()),
            });
        }

        #[derive(Deserialize)]
        struct CratesIoVersion {
            num: String,
            yanked: bool,
            #[serde(default)]
            created_at: Option<String>,
        }
        #[derive(Deserialize)]
        struct CratesIoResponse {
            versions: Vec<CratesIoVersion>,
        }

        let json: CratesIoResponse = resp
            .json()
            .await
            .map_err(|e| RegistryError::Parse(e.to_string()))?;

        let mut out: Vec<VersionInfo> = Vec::new();
        for v in json.versions {
            let version = match Version::parse(&v.num) {
                Ok(v) => v,
                Err(_) => match parse_version_lenient(&v.num) {
                    Some(v) => v,
                    None => continue,
                },
            };
            let published_at = v
                .created_at
                .as_deref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc));
            out.push(VersionInfo::new(version, v.yanked, published_at));
        }
        out.sort_by(|a, b| a.version.cmp(&b.version));
        Ok(out)
    }
}

/// Packagist (Composer) Registry client (https://repo.packagist.org/packages/{name}.json)
pub struct PackagistRegistryClient;

#[async_trait]
impl PackageRegistryClient for PackagistRegistryClient {
    async fn list_versions(
        &self,
        ecosystem: Ecosystem,
        name: &str,
    ) -> Result<Vec<VersionInfo>, RegistryError> {
        if ecosystem != Ecosystem::Packagist {
            return Err(RegistryError::UnsupportedEcosystem(ecosystem));
        }
        let url = format!("https://repo.packagist.org/packages/{}.json", name);
        let resp = reqwest::get(&url).await.map_err(|e| RegistryError::Http {
            message: e.to_string(),
            status: None,
        })?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(RegistryError::NotFound);
        }
        if !resp.status().is_success() {
            return Err(RegistryError::Http {
                message: format!("status {}", resp.status()),
                status: Some(resp.status().as_u16()),
            });
        }

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| RegistryError::Parse(e.to_string()))?;

        let versions_obj = json
            .get("package")
            .and_then(|p| p.get("versions"))
            .and_then(|v| v.as_object())
            .ok_or_else(|| RegistryError::Parse("missing package.versions".to_string()))?;

        let mut out: Vec<VersionInfo> = Vec::new();
        for (ver_str, _meta) in versions_obj.iter() {
            if let Some(v) = parse_version_lenient(ver_str).or_else(|| Version::parse(ver_str).ok())
            {
                out.push(VersionInfo::new(v, false, None));
            }
        }

        out.sort_by(|a, b| a.version.cmp(&b.version));
        Ok(out)
    }
}

/// Go module proxy client (https://proxy.golang.org/{module}/@v/list)
pub struct GoProxyRegistryClient;

#[async_trait]
impl PackageRegistryClient for GoProxyRegistryClient {
    async fn list_versions(
        &self,
        ecosystem: Ecosystem,
        name: &str,
    ) -> Result<Vec<VersionInfo>, RegistryError> {
        if ecosystem != Ecosystem::Go {
            return Err(RegistryError::UnsupportedEcosystem(ecosystem));
        }
        let url = format!("https://proxy.golang.org/{}/@v/list", name);
        let resp = reqwest::get(&url).await.map_err(|e| RegistryError::Http {
            message: e.to_string(),
            status: None,
        })?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(RegistryError::NotFound);
        }
        if !resp.status().is_success() {
            return Err(RegistryError::Http {
                message: format!("status {}", resp.status()),
                status: Some(resp.status().as_u16()),
            });
        }

        let body = resp
            .text()
            .await
            .map_err(|e| RegistryError::Parse(e.to_string()))?;

        let mut out: Vec<VersionInfo> = Vec::new();
        for line in body.lines() {
            let ver_str = line.trim();
            if ver_str.is_empty() {
                continue;
            }
            if let Some(v) = parse_version_lenient(ver_str).or_else(|| Version::parse(ver_str).ok())
            {
                out.push(VersionInfo::new(v, false, None));
            }
        }

        out.sort_by(|a, b| a.version.cmp(&b.version));
        Ok(out)
    }
}

/// Maven Central client (https://repo1.maven.org/maven2/{groupPath}/{artifact}/maven-metadata.xml)
pub struct MavenCentralRegistryClient;

#[async_trait]
impl PackageRegistryClient for MavenCentralRegistryClient {
    async fn list_versions(
        &self,
        ecosystem: Ecosystem,
        name: &str,
    ) -> Result<Vec<VersionInfo>, RegistryError> {
        if ecosystem != Ecosystem::Maven {
            return Err(RegistryError::UnsupportedEcosystem(ecosystem));
        }
        let parts: Vec<&str> = name.split(':').collect();
        if parts.len() != 2 {
            return Err(RegistryError::Parse(
                "maven package name must be 'group:artifact'".to_string(),
            ));
        }
        let group_path = parts[0].replace('.', "/");
        let artifact = parts[1];
        let url = format!(
            "https://repo1.maven.org/maven2/{}/{}/maven-metadata.xml",
            group_path, artifact
        );
        let resp = reqwest::get(&url).await.map_err(|e| RegistryError::Http {
            message: e.to_string(),
            status: None,
        })?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(RegistryError::NotFound);
        }
        if !resp.status().is_success() {
            return Err(RegistryError::Http {
                message: format!("status {}", resp.status()),
                status: Some(resp.status().as_u16()),
            });
        }

        let xml = resp
            .text()
            .await
            .map_err(|e| RegistryError::Parse(e.to_string()))?;

        let mut out: Vec<VersionInfo> = Vec::new();
        let mut reader = quick_xml::Reader::from_str(&xml);
        let mut buf = Vec::new();
        let mut in_version_tag = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(quick_xml::events::Event::Start(e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if name == "version" {
                        in_version_tag = true;
                    }
                }
                Ok(quick_xml::events::Event::End(e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if name == "version" {
                        in_version_tag = false;
                    }
                }
                Ok(quick_xml::events::Event::Text(t)) => {
                    if in_version_tag {
                        let txt = reader
                            .decoder()
                            .decode(t.as_ref())
                            .unwrap_or_default()
                            .trim()
                            .to_string();
                        if !txt.is_empty() {
                            if let Some(v) =
                                parse_version_lenient(&txt).or_else(|| Version::parse(&txt).ok())
                            {
                                out.push(VersionInfo::new(v, false, None));
                            }
                        }
                    }
                }
                Ok(quick_xml::events::Event::Eof) => break,
                Err(_e) => break,
                _ => {}
            }
            buf.clear();
        }

        out.sort_by(|a, b| a.version.cmp(&b.version));
        Ok(out)
    }
}

/// A multiplexer registry client that delegates to per-ecosystem clients.
pub struct MultiplexRegistryClient {
    npm: NpmRegistryClient,
    pypi: PyPiRegistryClient,
    rubygems: RubyGemsRegistryClient,
    nuget: NuGetRegistryClient,
    crates: CratesIoRegistryClient,
    packagist: PackagistRegistryClient,
    goproxy: GoProxyRegistryClient,
    maven_central: MavenCentralRegistryClient,
}

impl MultiplexRegistryClient {
    pub fn new() -> Self {
        Self {
            npm: NpmRegistryClient,
            pypi: PyPiRegistryClient,
            rubygems: RubyGemsRegistryClient,
            nuget: NuGetRegistryClient,
            crates: CratesIoRegistryClient,
            packagist: PackagistRegistryClient,
            goproxy: GoProxyRegistryClient,
            maven_central: MavenCentralRegistryClient,
        }
    }
}

impl Default for MultiplexRegistryClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PackageRegistryClient for MultiplexRegistryClient {
    async fn list_versions(
        &self,
        ecosystem: Ecosystem,
        name: &str,
    ) -> Result<Vec<VersionInfo>, RegistryError> {
        match ecosystem {
            Ecosystem::Npm => self.npm.list_versions(ecosystem, name).await,
            Ecosystem::PyPI => self.pypi.list_versions(ecosystem, name).await,
            Ecosystem::RubyGems => self.rubygems.list_versions(ecosystem, name).await,
            Ecosystem::NuGet => self.nuget.list_versions(ecosystem, name).await,
            Ecosystem::Cargo => self.crates.list_versions(ecosystem, name).await,
            Ecosystem::Packagist => self.packagist.list_versions(ecosystem, name).await,
            Ecosystem::Go => self.goproxy.list_versions(ecosystem, name).await,
            Ecosystem::Maven => self.maven_central.list_versions(ecosystem, name).await,
        }
    }
}
