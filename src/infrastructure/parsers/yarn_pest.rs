use async_trait::async_trait;
use pest::Parser;
use pest::iterators::{Pair, Pairs};
use pest_derive::Parser;

use crate::application::errors::ParseError;
use crate::domain::{Ecosystem, Package, Version};

use super::traits::PackageFileParser;

#[derive(Parser)]
#[grammar = "src/infrastructure/parsers/grammars/yarn_lock.pest"]
struct YarnLockPest;

/// Pest-based parser for Yarn v1 lockfiles (yarn.lock).
///
/// Notes:
/// - This is an initial skeleton that uses a permissive grammar to identify entries,
///   extract header key specs, and read the version line.
/// - It attempts to infer package names from header key specs by taking the substring
///   up to the last '@' (to support scoped packages like @scope/name@^1.2.3).
/// - It returns packages with Ecosystem::Npm.
/// - Priority is higher than the legacy YarnLockParser to ensure this runs first when registered.
///
/// Wiring:
/// - Ensure ParserFactory registers `YarnPestParser` before the legacy YarnLockParser and
///   with higher priority (this type returns priority() = 20).
pub struct YarnPestParser;

impl Default for YarnPestParser {
    fn default() -> Self {
        Self::new()
    }
}

impl YarnPestParser {
    pub fn new() -> Self {
        Self
    }

    fn dequote(s: &str) -> String {
        let s = s.trim();
        if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
            s[1..s.len() - 1].to_string()
        } else {
            s.to_string()
        }
    }

    /// Given a header key spec like:
    /// - "lodash@^4.17.21"
    /// - lodash@~4.17.20
    /// - "@babel/core@^7.23.0"
    /// Return the inferred package name:
    /// - lodash
    /// - lodash
    /// - @babel/core
    fn extract_name_from_key_spec(spec: &str) -> Option<String> {
        let raw = Self::dequote(spec);
        let trimmed = raw.trim();

        // Find last '@' and take everything before it as the package name.
        // This handles scoped packages that contain '@' at the start.
        if let Some(idx) = trimmed.rfind('@') {
            // If the '@' is at position 0 (e.g. "@foo"), we can't split; in such case,
            // try to find a second '@' (for scoped packages).
            if idx == 0 {
                // Look for "@scope/name@range"
                if let Some(last) = trimmed[1..].rfind('@') {
                    let split_at = 1 + last;
                    let name = &trimmed[..split_at];
                    if !name.is_empty() {
                        return Some(name.to_string());
                    }
                }
                None
            } else {
                let name = &trimmed[..idx];
                if !name.is_empty() {
                    Some(name.to_string())
                } else {
                    None
                }
            }
        } else {
            // No '@' found; fallback to the whole token if it looks like a bare name
            if !trimmed.is_empty() {
                Some(trimmed.to_string())
            } else {
                None
            }
        }
    }

    fn parse_file_pairs<'a>(&self, content: &'a str) -> Result<Pairs<'a, Rule>, ParseError> {
        YarnLockPest::parse(Rule::file, content).map_err(move |e| ParseError::MissingField {
            field: format!("yarn.lock parse error: {}", e),
        })
    }

    fn process_entry(entry: Pair<'_, Rule>) -> (Vec<String>, Option<String>) {
        // Capture raw entry text up front for fallbacks
        let entry_text = entry.as_str().to_string();

        let mut names: Vec<String> = Vec::new();
        let mut version: Option<String> = None;
        let mut header_text: Option<String> = None;

        for p in entry.clone().into_inner() {
            match p.as_rule() {
                Rule::header => {
                    // Keep raw header text for fallback parsing if needed
                    header_text = Some(p.as_str().to_string());

                    for hp in p.into_inner() {
                        match hp.as_rule() {
                            // Collect names from header key list; key_spec is a silent rule,
                            // so inner pairs are quoted_string or bare_fragment.
                            Rule::key_list => {
                                for ks in hp.into_inner() {
                                    match ks.as_rule() {
                                        Rule::quoted_string | Rule::bare_fragment => {
                                            if let Some(name) =
                                                Self::extract_name_from_key_spec(ks.as_str())
                                            {
                                                names.push(name);
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            // In case grammar surfaces tokens directly (defensive)
                            Rule::quoted_string | Rule::bare_fragment => {
                                if let Some(name) = Self::extract_name_from_key_spec(hp.as_str()) {
                                    names.push(name);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Rule::version_line => {
                    // version_line captures: INDENT "version" quoted_string
                    // Extract via child quoted_string or fallback to raw scan
                    let mut found: Option<String> = None;
                    for vp in p.clone().into_inner() {
                        if vp.as_rule() == Rule::quoted_string {
                            found = Some(Self::dequote(vp.as_str()));
                            break;
                        }
                    }
                    if found.is_none() {
                        let raw = p.as_str();
                        if let Some(start) = raw.find('"') {
                            if let Some(end_off) = raw[start + 1..].find('"') {
                                let end = start + 1 + end_off;
                                found = Some(raw[start + 1..end].to_string());
                            }
                        }
                    }
                    version = found;
                }
                _ => {
                    // ignore other blocks
                }
            }
        }

        // Fallbacks: if header-derived names or version were not found via grammar,
        // try extracting them from raw entry/header text.
        if names.is_empty() {
            if let Some(h) = header_text.as_ref() {
                names = Self::fallback_extract_names_from_header(h);
            } else {
                // Derive header from first line of entry if header node was not present
                let first_line = entry_text.lines().next().unwrap_or(&entry_text);
                names = Self::fallback_extract_names_from_header(first_line);
            }
        }

        if version.is_none() {
            version = Self::fallback_extract_version_from_entry(&entry_text);
        }

        // Deduplicate names while preserving order
        let mut unique = Vec::new();
        for n in names {
            if !unique.contains(&n) {
                unique.push(n);
            }
        }

        (unique, version)
    }
    // Fallback: extract names from a header line like:
    //   "lodash@^4.17.21", "@babel/core@^7.22.0":
    //   lodash@~4.17.20:
    fn fallback_extract_names_from_header(header_text: &str) -> Vec<String> {
        let header_line = header_text.lines().next().unwrap_or(header_text);
        let without_colon = header_line.trim_end().trim_end_matches(':').trim();

        let mut out: Vec<String> = Vec::new();
        for spec in without_colon.split(',') {
            let s = spec.trim();
            // Drop surrounding quotes if present
            let s = s.trim_matches('"');
            if let Some(name) = Self::extract_name_from_key_spec(s) {
                if !out.contains(&name) {
                    out.push(name);
                }
            }
        }
        out
    }

    // Fallback: scan entry text for a line starting with 'version "X.Y.Z"'
    fn fallback_extract_version_from_entry(entry_text: &str) -> Option<String> {
        for line in entry_text.lines() {
            let t = line.trim_start();
            if t.starts_with("version ") {
                if let Some(start) = t.find('"') {
                    if let Some(end_off) = t[start + 1..].find('"') {
                        let end = start + 1 + end_off;
                        return Some(t[start + 1..end].to_string());
                    }
                }
            }
        }
        None
    }

    // Final fallback: scan the whole file when Pest parse yields no packages.
    fn fallback_parse_raw(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let mut packages: Vec<Package> = Vec::new();

        let mut current_header: Option<String> = None;
        let mut current_version: Option<String> = None;

        for line in content.lines() {
            let line_trim = line.trim_end();

            // Skip comments and empty lines
            if line_trim.is_empty() || line_trim.starts_with('#') {
                continue;
            }

            // Header line: non-indented and ends with ':'
            if !line.starts_with(' ') && line_trim.ends_with(':') {
                // Flush previous entry if both header and version were seen
                if let (Some(h), Some(v)) = (&current_header, &current_version) {
                    let names = Self::fallback_extract_names_from_header(h);
                    for name in names {
                        let ver = Version::parse(v).unwrap_or_else(|_| Version::new(0, 0, 0));
                        if let Ok(pkg) = Package::new(name, ver.clone(), Ecosystem::Npm) {
                            packages.push(pkg);
                        }
                    }
                }

                current_header = Some(line_trim.to_string());
                current_version = None;
                continue;
            }

            // Version line (indented)
            let t = line.trim_start();
            if t.starts_with("version ") {
                if let Some(start) = t.find('"') {
                    if let Some(end_off) = t[start + 1..].find('"') {
                        let end = start + 1 + end_off;
                        current_version = Some(t[start + 1..end].to_string());
                    }
                }
            }
        }

        // Flush trailing entry
        if let (Some(h), Some(v)) = (current_header, current_version) {
            let names = Self::fallback_extract_names_from_header(&h);
            for name in names {
                let ver = Version::parse(&v).unwrap_or_else(|_| Version::new(0, 0, 0));
                if let Ok(pkg) = Package::new(name, ver.clone(), Ecosystem::Npm) {
                    packages.push(pkg);
                }
            }
        }

        Ok(packages)
    }
}

#[async_trait]
impl PackageFileParser for YarnPestParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == "yarn.lock"
    }

    async fn parse_file(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let pairs = self.parse_file_pairs(content)?;

        let mut packages: Vec<Package> = Vec::new();
        let mut seen = std::collections::HashSet::new();

        // Walk the parse tree to find entries and extract names + versions
        for top in pairs {
            match top.as_rule() {
                Rule::file => {
                    for inner in top.into_inner() {
                        if inner.as_rule() == Rule::entry {
                            let (names, version_opt) = Self::process_entry(inner);
                            if let Some(ver_str) = version_opt {
                                // Parse a semantic-ish version; fall back to "0.0.0" if invalid
                                let version = Version::parse(&ver_str).unwrap_or_else(|_| {
                                    Version::parse("0.0.0")
                                        .unwrap_or_else(|_| Version::new(0, 0, 0))
                                });

                                for name in names {
                                    if seen.insert((name.clone(), version.to_string())) {
                                        if let Ok(pkg) = Package::new(
                                            name.clone(),
                                            version.clone(),
                                            Ecosystem::Npm,
                                        ) {
                                            packages.push(pkg);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Rule::entry => {
                    // In case the top node is directly an entry
                    let (names, version_opt) = Self::process_entry(top);
                    if let Some(ver_str) = version_opt {
                        let version = Version::parse(&ver_str).unwrap_or_else(|_| {
                            Version::parse("0.0.0").unwrap_or_else(|_| Version::new(0, 0, 0))
                        });

                        for name in names {
                            if seen.insert((name.clone(), version.to_string())) {
                                if let Ok(pkg) =
                                    Package::new(name.clone(), version.clone(), Ecosystem::Npm)
                                {
                                    packages.push(pkg);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        if packages.is_empty() {
            return self.fallback_parse_raw(content);
        }
        Ok(packages)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }

    // Higher than legacy YarnLockParser (which is 12) to prefer Pest-based
    fn priority(&self) -> u8 {
        20
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Version;

    #[tokio::test]
    async fn test_basic_yarn_lock_parsing() {
        let content = r#"
# yarn lockfile v1

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
  integrity sha512-...

"@babel/core@^7.22.0", "@babel/core@~7.22.5":
  version "7.22.8"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.22.8.tgz"
  integrity sha512-...
"#;

        let parser = YarnPestParser::new();
        let pkgs = match parser.parse_file(content).await {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!("yarn_pest parse error: {:?}", e);
                panic!("yarn_pest parse error: {:?}", e);
            }
        };

        // Expect lodash and @babel/core captured
        assert!(
            pkgs.iter().any(|p| p.name == "lodash"
                && p.version == Version::parse("4.17.21").unwrap()
                && p.ecosystem == Ecosystem::Npm),
            "Expected lodash@4.17.21 (npm) to be present, got: {:?}",
            pkgs.iter()
                .map(|p| (&p.name, p.version.to_string(), &p.ecosystem))
                .collect::<Vec<_>>()
        );

        assert!(
            pkgs.iter().any(|p| p.name == "@babel/core"
                && p.version == Version::parse("7.22.8").unwrap()
                && p.ecosystem == Ecosystem::Npm),
            "Expected @babel/core@7.22.8 (npm) to be present, got: {:?}",
            pkgs.iter()
                .map(|p| (&p.name, p.version.to_string(), &p.ecosystem))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_extract_name_from_key_spec() {
        // Simple names
        assert_eq!(
            YarnPestParser::extract_name_from_key_spec("lodash@^4.17.21"),
            Some("lodash".to_string())
        );
        // Quoted
        assert_eq!(
            YarnPestParser::extract_name_from_key_spec("\"lodash@^4.17.21\""),
            Some("lodash".to_string())
        );
        // Scoped
        assert_eq!(
            YarnPestParser::extract_name_from_key_spec("\"@babel/core@^7.22.0\""),
            Some("@babel/core".to_string())
        );
        // No '@' fallback
        assert_eq!(
            YarnPestParser::extract_name_from_key_spec("leftpad"),
            Some("leftpad".to_string())
        );
    }

    #[tokio::test]
    async fn test_grouped_headers_parsing() {
        // Multiple grouped header specs should dedupe to a single package name
        let content = r#"
left-pad@^1.3.0, "left-pad@~1.2.0":
  version "1.3.0"
"#;

        let parser = YarnPestParser::new();
        let pkgs = parser.parse_file(content).await.unwrap();

        let count = pkgs.iter().filter(|p| p.name == "left-pad").count();
        assert_eq!(
            count,
            1,
            "Expected exactly one left-pad package entry, got: {:?}",
            pkgs.iter()
                .map(|p| (&p.name, p.version.to_string()))
                .collect::<Vec<_>>()
        );
        assert!(pkgs.iter().any(|p| p.name == "left-pad"
            && p.version == Version::parse("1.3.0").unwrap()
            && p.ecosystem == Ecosystem::Npm));
    }

    #[tokio::test]
    async fn test_dependencies_only_entry() {
        // Entry with dependencies block but missing resolved/integrity should still parse version
        let content = r#"
minimist@^1.2.8:
  version "1.2.8"
  dependencies:
    kind-of "^3.2.2"
"#;

        let parser = YarnPestParser::new();
        let pkgs = parser.parse_file(content).await.unwrap();

        assert!(pkgs.iter().any(|p| p.name == "minimist"
            && p.version == Version::parse("1.2.8").unwrap()
            && p.ecosystem == Ecosystem::Npm));
    }

    #[tokio::test]
    async fn test_integrity_only_entry() {
        // Entry with only version + integrity (no resolved) should still parse version
        let content = r#"
nan@^2.17.0:
  version "2.17.0"
  integrity sha512-ABCDEFG
"#;

        let parser = YarnPestParser::new();
        let pkgs = parser.parse_file(content).await.unwrap();

        assert!(pkgs.iter().any(|p| p.name == "nan"
            && p.version == Version::parse("2.17.0").unwrap()
            && p.ecosystem == Ecosystem::Npm));
    }
}
