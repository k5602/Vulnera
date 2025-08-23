//! Go ecosystem parsers

use super::traits::PackageFileParser;
use crate::application::errors::ParseError;
use crate::domain::{Ecosystem, Package, Version};
use async_trait::async_trait;

/// Parser for go.mod files
pub struct GoModParser;

impl Default for GoModParser {
    fn default() -> Self {
        Self::new()
    }
}

impl GoModParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse go.mod file content
    fn parse_go_mod(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();
        let mut in_require_block = false;

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with("//") {
                continue;
            }

            // Handle require block
            if line.starts_with("require (") {
                in_require_block = true;
                continue;
            } else if line == ")" && in_require_block {
                in_require_block = false;
                continue;
            }

            // Parse require statements
            if line.starts_with("require ") || in_require_block {
                if let Some(package) = self.parse_require_line(line)? {
                    packages.push(package);
                }
            }
        }

        Ok(packages)
    }

    /// Parse a single require line
    fn parse_require_line(&self, line: &str) -> Result<Option<Package>, ParseError> {
        let line = line.trim();

        // Remove "require " prefix if present
        let line = if let Some(stripped) = line.strip_prefix("require ") {
            stripped
        } else {
            line
        };

        // Skip lines that don't look like dependencies
        if line.is_empty() || line.starts_with("//") || line == "(" || line == ")" {
            return Ok(None);
        }

        // Parse module path and version
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return Ok(None);
        }

        let module_path = parts[0];
        let version_str = parts[1];

        // Clean version string
        let clean_version = self.clean_go_version(version_str)?;

        let version = Version::parse(&clean_version).map_err(|_| ParseError::Version {
            version: version_str.to_string(),
        })?;

        let package = Package::new(module_path.to_string(), version, Ecosystem::Go)
            .map_err(|e| ParseError::MissingField { field: e })?;

        Ok(Some(package))
    }

    /// Clean Go version string
    fn clean_go_version(&self, version_str: &str) -> Result<String, ParseError> {
        let version_str = version_str.trim();

        if version_str.is_empty() {
            return Ok("0.0.0".to_string());
        }

        // Remove 'v' prefix if present
        let cleaned = if let Some(stripped) = version_str.strip_prefix('v') {
            stripped
        } else {
            version_str
        };

        // Handle pseudo-versions (e.g., v0.0.0-20210101000000-abcdef123456)
        if let Some(dash_pos) = cleaned.find('-') {
            let base_version = &cleaned[..dash_pos];
            // If it's a pseudo-version, use the base version
            if base_version.matches('.').count() >= 2 {
                return Ok(base_version.to_string());
            }
        }

        // Handle +incompatible suffix
        let cleaned = if let Some(stripped) = cleaned.strip_suffix("+incompatible") {
            stripped
        } else {
            cleaned
        };

        Ok(cleaned.to_string())
    }
}

#[async_trait]
impl PackageFileParser for GoModParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == "go.mod"
    }

    async fn parse_file(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        self.parse_go_mod(content)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Go
    }

    fn priority(&self) -> u8 {
        10 // High priority for go.mod
    }
}

/// Parser for go.sum files
pub struct GoSumParser;

impl Default for GoSumParser {
    fn default() -> Self {
        Self::new()
    }
}

impl GoSumParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse go.sum file content
    fn parse_go_sum(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();
        let mut seen_modules = std::collections::HashSet::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines
            if line.is_empty() {
                continue;
            }

            // Parse go.sum line format: module version hash
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let module_path = parts[0];
                let version_str = parts[1];

                // Skip /go.mod entries (they're metadata)
                if version_str.ends_with("/go.mod") {
                    continue;
                }

                // Avoid duplicates (go.sum can have multiple entries per module)
                let module_key = format!("{}@{}", module_path, version_str);
                if seen_modules.contains(&module_key) {
                    continue;
                }
                seen_modules.insert(module_key);

                // Clean version string
                let clean_version = self.clean_go_sum_version(version_str)?;

                let version = Version::parse(&clean_version).map_err(|_| ParseError::Version {
                    version: version_str.to_string(),
                })?;

                let package = Package::new(module_path.to_string(), version, Ecosystem::Go)
                    .map_err(|e| ParseError::MissingField { field: e })?;

                packages.push(package);
            }
        }

        Ok(packages)
    }

    /// Clean Go version string from go.sum
    fn clean_go_sum_version(&self, version_str: &str) -> Result<String, ParseError> {
        let version_str = version_str.trim();

        if version_str.is_empty() {
            return Ok("0.0.0".to_string());
        }

        // Remove 'v' prefix if present
        let cleaned = if let Some(stripped) = version_str.strip_prefix('v') {
            stripped
        } else {
            version_str
        };

        // Handle pseudo-versions
        if let Some(dash_pos) = cleaned.find('-') {
            let base_version = &cleaned[..dash_pos];
            if base_version.matches('.').count() >= 2 {
                return Ok(base_version.to_string());
            }
        }

        // Handle +incompatible suffix
        let cleaned = if let Some(stripped) = cleaned.strip_suffix("+incompatible") {
            stripped
        } else {
            cleaned
        };

        Ok(cleaned.to_string())
    }
}

#[async_trait]
impl PackageFileParser for GoSumParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == "go.sum"
    }

    async fn parse_file(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        self.parse_go_sum(content)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Go
    }

    fn priority(&self) -> u8 {
        12 // Higher priority than go.mod for exact versions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_go_mod_parser() {
        let parser = GoModParser::new();
        let content = r#"
module example.com/myproject

go 1.18

require (
    github.com/gin-gonic/gin v1.8.1
    github.com/stretchr/testify v1.7.1
    golang.org/x/crypto v0.0.0-20220622213112-05595931fe9d
)

require (
    github.com/davecgh/go-spew v1.1.1 // indirect
    github.com/pmezard/go-difflib v1.0.0 // indirect
)
        "#;

        let packages = parser.parse_file(content).await.unwrap();
        assert_eq!(packages.len(), 5);

        let gin_pkg = packages
            .iter()
            .find(|p| p.name == "github.com/gin-gonic/gin")
            .unwrap();
        assert_eq!(gin_pkg.version, Version::parse("1.8.1").unwrap());
        assert_eq!(gin_pkg.ecosystem, Ecosystem::Go);

        let crypto_pkg = packages
            .iter()
            .find(|p| p.name == "golang.org/x/crypto")
            .unwrap();
        assert_eq!(crypto_pkg.version, Version::parse("0.0.0").unwrap());
    }

    #[tokio::test]
    async fn test_go_sum_parser() {
        let parser = GoSumParser::new();
        let content = r#"
github.com/gin-gonic/gin v1.8.1 h1:4+fr/el88TOO3ewCmQr8cx/CtZ/umlIRIs5M4NTNjf8=
github.com/gin-gonic/gin v1.8.1/go.mod h1:ji8BvRH1azfM+SYow9zQ6SZMvR8qOMZHmsCuWR9tTTk=
github.com/stretchr/testify v1.7.1 h1:5TQK59W5E3v0r2duFAb7P95B6hEeOyEnHRa8MjYSMTY=
github.com/stretchr/testify v1.7.1/go.mod h1:6Fq8oRcR53rry900zMqJjRRixrwX3KX962/h/Wwjteg=
        "#;

        let packages = parser.parse_file(content).await.unwrap();
        assert_eq!(packages.len(), 2); // Should skip /go.mod entries

        let gin_pkg = packages
            .iter()
            .find(|p| p.name == "github.com/gin-gonic/gin")
            .unwrap();
        assert_eq!(gin_pkg.version, Version::parse("1.8.1").unwrap());
    }

    #[test]
    fn test_clean_go_version() {
        let parser = GoModParser::new();

        assert_eq!(parser.clean_go_version("v1.8.1").unwrap(), "1.8.1");
        assert_eq!(parser.clean_go_version("1.8.1").unwrap(), "1.8.1");
        assert_eq!(
            parser
                .clean_go_version("v0.0.0-20220622213112-05595931fe9d")
                .unwrap(),
            "0.0.0"
        );
        assert_eq!(
            parser.clean_go_version("v2.0.0+incompatible").unwrap(),
            "2.0.0"
        );
    }

    #[test]
    fn test_parser_supports_file() {
        let mod_parser = GoModParser::new();
        let sum_parser = GoSumParser::new();

        assert!(mod_parser.supports_file("go.mod"));
        assert!(!mod_parser.supports_file("go.sum"));

        assert!(sum_parser.supports_file("go.sum"));
        assert!(!sum_parser.supports_file("go.mod"));
    }
}
