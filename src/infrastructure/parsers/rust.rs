//! Rust ecosystem parsers

use super::traits::PackageFileParser;
use crate::application::errors::ParseError;
use crate::domain::{Ecosystem, Package, Version};
use async_trait::async_trait;

/// Parser for Cargo.toml files
pub struct CargoParser;

impl Default for CargoParser {
    fn default() -> Self {
        Self::new()
    }
}

impl CargoParser {
    pub fn new() -> Self {
        Self
    }

    /// Extract dependencies from TOML section
    fn extract_dependencies(
        &self,
        toml_value: &toml::Value,
        section: &str,
    ) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();

        if let Some(deps) = toml_value.get(section).and_then(|s| s.as_table()) {
            for (name, version_info) in deps {
                let version_str = match version_info {
                    toml::Value::String(v) => v.clone(),
                    toml::Value::Table(t) => {
                        // Handle complex dependency specifications
                        if let Some(version) = t.get("version").and_then(|v| v.as_str()) {
                            version.to_string()
                        } else if t.get("git").is_some() || t.get("path").is_some() {
                            // Skip git and path dependencies for now
                            continue;
                        } else {
                            "0.0.0".to_string()
                        }
                    }
                    _ => "0.0.0".to_string(),
                };

                // Clean version string
                let clean_version = self.clean_cargo_version(&version_str)?;

                let version = Version::parse(&clean_version).map_err(|_| ParseError::Version {
                    version: version_str.clone(),
                })?;

                let package = Package::new(name.clone(), version, Ecosystem::Cargo)
                    .map_err(|e| ParseError::MissingField { field: e })?;

                packages.push(package);
            }
        }

        Ok(packages)
    }

    /// Clean Cargo version specifier
    fn clean_cargo_version(&self, version_str: &str) -> Result<String, ParseError> {
        let version_str = version_str.trim();

        if version_str.is_empty() || version_str == "*" {
            return Ok("0.0.0".to_string());
        }

        // Remove common Cargo prefixes
        let cleaned = if version_str.starts_with('^') || version_str.starts_with('~') {
            &version_str[1..]
        } else if version_str.starts_with(">=") || version_str.starts_with("<=") {
            &version_str[2..]
        } else if version_str.starts_with('>')
            || version_str.starts_with('<')
            || version_str.starts_with('=')
        {
            &version_str[1..]
        } else {
            version_str
        };

        // Handle version ranges (take the first version)
        let cleaned = if let Some(comma_pos) = cleaned.find(',') {
            &cleaned[..comma_pos]
        } else {
            cleaned
        };

        let cleaned = cleaned.trim();

        if cleaned.is_empty() {
            Ok("0.0.0".to_string())
        } else {
            Ok(cleaned.to_string())
        }
    }
}

#[async_trait]
impl PackageFileParser for CargoParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == "Cargo.toml"
    }

    async fn parse_file(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let toml_value: toml::Value = toml::from_str(content)?;
        let mut packages = Vec::new();

        // Extract from dependencies section
        packages.extend(self.extract_dependencies(&toml_value, "dependencies")?);

        // Extract from dev-dependencies section
        packages.extend(self.extract_dependencies(&toml_value, "dev-dependencies")?);

        // Extract from build-dependencies section
        packages.extend(self.extract_dependencies(&toml_value, "build-dependencies")?);

        Ok(packages)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Cargo
    }

    fn priority(&self) -> u8 {
        10 // High priority for Cargo.toml
    }
}

/// Parser for Cargo.lock files
pub struct CargoLockParser;

impl Default for CargoLockParser {
    fn default() -> Self {
        Self::new()
    }
}

impl CargoLockParser {
    pub fn new() -> Self {
        Self
    }

    /// Extract packages from Cargo.lock
    fn extract_lock_packages(&self, toml_value: &toml::Value) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();

        if let Some(packages_array) = toml_value.get("package").and_then(|p| p.as_array()) {
            for package_info in packages_array {
                if let Some(package_table) = package_info.as_table() {
                    let name = package_table
                        .get("name")
                        .and_then(|n| n.as_str())
                        .ok_or_else(|| ParseError::MissingField {
                            field: "package name".to_string(),
                        })?;

                    let version_str = package_table
                        .get("version")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| ParseError::MissingField {
                            field: "package version".to_string(),
                        })?;

                    let version = Version::parse(version_str).map_err(|_| ParseError::Version {
                        version: version_str.to_string(),
                    })?;

                    let package = Package::new(name.to_string(), version, Ecosystem::Cargo)
                        .map_err(|e| ParseError::MissingField { field: e })?;

                    packages.push(package);
                }
            }
        }

        Ok(packages)
    }
}

#[async_trait]
impl PackageFileParser for CargoLockParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == "Cargo.lock"
    }

    async fn parse_file(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let toml_value: toml::Value = toml::from_str(content)?;
        self.extract_lock_packages(&toml_value)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Cargo
    }

    fn priority(&self) -> u8 {
        15 // Higher priority than Cargo.toml for exact versions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cargo_toml_parser() {
        let parser = CargoParser::new();
        let content = r#"
[package]
name = "my-package"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }
reqwest = "^0.11"
clap = "~3.2"

[dev-dependencies]
tokio-test = "0.4"
        "#;

        let packages = parser.parse_file(content).await.unwrap();
        assert_eq!(packages.len(), 5);

        let serde_pkg = packages.iter().find(|p| p.name == "serde").unwrap();
        assert_eq!(serde_pkg.version, Version::parse("1.0").unwrap());
        assert_eq!(serde_pkg.ecosystem, Ecosystem::Cargo);

        let tokio_pkg = packages.iter().find(|p| p.name == "tokio").unwrap();
        assert_eq!(tokio_pkg.version, Version::parse("1.0").unwrap());
    }

    #[tokio::test]
    async fn test_cargo_lock_parser() {
        let parser = CargoLockParser::new();
        let content = r#"
# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 3

[[package]]
name = "serde"
version = "1.0.136"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.17.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
 "pin-project-lite",
]
        "#;

        let packages = parser.parse_file(content).await.unwrap();
        assert_eq!(packages.len(), 2);

        let serde_pkg = packages.iter().find(|p| p.name == "serde").unwrap();
        assert_eq!(serde_pkg.version, Version::parse("1.0.136").unwrap());

        let tokio_pkg = packages.iter().find(|p| p.name == "tokio").unwrap();
        assert_eq!(tokio_pkg.version, Version::parse("1.17.0").unwrap());
    }

    #[test]
    fn test_clean_cargo_version() {
        let parser = CargoParser::new();

        assert_eq!(parser.clean_cargo_version("1.0").unwrap(), "1.0");
        assert_eq!(parser.clean_cargo_version("^1.0").unwrap(), "1.0");
        assert_eq!(parser.clean_cargo_version("~1.0").unwrap(), "1.0");
        assert_eq!(parser.clean_cargo_version(">=1.0").unwrap(), "1.0");
        assert_eq!(parser.clean_cargo_version("1.0, <2.0").unwrap(), "1.0");
        assert_eq!(parser.clean_cargo_version("*").unwrap(), "0.0.0");
    }

    #[test]
    fn test_parser_supports_file() {
        let cargo_parser = CargoParser::new();
        let lock_parser = CargoLockParser::new();

        assert!(cargo_parser.supports_file("Cargo.toml"));
        assert!(!cargo_parser.supports_file("Cargo.lock"));

        assert!(lock_parser.supports_file("Cargo.lock"));
        assert!(!lock_parser.supports_file("Cargo.toml"));
    }
}
