//! PHP ecosystem parsers

use super::traits::PackageFileParser;
use crate::application::errors::ParseError;
use crate::domain::{Ecosystem, Package, Version};
use async_trait::async_trait;
use serde_json::Value;

/// Parser for composer.json files
pub struct ComposerParser;

impl ComposerParser {
    pub fn new() -> Self {
        Self
    }

    /// Extract dependencies from JSON object
    fn extract_dependencies(
        &self,
        json: &Value,
        dep_type: &str,
    ) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();

        if let Some(deps) = json.get(dep_type).and_then(|d| d.as_object()) {
            for (name, version_value) in deps {
                // Skip PHP version requirement
                if name == "php" {
                    continue;
                }

                let version_str =
                    version_value
                        .as_str()
                        .ok_or_else(|| ParseError::MissingField {
                            field: format!("version for package {}", name),
                        })?;

                // Clean version string
                let clean_version = self.clean_composer_version(version_str)?;

                let version = Version::parse(&clean_version).map_err(|_| ParseError::Version {
                    version: version_str.to_string(),
                })?;

                let package = Package::new(name.clone(), version, Ecosystem::Packagist)
                    .map_err(|e| ParseError::MissingField { field: e })?;

                packages.push(package);
            }
        }

        Ok(packages)
    }

    /// Clean Composer version string
    fn clean_composer_version(&self, version_str: &str) -> Result<String, ParseError> {
        let version_str = version_str.trim();

        if version_str.is_empty() || version_str == "*" {
            return Ok("0.0.0".to_string());
        }

        // Remove common Composer prefixes
        let cleaned = if version_str.starts_with('^') || version_str.starts_with('~') {
            &version_str[1..]
        } else if version_str.starts_with(">=") || version_str.starts_with("<=") {
            &version_str[2..]
        } else if version_str.starts_with('>') || version_str.starts_with('<') {
            &version_str[1..]
        } else {
            version_str
        };

        // Handle version ranges (take the first version)
        let cleaned = if let Some(pipe_pos) = cleaned.find('|') {
            &cleaned[..pipe_pos]
        } else if let Some(comma_pos) = cleaned.find(',') {
            &cleaned[..comma_pos]
        } else {
            cleaned
        };

        // Handle stability flags (remove -dev, -alpha, etc. for now)
        let cleaned = if let Some(dash_pos) = cleaned.find('-') {
            let base_part = &cleaned[..dash_pos];
            // Only keep the base if it looks like a version
            if base_part.matches('.').count() >= 1 {
                base_part
            } else {
                cleaned
            }
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
impl PackageFileParser for ComposerParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == "composer.json"
    }

    async fn parse_file(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let json: Value = serde_json::from_str(content)?;
        let mut packages = Vec::new();

        // Extract different types of dependencies
        packages.extend(self.extract_dependencies(&json, "require")?);
        packages.extend(self.extract_dependencies(&json, "require-dev")?);

        Ok(packages)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Packagist
    }

    fn priority(&self) -> u8 {
        10 // High priority for composer.json
    }
}

/// Parser for composer.lock files
pub struct ComposerLockParser;

impl ComposerLockParser {
    pub fn new() -> Self {
        Self
    }

    /// Extract packages from composer.lock
    fn extract_lock_packages(
        &self,
        json: &Value,
        section: &str,
    ) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();

        if let Some(packages_array) = json.get(section).and_then(|p| p.as_array()) {
            for package_info in packages_array {
                if let Some(package_obj) = package_info.as_object() {
                    let name = package_obj
                        .get("name")
                        .and_then(|n| n.as_str())
                        .ok_or_else(|| ParseError::MissingField {
                            field: "package name".to_string(),
                        })?;

                    let version_str = package_obj
                        .get("version")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| ParseError::MissingField {
                            field: "package version".to_string(),
                        })?;

                    // Clean version string (remove 'v' prefix if present)
                    let clean_version = if version_str.starts_with('v') {
                        &version_str[1..]
                    } else {
                        version_str
                    };

                    let version =
                        Version::parse(clean_version).map_err(|_| ParseError::Version {
                            version: version_str.to_string(),
                        })?;

                    let package = Package::new(name.to_string(), version, Ecosystem::Packagist)
                        .map_err(|e| ParseError::MissingField { field: e })?;

                    packages.push(package);
                }
            }
        }

        Ok(packages)
    }
}

#[async_trait]
impl PackageFileParser for ComposerLockParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == "composer.lock"
    }

    async fn parse_file(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let json: Value = serde_json::from_str(content)?;
        let mut packages = Vec::new();

        // Extract from packages section
        packages.extend(self.extract_lock_packages(&json, "packages")?);

        // Extract from packages-dev section
        packages.extend(self.extract_lock_packages(&json, "packages-dev")?);

        Ok(packages)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Packagist
    }

    fn priority(&self) -> u8 {
        15 // Higher priority than composer.json for exact versions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_composer_json_parser() {
        let parser = ComposerParser::new();
        let content = r#"
        {
            "name": "my/project",
            "require": {
                "php": "^8.0",
                "symfony/console": "^5.4",
                "guzzlehttp/guzzle": "~7.0",
                "monolog/monolog": ">=2.0"
            },
            "require-dev": {
                "phpunit/phpunit": "^9.5",
                "symfony/var-dumper": "*"
            }
        }
        "#;

        let packages = parser.parse_file(content).await.unwrap();
        assert_eq!(packages.len(), 5); // Excluding php version

        let symfony_pkg = packages
            .iter()
            .find(|p| p.name == "symfony/console")
            .unwrap();
        assert_eq!(symfony_pkg.version, Version::parse("5.4").unwrap());
        assert_eq!(symfony_pkg.ecosystem, Ecosystem::Packagist);

        let guzzle_pkg = packages
            .iter()
            .find(|p| p.name == "guzzlehttp/guzzle")
            .unwrap();
        assert_eq!(guzzle_pkg.version, Version::parse("7.0").unwrap());
    }

    #[tokio::test]
    async fn test_composer_lock_parser() {
        let parser = ComposerLockParser::new();
        let content = r#"
        {
            "_readme": [
                "This file locks the dependencies of your project to a known state"
            ],
            "packages": [
                {
                    "name": "symfony/console",
                    "version": "v5.4.8",
                    "source": {
                        "type": "git",
                        "url": "https://github.com/symfony/console.git",
                        "reference": "7fccea8728aa2d431a6725b02b3ce759049fc84d"
                    }
                },
                {
                    "name": "monolog/monolog",
                    "version": "2.5.0",
                    "source": {
                        "type": "git",
                        "url": "https://github.com/Seldaek/monolog.git",
                        "reference": "4192345e260f1d51b365536199744b987e160edc"
                    }
                }
            ],
            "packages-dev": [
                {
                    "name": "phpunit/phpunit",
                    "version": "9.5.20",
                    "source": {
                        "type": "git",
                        "url": "https://github.com/sebastianbergmann/phpunit.git",
                        "reference": "12bc8879fb65aef2138b26fc633cb1e3620cffba"
                    }
                }
            ]
        }
        "#;

        let packages = parser.parse_file(content).await.unwrap();
        assert_eq!(packages.len(), 3);

        let symfony_pkg = packages
            .iter()
            .find(|p| p.name == "symfony/console")
            .unwrap();
        assert_eq!(symfony_pkg.version, Version::parse("5.4.8").unwrap());

        let monolog_pkg = packages
            .iter()
            .find(|p| p.name == "monolog/monolog")
            .unwrap();
        assert_eq!(monolog_pkg.version, Version::parse("2.5.0").unwrap());
    }

    #[test]
    fn test_clean_composer_version() {
        let parser = ComposerParser::new();

        assert_eq!(parser.clean_composer_version("^5.4").unwrap(), "5.4");
        assert_eq!(parser.clean_composer_version("~7.0").unwrap(), "7.0");
        assert_eq!(parser.clean_composer_version(">=2.0").unwrap(), "2.0");
        assert_eq!(parser.clean_composer_version("*").unwrap(), "0.0.0");
        assert_eq!(parser.clean_composer_version("5.4|6.0").unwrap(), "5.4");
        assert_eq!(parser.clean_composer_version("2.5.0-dev").unwrap(), "2.5.0");
    }

    #[test]
    fn test_parser_supports_file() {
        let composer_parser = ComposerParser::new();
        let lock_parser = ComposerLockParser::new();

        assert!(composer_parser.supports_file("composer.json"));
        assert!(!composer_parser.supports_file("composer.lock"));

        assert!(lock_parser.supports_file("composer.lock"));
        assert!(!lock_parser.supports_file("composer.json"));
    }
}
