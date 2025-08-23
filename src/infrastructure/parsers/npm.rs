//! Node.js ecosystem parsers

use super::traits::PackageFileParser;
use crate::application::errors::ParseError;
use crate::domain::{Ecosystem, Package, Version};
use async_trait::async_trait;
use serde_json::Value;

/// Parser for package.json files
pub struct NpmParser;

impl Default for NpmParser {
    fn default() -> Self {
        Self::new()
    }
}

impl NpmParser {
    pub fn new() -> Self {
        Self
    }

    /// Extract dependencies from a JSON object
    fn extract_dependencies(
        &self,
        json: &Value,
        dep_type: &str,
    ) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();

        if let Some(deps) = json.get(dep_type).and_then(|d| d.as_object()) {
            for (name, version_value) in deps {
                let version_str =
                    version_value
                        .as_str()
                        .ok_or_else(|| ParseError::MissingField {
                            field: format!("version for package {}", name),
                        })?;

                // Clean version string (remove npm-specific prefixes like ^, ~, >=, etc.)
                let clean_version = self.clean_version_string(version_str)?;

                let version = Version::parse(&clean_version).map_err(|_| ParseError::Version {
                    version: version_str.to_string(),
                })?;

                let package = Package::new(name.clone(), version, Ecosystem::Npm)
                    .map_err(|e| ParseError::MissingField { field: e })?;

                packages.push(package);
            }
        }

        Ok(packages)
    }

    /// Clean npm version string by removing prefixes and ranges
    fn clean_version_string(&self, version_str: &str) -> Result<String, ParseError> {
        let version_str = version_str.trim();

        // Handle common npm version patterns
        if version_str.is_empty() {
            return Err(ParseError::Version {
                version: version_str.to_string(),
            });
        }

        // Handle special cases
        if version_str == "*" || version_str == "latest" {
            return Ok("0.0.0".to_string());
        }

        // Remove common prefixes
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
        let cleaned = if let Some(space_pos) = cleaned.find(' ') {
            &cleaned[..space_pos]
        } else {
            cleaned
        };

        // Handle OR conditions (take the first version)
        let cleaned = if let Some(or_pos) = cleaned.find("||") {
            &cleaned[..or_pos]
        } else {
            cleaned
        };

        let cleaned = cleaned.trim();

        if cleaned.is_empty() {
            return Err(ParseError::Version {
                version: version_str.to_string(),
            });
        }

        Ok(cleaned.to_string())
    }
}

#[async_trait]
impl PackageFileParser for NpmParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == "package.json"
    }

    async fn parse_file(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let json: Value = serde_json::from_str(content)?;
        let mut packages = Vec::new();

        // Extract different types of dependencies
        packages.extend(self.extract_dependencies(&json, "dependencies")?);
        packages.extend(self.extract_dependencies(&json, "devDependencies")?);
        packages.extend(self.extract_dependencies(&json, "peerDependencies")?);
        packages.extend(self.extract_dependencies(&json, "optionalDependencies")?);

        Ok(packages)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }

    fn priority(&self) -> u8 {
        10 // High priority for package.json
    }
}

/// Parser for package-lock.json files
pub struct PackageLockParser;

impl Default for PackageLockParser {
    fn default() -> Self {
        Self::new()
    }
}

impl PackageLockParser {
    pub fn new() -> Self {
        Self
    }

    /// Extract packages from lockfile dependencies
    fn extract_lockfile_packages(deps: &Value) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();

        if let Some(deps_obj) = deps.as_object() {
            for (name, dep_info) in deps_obj {
                if let Some(version_str) = dep_info.get("version").and_then(|v| v.as_str()) {
                    let version = Version::parse(version_str).map_err(|_| ParseError::Version {
                        version: version_str.to_string(),
                    })?;

                    let package = Package::new(name.clone(), version, Ecosystem::Npm)
                        .map_err(|e| ParseError::MissingField { field: e })?;

                    packages.push(package);
                }

                // Recursively process nested dependencies
                if let Some(nested_deps) = dep_info.get("dependencies") {
                    packages.extend(Self::extract_lockfile_packages(nested_deps)?);
                }
            }
        }

        Ok(packages)
    }
}

#[async_trait]
impl PackageFileParser for PackageLockParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == "package-lock.json"
    }

    async fn parse_file(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let json: Value = serde_json::from_str(content)?;
        let mut packages = Vec::new();

        // Extract from dependencies section
        if let Some(deps) = json.get("dependencies") {
            packages.extend(Self::extract_lockfile_packages(deps)?);
        }

        // Extract from packages section (npm v7+)
        if let Some(pkgs) = json.get("packages") {
            packages.extend(Self::extract_lockfile_packages(pkgs)?);
        }

        Ok(packages)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }

    fn priority(&self) -> u8 {
        15 // Higher priority than package.json for exact versions
    }
}

/// Parser for yarn.lock files
pub struct YarnLockParser;

impl Default for YarnLockParser {
    fn default() -> Self {
        Self::new()
    }
}

impl YarnLockParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse yarn.lock format which is a custom format
    fn parse_yarn_lock(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();
        let mut current_package: Option<String> = None;
        let mut current_version: Option<String> = None;

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Package declaration line (starts with package name)
            if !line.starts_with(' ') && line.contains('@') && line.ends_with(':') {
                // Save previous package if exists
                if let (Some(name), Some(version)) = (&current_package, &current_version) {
                    if let Ok(parsed_version) = Version::parse(version) {
                        if let Ok(package) =
                            Package::new(name.clone(), parsed_version, Ecosystem::Npm)
                        {
                            packages.push(package);
                        }
                    }
                }

                // Parse new package name
                let package_line = &line[..line.len() - 1]; // Remove trailing ':'
                if let Some(at_pos) = package_line.rfind('@') {
                    current_package = Some(package_line[..at_pos].to_string());
                } else {
                    current_package = Some(package_line.to_string());
                }
                current_version = None;
            }
            // Version line
            else if line.starts_with("version ") {
                let version_str = if let Some(rest) = line.strip_prefix("version ") {
                    rest.strip_prefix('"')
                        .and_then(|v| v.strip_suffix('"'))
                        .unwrap_or(rest)
                } else {
                    line
                };
                current_version = Some(version_str.to_string());
            }
        }

        // Don't forget the last package
        if let (Some(name), Some(version)) = (current_package, current_version) {
            if let Ok(parsed_version) = Version::parse(&version) {
                if let Ok(package) = Package::new(name, parsed_version, Ecosystem::Npm) {
                    packages.push(package);
                }
            }
        }

        Ok(packages)
    }
}

#[async_trait]
impl PackageFileParser for YarnLockParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == "yarn.lock"
    }

    async fn parse_file(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        self.parse_yarn_lock(content)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }

    fn priority(&self) -> u8 {
        12 // Medium-high priority for yarn.lock
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_npm_parser_package_json() {
        let parser = NpmParser::new();
        let content = r#"
        {
            "name": "test-package",
            "version": "1.0.0",
            "dependencies": {
                "express": "^4.17.1",
                "lodash": "~4.17.21"
            },
            "devDependencies": {
                "jest": ">=26.0.0"
            }
        }
        "#;

        let packages = parser.parse_file(content).await.unwrap();
        assert_eq!(packages.len(), 3);

        let express_pkg = packages.iter().find(|p| p.name == "express").unwrap();
        assert_eq!(express_pkg.version, Version::parse("4.17.1").unwrap());
        assert_eq!(express_pkg.ecosystem, Ecosystem::Npm);
    }

    #[tokio::test]
    async fn test_package_lock_parser() {
        let parser = PackageLockParser::new();
        let content = r#"
        {
            "name": "test-package",
            "version": "1.0.0",
            "dependencies": {
                "express": {
                    "version": "4.17.1",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.17.1.tgz"
                },
                "lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
                }
            }
        }
        "#;

        let packages = parser.parse_file(content).await.unwrap();
        assert_eq!(packages.len(), 2);

        let express_pkg = packages.iter().find(|p| p.name == "express").unwrap();
        assert_eq!(express_pkg.version, Version::parse("4.17.1").unwrap());
    }

    #[tokio::test]
    async fn test_yarn_lock_parser() {
        let parser = YarnLockParser::new();
        let content = r#"
# yarn lockfile v1

express@^4.17.1:
  version "4.17.1"
  resolved "https://registry.yarnpkg.com/express/-/express-4.17.1.tgz"

lodash@~4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
        "#;

        let packages = parser.parse_file(content).await.unwrap();
        assert_eq!(packages.len(), 2);

        let express_pkg = packages.iter().find(|p| p.name == "express").unwrap();
        assert_eq!(express_pkg.version, Version::parse("4.17.1").unwrap());
    }

    #[test]
    fn test_clean_version_string() {
        let parser = NpmParser::new();

        assert_eq!(parser.clean_version_string("^4.17.1").unwrap(), "4.17.1");
        assert_eq!(parser.clean_version_string("~4.17.21").unwrap(), "4.17.21");
        assert_eq!(parser.clean_version_string(">=26.0.0").unwrap(), "26.0.0");
        assert_eq!(parser.clean_version_string("4.17.1").unwrap(), "4.17.1");
        assert_eq!(
            parser.clean_version_string("1.0.0 - 2.0.0").unwrap(),
            "1.0.0"
        );
    }

    #[test]
    fn test_parser_supports_file() {
        let npm_parser = NpmParser::new();
        let lock_parser = PackageLockParser::new();
        let yarn_parser = YarnLockParser::new();

        assert!(npm_parser.supports_file("package.json"));
        assert!(!npm_parser.supports_file("package-lock.json"));

        assert!(lock_parser.supports_file("package-lock.json"));
        assert!(!lock_parser.supports_file("package.json"));

        assert!(yarn_parser.supports_file("yarn.lock"));
        assert!(!yarn_parser.supports_file("package.json"));
    }
}
