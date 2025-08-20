//! Python ecosystem parsers

use super::traits::PackageFileParser;
use crate::application::errors::ParseError;
use crate::domain::{Ecosystem, Package, Version};
use async_trait::async_trait;

/// Parser for requirements.txt files
pub struct RequirementsTxtParser;

impl RequirementsTxtParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse a single requirement line
    fn parse_requirement_line(&self, line: &str) -> Result<Option<Package>, ParseError> {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            return Ok(None);
        }

        // Skip URLs and VCS requirements for now
        if line.starts_with("http") || line.starts_with("git+") || line.starts_with("-e ") {
            return Ok(None);
        }

        // Parse package name and version specifier
        let (name, version_spec) = if let Some(pos) = line.find("==") {
            (&line[..pos], &line[pos + 2..])
        } else if let Some(pos) = line.find(">=") {
            (&line[..pos], &line[pos + 2..])
        } else if let Some(pos) = line.find("<=") {
            (&line[..pos], &line[pos + 2..])
        } else if let Some(pos) = line.find("~=") {
            (&line[..pos], &line[pos + 2..])
        } else if let Some(pos) = line.find('>') {
            (&line[..pos], &line[pos + 1..])
        } else if let Some(pos) = line.find('<') {
            (&line[..pos], &line[pos + 1..])
        } else {
            // No version specifier, use a default version
            (line, "0.0.0")
        };

        let name = name.trim();
        let version_spec = version_spec.trim();

        // Clean version specifier (remove extras, comments, etc.)
        let clean_version = self.clean_version_spec(version_spec)?;

        let version = Version::parse(&clean_version).map_err(|_| ParseError::Version {
            version: version_spec.to_string(),
        })?;

        let package = Package::new(name.to_string(), version, Ecosystem::PyPI)
            .map_err(|e| ParseError::MissingField { field: e })?;

        Ok(Some(package))
    }

    /// Clean Python version specifier
    fn clean_version_spec(&self, version_spec: &str) -> Result<String, ParseError> {
        let version_spec = version_spec.trim();

        if version_spec.is_empty() {
            return Ok("0.0.0".to_string());
        }

        // Remove comments
        let version_spec = if let Some(comment_pos) = version_spec.find('#') {
            &version_spec[..comment_pos]
        } else {
            version_spec
        };

        // Remove extras (e.g., "requests[security]" -> "requests")
        let version_spec = if let Some(bracket_pos) = version_spec.find('[') {
            &version_spec[..bracket_pos]
        } else {
            version_spec
        };

        // Handle version ranges (take the first version)
        let version_spec = if let Some(comma_pos) = version_spec.find(',') {
            &version_spec[..comma_pos]
        } else {
            version_spec
        };

        let version_spec = version_spec.trim();

        if version_spec.is_empty() {
            Ok("0.0.0".to_string())
        } else {
            Ok(version_spec.to_string())
        }
    }
}

#[async_trait]
impl PackageFileParser for RequirementsTxtParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == "requirements.txt" || filename.ends_with("-requirements.txt")
    }

    async fn parse_file(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();

        for line in content.lines() {
            if let Some(package) = self.parse_requirement_line(line)? {
                packages.push(package);
            }
        }

        Ok(packages)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::PyPI
    }

    fn priority(&self) -> u8 {
        8 // Medium priority for requirements.txt
    }
}

/// Parser for Pipfile files
pub struct PipfileParser;

impl PipfileParser {
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
                        } else {
                            "0.0.0".to_string()
                        }
                    }
                    _ => "0.0.0".to_string(),
                };

                // Clean version string
                let clean_version = self.clean_pipfile_version(&version_str)?;

                let version = Version::parse(&clean_version).map_err(|_| ParseError::Version {
                    version: version_str.clone(),
                })?;

                let package = Package::new(name.clone(), version, Ecosystem::PyPI)
                    .map_err(|e| ParseError::MissingField { field: e })?;

                packages.push(package);
            }
        }

        Ok(packages)
    }

    /// Clean Pipfile version specifier
    fn clean_pipfile_version(&self, version_str: &str) -> Result<String, ParseError> {
        let version_str = version_str.trim();

        if version_str.is_empty() || version_str == "*" || version_str == "latest" {
            return Ok("0.0.0".to_string());
        }

        // Handle complex ranges like ">=2.25.1,<3.0.0"
        if version_str.contains(',') {
            // Extract the first version from a range
            let parts: Vec<&str> = version_str.split(',').collect();
            if let Some(first_part) = parts.first() {
                return self.clean_pipfile_version(first_part);
            }
        }

        // Remove common prefixes
        let cleaned = if version_str.starts_with("==") {
            &version_str[2..]
        } else if version_str.starts_with(">=")
            || version_str.starts_with("<=")
            || version_str.starts_with("~=")
        {
            &version_str[2..]
        } else if version_str.starts_with('>') || version_str.starts_with('<') {
            &version_str[1..]
        } else {
            version_str
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
impl PackageFileParser for PipfileParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == "Pipfile"
    }

    async fn parse_file(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let toml_value: toml::Value = toml::from_str(content)?;
        let mut packages = Vec::new();

        // Extract from packages section
        packages.extend(self.extract_dependencies(&toml_value, "packages")?);

        // Extract from dev-packages section
        packages.extend(self.extract_dependencies(&toml_value, "dev-packages")?);

        Ok(packages)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::PyPI
    }

    fn priority(&self) -> u8 {
        10 // High priority for Pipfile
    }
}

/// Parser for pyproject.toml files
pub struct PyProjectTomlParser;

impl PyProjectTomlParser {
    pub fn new() -> Self {
        Self
    }

    /// Extract dependencies from pyproject.toml
    fn extract_pyproject_dependencies(
        &self,
        toml_value: &toml::Value,
    ) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();

        // Extract from project.dependencies
        if let Some(project) = toml_value.get("project") {
            if let Some(deps) = project.get("dependencies").and_then(|d| d.as_array()) {
                for dep in deps {
                    if let Some(dep_str) = dep.as_str() {
                        if let Some(package) = self.parse_dependency_string(dep_str)? {
                            packages.push(package);
                        }
                    }
                }
            }

            // Extract from project.optional-dependencies
            if let Some(optional_deps) = project
                .get("optional-dependencies")
                .and_then(|d| d.as_table())
            {
                for (_, deps_array) in optional_deps {
                    if let Some(deps) = deps_array.as_array() {
                        for dep in deps {
                            if let Some(dep_str) = dep.as_str() {
                                if let Some(package) = self.parse_dependency_string(dep_str)? {
                                    packages.push(package);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Extract from tool.poetry.dependencies (Poetry format)
        if let Some(tool) = toml_value.get("tool") {
            if let Some(poetry) = tool.get("poetry") {
                if let Some(deps) = poetry.get("dependencies").and_then(|d| d.as_table()) {
                    for (name, version_info) in deps {
                        if name == "python" {
                            continue; // Skip Python version requirement
                        }

                        let version_str = match version_info {
                            toml::Value::String(v) => v.clone(),
                            toml::Value::Table(t) => {
                                if let Some(version) = t.get("version").and_then(|v| v.as_str()) {
                                    version.to_string()
                                } else {
                                    "0.0.0".to_string()
                                }
                            }
                            _ => "0.0.0".to_string(),
                        };

                        let clean_version = self.clean_poetry_version(&version_str)?;

                        let version =
                            Version::parse(&clean_version).map_err(|_| ParseError::Version {
                                version: version_str.clone(),
                            })?;

                        let package = Package::new(name.clone(), version, Ecosystem::PyPI)
                            .map_err(|e| ParseError::MissingField { field: e })?;

                        packages.push(package);
                    }
                }
            }
        }

        Ok(packages)
    }

    /// Parse a dependency string like "requests>=2.25.1"
    fn parse_dependency_string(&self, dep_str: &str) -> Result<Option<Package>, ParseError> {
        let dep_str = dep_str.trim();

        if dep_str.is_empty() {
            return Ok(None);
        }

        // Parse package name and version specifier
        let (name, version_spec) = if let Some(pos) = dep_str.find("==") {
            (&dep_str[..pos], &dep_str[pos + 2..])
        } else if let Some(pos) = dep_str.find(">=") {
            (&dep_str[..pos], &dep_str[pos + 2..])
        } else if let Some(pos) = dep_str.find("<=") {
            (&dep_str[..pos], &dep_str[pos + 2..])
        } else if let Some(pos) = dep_str.find("~=") {
            (&dep_str[..pos], &dep_str[pos + 2..])
        } else if let Some(pos) = dep_str.find('>') {
            (&dep_str[..pos], &dep_str[pos + 1..])
        } else if let Some(pos) = dep_str.find('<') {
            (&dep_str[..pos], &dep_str[pos + 1..])
        } else {
            (dep_str, "0.0.0")
        };

        let name = name.trim();
        let version_spec = version_spec.trim();

        // Clean version specifier
        let clean_version = if version_spec.is_empty() {
            "0.0.0".to_string()
        } else {
            // Handle version ranges (take the first version)
            let version_spec = if let Some(comma_pos) = version_spec.find(',') {
                &version_spec[..comma_pos]
            } else {
                version_spec
            };
            version_spec.trim().to_string()
        };

        let version = Version::parse(&clean_version).map_err(|_| ParseError::Version {
            version: version_spec.to_string(),
        })?;

        let package = Package::new(name.to_string(), version, Ecosystem::PyPI)
            .map_err(|e| ParseError::MissingField { field: e })?;

        Ok(Some(package))
    }

    /// Clean Poetry version specifier
    fn clean_poetry_version(&self, version_str: &str) -> Result<String, ParseError> {
        let version_str = version_str.trim();

        if version_str.is_empty() || version_str == "*" {
            return Ok("0.0.0".to_string());
        }

        // Remove common Poetry prefixes
        let cleaned = if version_str.starts_with("^") || version_str.starts_with("~") {
            &version_str[1..]
        } else if version_str.starts_with(">=") || version_str.starts_with("<=") {
            &version_str[2..]
        } else if version_str.starts_with('>') || version_str.starts_with('<') {
            &version_str[1..]
        } else {
            version_str
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
impl PackageFileParser for PyProjectTomlParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == "pyproject.toml"
    }

    async fn parse_file(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let toml_value: toml::Value = toml::from_str(content)?;
        self.extract_pyproject_dependencies(&toml_value)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::PyPI
    }

    fn priority(&self) -> u8 {
        12 // High priority for pyproject.toml
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_requirements_txt_parser() {
        let parser = RequirementsTxtParser::new();
        let content = r#"
# This is a comment
requests==2.25.1
flask>=1.1.0
django~=3.2.0
numpy
# Another comment
pytest>=6.0.0  # inline comment
        "#;

        let packages = parser.parse_file(content).await.unwrap();
        assert_eq!(packages.len(), 5);

        let requests_pkg = packages.iter().find(|p| p.name == "requests").unwrap();
        assert_eq!(requests_pkg.version, Version::parse("2.25.1").unwrap());
    }

    #[tokio::test]
    async fn test_pipfile_parser() {
        let parser = PipfileParser::new();
        let content = r#"
[[source]]
url = "https://pypi.org/simple"
verify_ssl = true
name = "pypi"

[packages]
requests = "==2.25.1"
flask = ">=1.1.0"
django = "*"

[dev-packages]
pytest = ">=6.0.0"
        "#;

        let packages = parser.parse_file(content).await.unwrap();
        assert_eq!(packages.len(), 4);

        let requests_pkg = packages.iter().find(|p| p.name == "requests").unwrap();
        assert_eq!(requests_pkg.version, Version::parse("2.25.1").unwrap());
    }

    #[tokio::test]
    async fn test_pyproject_toml_parser() {
        let parser = PyProjectTomlParser::new();
        let content = r#"
[project]
name = "my-package"
version = "0.1.0"
dependencies = [
    "requests>=2.25.1",
    "flask==1.1.4",
    "click>=7.0"
]

[project.optional-dependencies]
dev = [
    "pytest>=6.0.0",
    "black>=21.0.0"
]
        "#;

        let packages = parser.parse_file(content).await.unwrap();
        assert_eq!(packages.len(), 5);

        let requests_pkg = packages.iter().find(|p| p.name == "requests").unwrap();
        assert_eq!(requests_pkg.version, Version::parse("2.25.1").unwrap());
    }

    #[test]
    fn test_clean_version_specs() {
        let parser = RequirementsTxtParser::new();

        assert_eq!(parser.clean_version_spec("2.25.1").unwrap(), "2.25.1");
        assert_eq!(
            parser.clean_version_spec("2.25.1 # comment").unwrap(),
            "2.25.1"
        );
        assert_eq!(parser.clean_version_spec("").unwrap(), "0.0.0");
    }

    #[test]
    fn test_parser_supports_file() {
        let req_parser = RequirementsTxtParser::new();
        let pipfile_parser = PipfileParser::new();
        let pyproject_parser = PyProjectTomlParser::new();

        assert!(req_parser.supports_file("requirements.txt"));
        assert!(req_parser.supports_file("dev-requirements.txt"));
        assert!(!req_parser.supports_file("Pipfile"));

        assert!(pipfile_parser.supports_file("Pipfile"));
        assert!(!pipfile_parser.supports_file("requirements.txt"));

        assert!(pyproject_parser.supports_file("pyproject.toml"));
        assert!(!pyproject_parser.supports_file("Pipfile"));
    }
}
