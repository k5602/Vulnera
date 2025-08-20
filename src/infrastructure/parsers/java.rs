//! Java ecosystem parsers

use super::traits::PackageFileParser;
use crate::application::errors::ParseError;
use crate::domain::{Ecosystem, Package, Version};
use async_trait::async_trait;
use regex::Regex;

/// Parser for Maven pom.xml files
pub struct MavenParser;

impl Default for MavenParser {
    fn default() -> Self {
        Self::new()
    }
}

impl MavenParser {
    pub fn new() -> Self {
        Self
    }

    /// Extract dependencies from XML content
    fn extract_maven_dependencies(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();

        // Simple regex-based XML parsing (for production, consider using a proper XML parser)
        // Use DOTALL flag to match across newlines
        let dependency_regex = Regex::new(r"(?s)<dependency>.*?</dependency>").unwrap();
        let group_regex = Regex::new(r"<groupId>\s*(.*?)\s*</groupId>").unwrap();
        let artifact_regex = Regex::new(r"<artifactId>\s*(.*?)\s*</artifactId>").unwrap();
        let version_regex = Regex::new(r"<version>\s*(.*?)\s*</version>").unwrap();

        for dependency_match in dependency_regex.find_iter(content) {
            let dependency_xml = dependency_match.as_str();

            let group_id = group_regex
                .captures(dependency_xml)
                .and_then(|caps| caps.get(1))
                .map(|m| m.as_str().trim())
                .unwrap_or("");

            let artifact_id = artifact_regex
                .captures(dependency_xml)
                .and_then(|caps| caps.get(1))
                .map(|m| m.as_str().trim())
                .unwrap_or("");

            let version_str = version_regex
                .captures(dependency_xml)
                .and_then(|caps| caps.get(1))
                .map(|m| m.as_str().trim())
                .unwrap_or("0.0.0");

            if !group_id.is_empty() && !artifact_id.is_empty() {
                // Maven package name is typically groupId:artifactId
                let package_name = format!("{}:{}", group_id, artifact_id);

                // Clean version string (remove Maven-specific patterns)
                let clean_version = self.clean_maven_version(version_str)?;

                let version = Version::parse(&clean_version).map_err(|_| ParseError::Version {
                    version: version_str.to_string(),
                })?;

                let package = Package::new(package_name, version, Ecosystem::Maven)
                    .map_err(|e| ParseError::MissingField { field: e })?;

                packages.push(package);
            }
        }

        Ok(packages)
    }

    /// Clean Maven version string
    fn clean_maven_version(&self, version_str: &str) -> Result<String, ParseError> {
        let version_str = version_str.trim();

        if version_str.is_empty() {
            return Ok("0.0.0".to_string());
        }

        // Handle Maven property placeholders (simplified)
        if version_str.starts_with("${") && version_str.ends_with('}') {
            return Ok("0.0.0".to_string()); // Default for unresolved properties
        }

        // Handle version ranges (take the first version)
        if version_str.starts_with('[') || version_str.starts_with('(') {
            // Extract first version from range like "[1.0,2.0)" or "(1.0,2.0]"
            let range_content = &version_str[1..version_str.len() - 1];
            if let Some(comma_pos) = range_content.find(',') {
                let first_version = range_content[..comma_pos].trim();
                return Ok(first_version.to_string());
            }
        }

        Ok(version_str.to_string())
    }
}

#[async_trait]
impl PackageFileParser for MavenParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == "pom.xml"
    }

    async fn parse_file(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        self.extract_maven_dependencies(content)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Maven
    }

    fn priority(&self) -> u8 {
        10 // High priority for pom.xml
    }
}

/// Parser for Gradle build files
pub struct GradleParser;

impl Default for GradleParser {
    fn default() -> Self {
        Self::new()
    }
}

impl GradleParser {
    pub fn new() -> Self {
        Self
    }

    /// Extract dependencies from Gradle build file
    fn extract_gradle_dependencies(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();

        // Regex patterns for different Gradle dependency formats
        let dependency_patterns = vec![
            // implementation 'group:artifact:version'
            Regex::new(r#"(?:implementation|compile|api|testImplementation|testCompile)\s+['"]([^:]+):([^:]+):([^'"]+)['"]"#).unwrap(),
            // implementation group: 'group', name: 'artifact', version: 'version'
            Regex::new(r#"(?:implementation|compile|api|testImplementation|testCompile)\s+group:\s*['"]([^'"]+)['"],\s*name:\s*['"]([^'"]+)['"],\s*version:\s*['"]([^'"]+)['"]"#).unwrap(),
        ];

        for pattern in dependency_patterns {
            for captures in pattern.captures_iter(content) {
                let group_id = captures.get(1).map(|m| m.as_str().trim()).unwrap_or("");
                let artifact_id = captures.get(2).map(|m| m.as_str().trim()).unwrap_or("");
                let version_str = captures
                    .get(3)
                    .map(|m| m.as_str().trim())
                    .unwrap_or("0.0.0");

                if !group_id.is_empty() && !artifact_id.is_empty() {
                    let package_name = format!("{}:{}", group_id, artifact_id);

                    // Clean version string
                    let clean_version = self.clean_gradle_version(version_str)?;

                    let version =
                        Version::parse(&clean_version).map_err(|_| ParseError::Version {
                            version: version_str.to_string(),
                        })?;

                    let package = Package::new(package_name, version, Ecosystem::Maven)
                        .map_err(|e| ParseError::MissingField { field: e })?;

                    packages.push(package);
                }
            }
        }

        Ok(packages)
    }

    /// Clean Gradle version string
    fn clean_gradle_version(&self, version_str: &str) -> Result<String, ParseError> {
        let version_str = version_str.trim();

        if version_str.is_empty() {
            return Ok("0.0.0".to_string());
        }

        // Handle Gradle version catalogs and property references
        if version_str.starts_with("$") {
            return Ok("0.0.0".to_string()); // Default for unresolved properties
        }

        // Handle version ranges (simplified)
        if version_str.contains('+') {
            // Handle dynamic versions like "1.+" -> "1.0.0"
            let base_version = version_str.replace('+', "0");
            return Ok(base_version);
        }

        // Handle classifier suffixes like "-jre", "-android", etc.
        if let Some(dash_pos) = version_str.find('-') {
            let base_version = &version_str[..dash_pos];
            // Only keep the base if it looks like a version
            if base_version.matches('.').count() >= 1 {
                return Ok(base_version.to_string());
            }
        }

        Ok(version_str.to_string())
    }
}

#[async_trait]
impl PackageFileParser for GradleParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == "build.gradle" || filename == "build.gradle.kts"
    }

    async fn parse_file(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        self.extract_gradle_dependencies(content)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Maven
    }

    fn priority(&self) -> u8 {
        8 // Medium priority for Gradle files
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_maven_parser() {
        let parser = MavenParser::new();
        let content = r#"
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>5.3.21</version>
        </dependency>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>
        "#;

        let packages = parser.parse_file(content).await.unwrap();
        assert_eq!(packages.len(), 2);

        let spring_pkg = packages
            .iter()
            .find(|p| p.name == "org.springframework:spring-core")
            .unwrap();
        assert_eq!(spring_pkg.version, Version::parse("5.3.21").unwrap());
        assert_eq!(spring_pkg.ecosystem, Ecosystem::Maven);
    }

    #[tokio::test]
    async fn test_gradle_parser() {
        let parser = GradleParser::new();
        let content = r#"
dependencies {
    implementation 'org.springframework:spring-core:5.3.21'
    testImplementation 'junit:junit:4.13.2'
    api group: 'com.google.guava', name: 'guava', version: '31.1-jre'
    compile 'org.apache.commons:commons-lang3:3.12.0'
}
        "#;

        let packages = parser.parse_file(content).await.unwrap();
        assert_eq!(packages.len(), 4);

        let spring_pkg = packages
            .iter()
            .find(|p| p.name == "org.springframework:spring-core")
            .unwrap();
        assert_eq!(spring_pkg.version, Version::parse("5.3.21").unwrap());

        let guava_pkg = packages
            .iter()
            .find(|p| p.name == "com.google.guava:guava")
            .unwrap();
        assert_eq!(guava_pkg.version, Version::parse("31.1").unwrap()); // -jre suffix handled
    }

    #[test]
    fn test_clean_maven_version() {
        let parser = MavenParser::new();

        assert_eq!(parser.clean_maven_version("5.3.21").unwrap(), "5.3.21");
        assert_eq!(
            parser.clean_maven_version("${spring.version}").unwrap(),
            "0.0.0"
        );
        assert_eq!(parser.clean_maven_version("[1.0,2.0)").unwrap(), "1.0");
        assert_eq!(parser.clean_maven_version("(1.0,2.0]").unwrap(), "1.0");
    }

    #[test]
    fn test_clean_gradle_version() {
        let parser = GradleParser::new();

        assert_eq!(parser.clean_gradle_version("5.3.21").unwrap(), "5.3.21");
        assert_eq!(
            parser.clean_gradle_version("$springVersion").unwrap(),
            "0.0.0"
        );
        assert_eq!(parser.clean_gradle_version("1.+").unwrap(), "1.0");
    }

    #[test]
    fn test_parser_supports_file() {
        let maven_parser = MavenParser::new();
        let gradle_parser = GradleParser::new();

        assert!(maven_parser.supports_file("pom.xml"));
        assert!(!maven_parser.supports_file("build.gradle"));

        assert!(gradle_parser.supports_file("build.gradle"));
        assert!(gradle_parser.supports_file("build.gradle.kts"));
        assert!(!gradle_parser.supports_file("pom.xml"));
    }
}
