//! Traits for package file parsers

use crate::application::errors::ParseError;
use crate::domain::{Ecosystem, Package};
use async_trait::async_trait;

/// Trait for parsing dependency files
#[async_trait]
pub trait PackageFileParser: Send + Sync {
    /// Check if this parser supports the given filename
    fn supports_file(&self, filename: &str) -> bool;

    /// Parse the file content and extract packages
    async fn parse_file(&self, content: &str) -> Result<Vec<Package>, ParseError>;

    /// Get the ecosystem this parser handles
    fn ecosystem(&self) -> Ecosystem;

    /// Get the priority of this parser (higher numbers = higher priority)
    /// Used when multiple parsers support the same file
    fn priority(&self) -> u8 {
        0
    }
}

/// Factory for creating appropriate parsers based on filename
pub struct ParserFactory {
    parsers: Vec<Box<dyn PackageFileParser>>,
}

impl ParserFactory {
    /// Create a new parser factory with all available parsers
    pub fn new() -> Self {
        let mut parsers: Vec<Box<dyn PackageFileParser>> = Vec::new();

        // Add all parser implementations
        parsers.push(Box::new(
            crate::infrastructure::parsers::npm::NpmParser::new(),
        ));
        parsers.push(Box::new(
            crate::infrastructure::parsers::npm::PackageLockParser::new(),
        ));
        parsers.push(Box::new(
            crate::infrastructure::parsers::yarn_pest::YarnPestParser::new(),
        ));
        parsers.push(Box::new(
            crate::infrastructure::parsers::npm::YarnLockParser::new(),
        ));

        parsers.push(Box::new(
            crate::infrastructure::parsers::python::RequirementsTxtParser::new(),
        ));
        parsers.push(Box::new(
            crate::infrastructure::parsers::python::PipfileParser::new(),
        ));
        parsers.push(Box::new(
            crate::infrastructure::parsers::python::PyProjectTomlParser::new(),
        ));

        parsers.push(Box::new(
            crate::infrastructure::parsers::java::MavenParser::new(),
        ));
        // Pest-based Gradle parser
        parsers.push(Box::new(
            crate::infrastructure::parsers::gradle_pest::GradlePestParser::new(),
        ));
        // Legacy Gradle parser as fallback "deprecated once pest tested enough"
        parsers.push(Box::new(
            crate::infrastructure::parsers::java::GradleParser::new(),
        ));

        parsers.push(Box::new(
            crate::infrastructure::parsers::rust::CargoParser::new(),
        ));
        parsers.push(Box::new(
            crate::infrastructure::parsers::rust::CargoLockParser::new(),
        ));

        parsers.push(Box::new(
            crate::infrastructure::parsers::go::GoModParser::new(),
        ));
        parsers.push(Box::new(
            crate::infrastructure::parsers::go::GoSumParser::new(),
        ));

        parsers.push(Box::new(
            crate::infrastructure::parsers::php::ComposerParser::new(),
        ));
        parsers.push(Box::new(
            crate::infrastructure::parsers::php::ComposerLockParser::new(),
        ));

        parsers.push(Box::new(
            crate::infrastructure::parsers::nuget::NuGetPackagesConfigParser::new(),
        ));
        parsers.push(Box::new(
            crate::infrastructure::parsers::nuget::NuGetProjectXmlParser::new(),
        ));

        parsers.push(Box::new(
            crate::infrastructure::parsers::ruby::GemfileLockParser::new(),
        ));
        parsers.push(Box::new(
            crate::infrastructure::parsers::ruby::GemfileParser::new(),
        ));

        Self { parsers }
    }

    /// Create a parser for the given filename
    pub fn create_parser(&self, filename: &str) -> Option<&dyn PackageFileParser> {
        // Find all parsers that support this file
        let mut supporting_parsers: Vec<&dyn PackageFileParser> = self
            .parsers
            .iter()
            .filter(|parser| parser.supports_file(filename))
            .map(|parser| parser.as_ref())
            .collect();

        if supporting_parsers.is_empty() {
            return None;
        }

        // Sort by priority (highest first)
        supporting_parsers.sort_by(|a, b| b.priority().cmp(&a.priority()));

        // Return the highest priority parser
        supporting_parsers.into_iter().next()
    }

    /// Detect ecosystem from filename
    pub fn detect_ecosystem(&self, filename: &str) -> Option<Ecosystem> {
        self.create_parser(filename)
            .map(|parser| parser.ecosystem())
    }

    /// Get all supported file extensions
    pub fn supported_extensions(&self) -> Vec<String> {
        let mut extensions = Vec::new();

        for ecosystem in Ecosystem::all() {
            extensions.extend(
                ecosystem
                    .file_extensions()
                    .iter()
                    .map(|ext| ext.to_string()),
            );
        }

        extensions.sort();
        extensions.dedup();
        extensions
    }

    /// Check if a filename is supported by any parser
    pub fn is_supported(&self, filename: &str) -> bool {
        self.parsers
            .iter()
            .any(|parser| parser.supports_file(filename))
    }
}

impl Default for ParserFactory {
    fn default() -> Self {
        Self::new()
    }
}
