use async_trait::async_trait;
use pest::Parser;
use pest::iterators::{Pair, Pairs};
use regex::Regex;

use crate::application::errors::ParseError;
use crate::domain::{Ecosystem, Package, Version};

use super::traits::PackageFileParser;

// Internal pest module to avoid exporting Rule and causing name conflicts
mod pest_impl {
    
    
    use pest_derive::Parser;

    #[derive(Parser)]
    #[grammar = "src/infrastructure/parsers/grammars/gradle.pest"]
    pub struct GradlePest;
}

pub struct GradlePestParser;

impl Default for GradlePestParser {
    fn default() -> Self {
        Self::new()
    }
}

impl GradlePestParser {
    pub fn new() -> Self {
        Self
    }

    fn dequote(s: &str) -> String {
        let s = s.trim();
        if s.len() >= 2
            && ((s.starts_with('"') && s.ends_with('"'))
                || (s.starts_with('\'') && s.ends_with('\'')))
            {
                return s[1..s.len() - 1].to_string();
            }
        s.to_string()
    }

    fn clean_version(s: &str) -> String {
        let mut v = s.trim().to_string();
        if v.is_empty() {
            return "0.0.0".to_string();
        }
        // Variables or special dynamic tokens -> default
        if v.starts_with('$') || v.contains("latest") {
            return "0.0.0".to_string();
        }
        // Dynamic versions: 1.+ => 1.0 (best-effort)
        if v.contains('+') {
            v = v.replace('+', "0");
        }
        // Strip classifier suffix like "-jre" if present and base looks version-like
        if let Some(idx) = v.find('-') {
            let base = &v[..idx];
            if base.matches('.').count() >= 1 {
                return base.to_string();
            }
        }
        v
    }

    fn parse_coord_string(s: &str) -> Option<(String, String, String)> {
        let raw = Self::dequote(s);
        let parts: Vec<&str> = raw.split(':').collect();
        if parts.len() < 3 {
            return None;
        }
        let group = parts[0].trim().to_string();
        let name = parts[1].trim().to_string();
        let version = parts[2].trim().to_string();
        if group.is_empty() || name.is_empty() {
            return None;
        }
        Some((group, name, version))
    }

    fn parse_named_args(pair: Pair<'_, pest_impl::Rule>) -> Option<(String, String, String)> {
        let mut group: Option<String> = None;
        let mut name: Option<String> = None;
        let mut version: Option<String> = None;

        for kv in pair.into_inner() {
            match kv.as_rule() {
                pest_impl::Rule::kv_groovy | pest_impl::Rule::kv_kotlin => {
                    let mut key: Option<&str> = None;
                    let mut val: Option<String> = None;
                    for p in kv.into_inner() {
                        match p.as_rule() {
                            pest_impl::Rule::named_key => key = Some(p.as_str().trim()),
                            pest_impl::Rule::quoted_string => val = Some(Self::dequote(p.as_str())),
                            _ => {}
                        }
                    }
                    if let (Some(k), Some(v)) = (key, val) {
                        match k {
                            "group" => group = Some(v),
                            "name" => name = Some(v),
                            "version" => version = Some(v),
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }

        if let (Some(g), Some(a)) = (group, name) {
            let ver = version.unwrap_or_else(|| "0.0.0".to_string());
            return Some((g, a, ver));
        }
        None
    }

    fn process_dep_stmt(stmt: Pair<'_, pest_impl::Rule>) -> Option<(String, String, String)> {
        // dep_stmt = config_name ~ ( platform_call | enclosed_coord | quoted_string | named_args_groovy | named_args_kotlin | project_call )
        let mut result: Option<(String, String, String)> = None;

        for p in stmt.into_inner() {
            match p.as_rule() {
                pest_impl::Rule::platform_call => {
                    // platform_call inner: quoted_string | named_args_groovy | named_args_kotlin
                    for inner in p.into_inner() {
                        match inner.as_rule() {
                            pest_impl::Rule::quoted_string => {
                                if let Some(t) = Self::parse_coord_string(inner.as_str()) {
                                    result = Some(t);
                                    break;
                                }
                            }
                            pest_impl::Rule::named_args_groovy
                            | pest_impl::Rule::named_args_kotlin => {
                                if let Some(t) = Self::parse_named_args(inner) {
                                    result = Some(t);
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    if result.is_some() {
                        break;
                    }
                }
                pest_impl::Rule::enclosed_coord => {
                    // enclosed_coord contains a quoted_string
                    for inner in p.into_inner() {
                        if let pest_impl::Rule::quoted_string = inner.as_rule() {
                            if let Some(t) = Self::parse_coord_string(inner.as_str()) {
                                result = Some(t);
                                break;
                            }
                        }
                    }
                    if result.is_some() {
                        break;
                    }
                }
                pest_impl::Rule::quoted_string => {
                    if let Some(t) = Self::parse_coord_string(p.as_str()) {
                        result = Some(t);
                        break;
                    }
                }
                pest_impl::Rule::named_args_groovy | pest_impl::Rule::named_args_kotlin => {
                    if let Some(t) = Self::parse_named_args(p) {
                        result = Some(t);
                        break;
                    }
                }
                pest_impl::Rule::project_call => {
                    // Ignore project(':module') dependencies for external GA:V extraction
                }
                _ => {
                    // config_name or separators, ignore
                }
            }
        }

        result
    }

    fn parse_pairs<'a>(&self, content: &'a str) -> Result<Pairs<'a, pest_impl::Rule>, ParseError> {
        pest_impl::GradlePest::parse(pest_impl::Rule::file, content).map_err(|e| {
            ParseError::MissingField {
                field: format!("gradle parse error: {}", e),
            }
        })
    }

    // Regex-based fallback parser to handle Gradle dependency declarations when Pest parse
    // yields no packages due to unexpected syntax/formatting variants.
    fn fallback_parse_raw(&self, content: &str) -> Vec<Package> {
        let mut out: Vec<Package> = Vec::new();
        let mut seen = std::collections::HashSet::new();

        // 1) Direct coordinates: implementation 'group:artifact:version' or with parentheses
        let re_coord = Regex::new(
            r#"(?m)^\s*(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testCompile|testCompileOnly|testRuntimeOnly|annotationProcessor|kapt|compile|provided|runtime|testRuntime)\s*(?:\(\s*)?['"]([^:'"]+)[:]([^:'"]+)[:]([^'"]+)['"]\s*\)?"#,
        )
        .unwrap();

        for caps in re_coord.captures_iter(content) {
            let g = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            let a = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
            let v = caps.get(3).map(|m| m.as_str()).unwrap_or_default();
            if !g.is_empty() && !a.is_empty() {
                let name = format!("{}:{}", g, a);
                let cleaned = Self::clean_version(v);
                let version = Version::parse(&cleaned).unwrap_or_else(|_| Version::new(0, 0, 0));
                if seen.insert((name.clone(), version.to_string())) {
                    if let Ok(pkg) = Package::new(name.clone(), version.clone(), Ecosystem::Maven) {
                        out.push(pkg);
                    }
                }
            }
        }

        // 1b) Secondary regex specifically for double-quoted coordinates (including optional parentheses)
        let re_coord_dq = Regex::new(
            r#"(?m)^\s*(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testCompile|testCompileOnly|testRuntimeOnly|annotationProcessor|kapt|compile|provided|runtime|testRuntime)\s*(?:\(\s*)?"([^:"]+)[:]([^:"]+)[:]([^"]+)"\s*\)?"#
        )
        .unwrap();

        for caps in re_coord_dq.captures_iter(content) {
            let g = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            let a = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
            let v = caps.get(3).map(|m| m.as_str()).unwrap_or_default();
            if !g.is_empty() && !a.is_empty() {
                let name = format!("{}:{}", g, a);
                let cleaned = Self::clean_version(v);
                let version = Version::parse(&cleaned).unwrap_or_else(|_| Version::new(0, 0, 0));
                if seen.insert((name.clone(), version.to_string())) {
                    if let Ok(pkg) = Package::new(name.clone(), version.clone(), Ecosystem::Maven) {
                        out.push(pkg);
                    }
                }
            }
        }

        // 2) platform/enforcedPlatform coordinates inside parentheses
        let re_platform = Regex::new(
            r#"(?m)^\s*(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testCompile|testCompileOnly|testRuntimeOnly|annotationProcessor|kapt|compile|provided|runtime|testRuntime)\s*\(\s*(?:enforcedPlatform|platform)\(\s*['"]([^:'"]+)[:]([^:'"]+)[:]([^'"]+)['"]\s*\)\s*\)"#,
        )
        .unwrap();

        for caps in re_platform.captures_iter(content) {
            let g = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            let a = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
            let v = caps.get(3).map(|m| m.as_str()).unwrap_or_default();
            if !g.is_empty() && !a.is_empty() {
                let name = format!("{}:{}", g, a);
                let cleaned = Self::clean_version(v);
                let version = Version::parse(&cleaned).unwrap_or_else(|_| Version::new(0, 0, 0));
                if seen.insert((name.clone(), version.to_string())) {
                    if let Ok(pkg) = Package::new(name.clone(), version.clone(), Ecosystem::Maven) {
                        out.push(pkg);
                    }
                }
            }
        }

        // 3) Groovy named args: implementation group: 'g', name: 'a', version: 'v'
        let re_named_groovy = Regex::new(
            r#"(?m)^\s*(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testCompile)\s+group\s*:\s*['"]([^'"]+)['"]\s*,\s*name\s*:\s*['"]([^'"]+)['"]\s*,\s*version\s*:\s*['"]([^'"]+)['"]"#,
        )
        .unwrap();

        for caps in re_named_groovy.captures_iter(content) {
            let g = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            let a = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
            let v = caps.get(3).map(|m| m.as_str()).unwrap_or_default();
            if !g.is_empty() && !a.is_empty() {
                let name = format!("{}:{}", g, a);
                let cleaned = Self::clean_version(v);
                let version = Version::parse(&cleaned).unwrap_or_else(|_| Version::new(0, 0, 0));
                if seen.insert((name.clone(), version.to_string())) {
                    if let Ok(pkg) = Package::new(name.clone(), version.clone(), Ecosystem::Maven) {
                        out.push(pkg);
                    }
                }
            }
        }

        // 4) Kotlin named args: implementation(group = "g", name = "a", version = "v")
        let re_named_kotlin = Regex::new(
            r#"(?m)^\s*(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testCompile)\s*\(\s*group\s*=\s*['"]([^'"]+)['"]\s*,\s*name\s*=\s*['"]([^'"]+)['"]\s*,\s*version\s*=\s*['"]([^'"]+)['"]\s*\)"#,
        )
        .unwrap();

        for caps in re_named_kotlin.captures_iter(content) {
            let g = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            let a = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
            let v = caps.get(3).map(|m| m.as_str()).unwrap_or_default();
            if !g.is_empty() && !a.is_empty() {
                let name = format!("{}:{}", g, a);
                let cleaned = Self::clean_version(v);
                let version = Version::parse(&cleaned).unwrap_or_else(|_| Version::new(0, 0, 0));
                if seen.insert((name.clone(), version.to_string())) {
                    if let Ok(pkg) = Package::new(name.clone(), version.clone(), Ecosystem::Maven) {
                        out.push(pkg);
                    }
                }
            }
        }

        out
    }
}

#[async_trait]
impl PackageFileParser for GradlePestParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == "build.gradle" || filename == "build.gradle.kts"
    }

    async fn parse_file(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let pairs = self.parse_pairs(content)?;
        let mut out: Vec<Package> = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for top in pairs {
            match top.as_rule() {
                pest_impl::Rule::file => {
                    for inner in top.into_inner() {
                        match inner.as_rule() {
                            pest_impl::Rule::dependencies_block => {
                                for stmt in inner.into_inner() {
                                    if stmt.as_rule() == pest_impl::Rule::dep_stmt {
                                        if let Some((g, a, v)) = Self::process_dep_stmt(stmt) {
                                            let name = format!("{}:{}", g, a);
                                            let cleaned = Self::clean_version(&v);
                                            let version = Version::parse(&cleaned)
                                                .unwrap_or_else(|_| Version::new(0, 0, 0));
                                            if seen.insert((name.clone(), version.to_string())) {
                                                if let Ok(pkg) = Package::new(
                                                    name.clone(),
                                                    version.clone(),
                                                    Ecosystem::Maven,
                                                ) {
                                                    out.push(pkg);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            pest_impl::Rule::dep_stmt => {
                                if let Some((g, a, v)) = Self::process_dep_stmt(inner) {
                                    let name = format!("{}:{}", g, a);
                                    let cleaned = Self::clean_version(&v);
                                    let version = Version::parse(&cleaned)
                                        .unwrap_or_else(|_| Version::new(0, 0, 0));
                                    if seen.insert((name.clone(), version.to_string())) {
                                        if let Ok(pkg) = Package::new(
                                            name.clone(),
                                            version.clone(),
                                            Ecosystem::Maven,
                                        ) {
                                            out.push(pkg);
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                pest_impl::Rule::dependencies_block => {
                    for stmt in top.into_inner() {
                        if stmt.as_rule() == pest_impl::Rule::dep_stmt {
                            if let Some((g, a, v)) = Self::process_dep_stmt(stmt) {
                                let name = format!("{}:{}", g, a);
                                let cleaned = Self::clean_version(&v);
                                let version = Version::parse(&cleaned)
                                    .unwrap_or_else(|_| Version::new(0, 0, 0));
                                if seen.insert((name.clone(), version.to_string())) {
                                    if let Ok(pkg) = Package::new(
                                        name.clone(),
                                        version.clone(),
                                        Ecosystem::Maven,
                                    ) {
                                        out.push(pkg);
                                    }
                                }
                            }
                        }
                    }
                }
                pest_impl::Rule::dep_stmt => {
                    if let Some((g, a, v)) = Self::process_dep_stmt(top) {
                        let name = format!("{}:{}", g, a);
                        let cleaned = Self::clean_version(&v);
                        let version =
                            Version::parse(&cleaned).unwrap_or_else(|_| Version::new(0, 0, 0));
                        if seen.insert((name.clone(), version.to_string())) {
                            if let Ok(pkg) =
                                Package::new(name.clone(), version.clone(), Ecosystem::Maven)
                            {
                                out.push(pkg);
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Always attempt regex fallback too; merge any missing entries (helps with double-quoted top-level coords)
        let fallback_pkgs = self.fallback_parse_raw(content);
        for pkg in fallback_pkgs {
            if seen.insert((pkg.name.clone(), pkg.version.to_string())) {
                out.push(pkg);
            }
        }
        Ok(out)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Maven
    }

    // Higher than legacy Gradle parser (which was 8)
    fn priority(&self) -> u8 {
        18
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Version;

    #[tokio::test]
    async fn test_gradle_pest_basic_groovy() {
        let content = r#"
dependencies {
    implementation 'org.springframework:spring-core:5.3.21'
    testImplementation "junit:junit:4.13.2"
}
"#;
        let parser = GradlePestParser::new();
        let pkgs = parser.parse_file(content).await.unwrap();

        assert!(
            pkgs.iter()
                .any(|p| p.name == "org.springframework:spring-core"
                    && p.version == Version::parse("5.3.21").unwrap()),
            "Expected org.springframework:spring-core:5.3.21, got: {:?}",
            pkgs.iter()
                .map(|p| (&p.name, p.version.to_string()))
                .collect::<Vec<_>>()
        );

        assert!(
            pkgs.iter()
                .any(|p| p.name == "junit:junit" && p.version == Version::parse("4.13.2").unwrap()),
            "Expected junit:junit:4.13.2, got: {:?}",
            pkgs.iter()
                .map(|p| (&p.name, p.version.to_string()))
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn test_gradle_pest_named_args_groovy() {
        let content = r#"
dependencies {
    api group: 'com.google.guava', name: 'guava', version: '31.1-jre'
}
"#;
        let parser = GradlePestParser::new();
        let pkgs = parser.parse_file(content).await.unwrap();

        let guava = pkgs
            .iter()
            .find(|p| p.name == "com.google.guava:guava")
            .unwrap();
        // -jre suffix removed
        assert_eq!(guava.version, Version::parse("31.1").unwrap());
    }

    #[tokio::test]
    async fn test_gradle_pest_kotlin_enclosed_and_platform() {
        let content = r#"
dependencies {
    implementation("org.slf4j:slf4j-api:2.0.13")
    implementation(platform("org.springframework.boot:spring-boot-dependencies:3.2.5"))
}
"#;
        let parser = GradlePestParser::new();
        let pkgs = parser.parse_file(content).await.unwrap();

        assert!(
            pkgs.iter().any(|p| p.name == "org.slf4j:slf4j-api"
                && p.version == Version::parse("2.0.13").unwrap())
        );

        // Platform BOM captured as a package coordinate (best-effort)
        assert!(pkgs.iter().any(
            |p| p.name == "org.springframework.boot:spring-boot-dependencies"
                && p.version == Version::parse("3.2.5").unwrap()
        ));
    }

    #[tokio::test]
    async fn test_gradle_pest_project_ignored() {
        let content = r#"
dependencies {
    implementation project(":my-module")
    runtimeOnly project(':another-module')
}
"#;
        let parser = GradlePestParser::new();
        let pkgs = parser.parse_file(content).await.unwrap();

        // No packages should be extracted from project() declarations
        assert!(pkgs.is_empty());
    }

    #[tokio::test]
    async fn test_gradle_pest_top_level_dep_stmt() {
        let content = r#"implementation 'org.apache.commons:commons-lang3:3.12.0'"#;
        let parser = GradlePestParser::new();
        let pkgs = parser.parse_file(content).await.unwrap();

        let commons = pkgs
            .iter()
            .find(|p| p.name == "org.apache.commons:commons-lang3")
            .unwrap();
        assert_eq!(commons.version, Version::parse("3.12.0").unwrap());
    }

    #[tokio::test]
    async fn test_gradle_pest_kotlin_named_args() {
        let content = r#"
dependencies {
    implementation(group = "org.slf4j", name = "slf4j-api", version = "2.0.13")
}
"#;
        let parser = GradlePestParser::new();
        let pkgs = parser.parse_file(content).await.unwrap();

        let slf4j = pkgs
            .iter()
            .find(|p| p.name == "org.slf4j:slf4j-api")
            .unwrap();
        assert_eq!(slf4j.version, Version::parse("2.0.13").unwrap());
    }
}
