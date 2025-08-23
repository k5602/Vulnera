use super::traits::PackageFileParser;
use crate::application::errors::ParseError;
use crate::domain::{Ecosystem, Package, Version};
use async_trait::async_trait;
use quick_xml::Reader;
use quick_xml::events::Event;
use regex::Regex;

/// Best-effort cleaning of NuGet version strings:
/// - Extracts the first numeric dotted version (1 to 4 segments), optionally keeps a simple pre-release suffix
/// - If a range is provided (e.g., "[1.2.3, 2.0.0)"), it picks the first version in the string (usually the lower bound)
/// - On failure or unresolved property-like values (e.g., "$(SomeVar)"), returns "0.0.0"
fn clean_nuget_version(input: &str) -> String {
    let s = input.trim();
    if s.is_empty() || s.contains("$(") {
        return "0.0.0".to_string();
    }
    // Capture numeric dotted version with optional simple pre-release (e.g., -rc1)
    // Accept up to 4 numeric segments because NuGet sometimes uses 4-part versions (e.g., 4.2.11.1)
    // Semver crate may not accept 4 segments, so fall back by truncating to 3 segments if needed later.
    let re = Regex::new(r"(?i)\b(\d+(?:\.\d+){0,3}(?:-[0-9A-Za-z\.-]+)?)\b").unwrap();
    if let Some(caps) = re.captures(s) {
        return caps.get(1).unwrap().as_str().to_string();
    }
    "0.0.0".to_string()
}

/// NuGet allows 4-segment versions, but semver::Version is 3 segments.
/// If parsing fails and we have 4 segments, try truncating to 3.
fn parse_version_lenient(v: &str) -> Result<Version, ParseError> {
    match Version::parse(v) {
        Ok(ver) => Ok(ver),
        Err(_) => {
            // Try truncating to first 3 numeric segments if 4 present
            let parts: Vec<&str> = v.split('-').collect(); // split prerelease from core
            let core = parts[0];
            let prerelease = if parts.len() > 1 {
                Some(parts[1])
            } else {
                None
            };

            let nums: Vec<&str> = core.split('.').collect();
            if nums.len() > 3 {
                let truncated = format!("{}.{}.{}", nums[0], nums[1], nums[2]);
                let with_pre = match prerelease {
                    Some(pre) if !pre.is_empty() => format!("{}-{}", truncated, pre),
                    _ => truncated,
                };
                Version::parse(&with_pre).map_err(|_| ParseError::Version {
                    version: v.to_string(),
                })
            } else {
                Err(ParseError::Version {
                    version: v.to_string(),
                })
            }
        }
    }
}

/// Parser for legacy NuGet packages.config files.
/// Example:
/// <?xml version="1.0" encoding="utf-8"?>
/// <packages>
///   <package id="Newtonsoft.Json" version="12.0.3" targetFramework="net472" />
///   <package id="Serilog" version="2.10.0" />
/// </packages>
pub struct NuGetPackagesConfigParser;

impl Default for NuGetPackagesConfigParser {
    fn default() -> Self {
        Self::new()
    }
}

impl NuGetPackagesConfigParser {
    pub fn new() -> Self {
        Self
    }

    fn parse_packages_config(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();

        let mut reader = Reader::from_str(content);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if name.eq_ignore_ascii_case("package") {
                        let mut id: Option<String> = None;
                        let mut version: Option<String> = None;

                        for attr in e.attributes().flatten() {
                            let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                            let val = reader
                                .decoder()
                                .decode(&attr.value)
                                .unwrap_or_default()
                                .trim()
                                .to_string();

                            match key.as_str() {
                                "id" => id = Some(val),
                                "version" => version = Some(val),
                                _ => {}
                            }
                        }

                        if let Some(pkg_name) = id {
                            let raw_ver = version.unwrap_or_else(|| "0.0.0".to_string());
                            let cleaned = clean_nuget_version(&raw_ver);
                            let ver = parse_version_lenient(&cleaned)?;

                            let pkg = Package::new(pkg_name, ver, Ecosystem::NuGet)
                                .map_err(|e| ParseError::MissingField { field: e })?;
                            packages.push(pkg);
                        }
                    }

                    // If this is an Empty element, no End event will follow; we just continue
                    if matches!(e, quick_xml::events::BytesStart { .. }) {
                        // Start event handled above
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(ParseError::MissingField {
                        field: format!("XML parse error: {}", e),
                    });
                }
                _ => {}
            }
            buf.clear();
        }

        Ok(packages)
    }
}

#[async_trait]
impl PackageFileParser for NuGetPackagesConfigParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename.eq_ignore_ascii_case("packages.config")
    }

    async fn parse_file(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        self.parse_packages_config(content)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::NuGet
    }

    fn priority(&self) -> u8 {
        18 // Prefer over project files; resolved versions are more precise
    }
}

/// Parser for SDK-style project files (.csproj, .fsproj, .vbproj) with <PackageReference>
/// Examples:
/// <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
/// <PackageReference Include="Serilog">
///   <Version>2.12.0</Version>
/// </PackageReference>
pub struct NuGetProjectXmlParser;

impl Default for NuGetProjectXmlParser {
    fn default() -> Self {
        Self::new()
    }
}

impl NuGetProjectXmlParser {
    pub fn new() -> Self {
        Self
    }

    fn parse_project_xml(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();

        let mut reader = Reader::from_str(content);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::new();

        let mut in_package_ref = false;
        let mut current_name: Option<String> = None;
        let mut current_version: Option<String> = None;
        let mut in_version_child = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if tag.eq_ignore_ascii_case("PackageReference") {
                        in_package_ref = true;
                        current_name = None;
                        current_version = None;

                        for attr in e.attributes().flatten() {
                            let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                            let val = reader
                                .decoder()
                                .decode(&attr.value)
                                .unwrap_or_default()
                                .trim()
                                .to_string();

                            match key.as_str() {
                                "Include" => current_name = Some(val),
                                "Version" => current_version = Some(val),
                                _ => {}
                            }
                        }
                    } else if in_package_ref && tag.eq_ignore_ascii_case("Version") {
                        in_version_child = true;
                    }
                }
                Ok(Event::Empty(e)) => {
                    let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if tag.eq_ignore_ascii_case("PackageReference") {
                        // Self-closing PackageReference
                        let mut name_attr: Option<String> = None;
                        let mut version_attr: Option<String> = None;

                        for attr in e.attributes().flatten() {
                            let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                            let val = reader
                                .decoder()
                                .decode(&attr.value)
                                .unwrap_or_default()
                                .trim()
                                .to_string();
                            match key.as_str() {
                                "Include" => name_attr = Some(val),
                                "Version" => version_attr = Some(val),
                                _ => {}
                            }
                        }

                        if let Some(pkg_name) = name_attr {
                            let raw_ver = version_attr.unwrap_or_else(|| "0.0.0".to_string());
                            let cleaned = clean_nuget_version(&raw_ver);
                            let ver = parse_version_lenient(&cleaned)?;

                            let pkg = Package::new(pkg_name, ver, Ecosystem::NuGet)
                                .map_err(|e| ParseError::MissingField { field: e })?;
                            packages.push(pkg);
                        }
                    }
                }
                Ok(Event::Text(t)) => {
                    if in_package_ref && in_version_child {
                        let txt = reader
                            .decoder()
                            .decode(t.as_ref())
                            .unwrap_or_default()
                            .trim()
                            .to_string();
                        if !txt.is_empty() {
                            current_version = Some(txt);
                        }
                    }
                }
                Ok(Event::End(e)) => {
                    let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if tag.eq_ignore_ascii_case("Version") && in_package_ref {
                        in_version_child = false;
                    } else if tag.eq_ignore_ascii_case("PackageReference") && in_package_ref {
                        // Finalize this package ref
                        if let Some(pkg_name) = current_name.take() {
                            let raw_ver = current_version
                                .take()
                                .unwrap_or_else(|| "0.0.0".to_string());
                            let cleaned = clean_nuget_version(&raw_ver);
                            let ver = parse_version_lenient(&cleaned)?;

                            let pkg = Package::new(pkg_name, ver, Ecosystem::NuGet)
                                .map_err(|e| ParseError::MissingField { field: e })?;
                            packages.push(pkg);
                        }
                        in_package_ref = false;
                        in_version_child = false;
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(ParseError::MissingField {
                        field: format!("XML parse error: {}", e),
                    });
                }
                _ => {}
            }
            buf.clear();
        }

        Ok(packages)
    }
}

#[async_trait]
impl PackageFileParser for NuGetProjectXmlParser {
    fn supports_file(&self, filename: &str) -> bool {
        let f = filename.to_ascii_lowercase();
        f.ends_with(".csproj") || f.ends_with(".fsproj") || f.ends_with(".vbproj")
    }

    async fn parse_file(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        self.parse_project_xml(content)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::NuGet
    }

    fn priority(&self) -> u8 {
        8 // Lower than packages.config, higher than generic/legacy fallbacks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_packages_config_parser() {
        let parser = NuGetPackagesConfigParser::new();
        let content = r#"
<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="12.0.3" targetFramework="net472" />
  <package id="Serilog" version="[2.10.0,3.0.0)" />
  <package id="NoVersion" />
</packages>
"#;

        let pkgs = parser.parse_file(content).await.unwrap();
        assert_eq!(pkgs.len(), 3);

        let nj = pkgs.iter().find(|p| p.name == "Newtonsoft.Json").unwrap();
        assert_eq!(nj.version, Version::parse("12.0.3").unwrap());

        let serilog = pkgs.iter().find(|p| p.name == "Serilog").unwrap();
        assert_eq!(serilog.version, Version::parse("2.10.0").unwrap());

        let nov = pkgs.iter().find(|p| p.name == "NoVersion").unwrap();
        assert_eq!(nov.version, Version::parse("0.0.0").unwrap());
    }

    #[tokio::test]
    async fn test_project_xml_parser() {
        let parser = NuGetProjectXmlParser::new();
        let content = r#"
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
    <PackageReference Include="Serilog">
      <Version>2.12.0</Version>
    </PackageReference>
    <PackageReference Include="WeirdVersion" Version="[1.2.3, 2.0.0)" />
  </ItemGroup>
</Project>
"#;

        let pkgs = parser.parse_file(content).await.unwrap();
        assert_eq!(pkgs.len(), 3);

        let nj = pkgs.iter().find(|p| p.name == "Newtonsoft.Json").unwrap();
        assert_eq!(nj.version, Version::parse("13.0.1").unwrap());

        let serilog = pkgs.iter().find(|p| p.name == "Serilog").unwrap();
        assert_eq!(serilog.version, Version::parse("2.12.0").unwrap());

        let weird = pkgs.iter().find(|p| p.name == "WeirdVersion").unwrap();
        assert_eq!(weird.version, Version::parse("1.2.3").unwrap());
    }

    #[test]
    fn test_clean_nuget_version() {
        assert_eq!(clean_nuget_version("13.0.1"), "13.0.1");
        assert_eq!(clean_nuget_version("[2.10.0,3.0.0)"), "2.10.0");
        assert_eq!(clean_nuget_version("  1.2.3-rc1  "), "1.2.3-rc1");
        assert_eq!(clean_nuget_version("$(SomeVar)"), "0.0.0");
        assert_eq!(clean_nuget_version(""), "0.0.0");
    }
}
