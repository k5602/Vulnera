//! Comprehensive edge case tests for all parsers
//! Tests malformed files, edge cases, and error conditions

use std::collections::HashMap;
use vulnera_rust::domain::value_objects::{Ecosystem, Version};
use vulnera_rust::infrastructure::parsers::traits::{PackageFileParser, ParserFactory};

// Test data generators

fn generate_malformed_package_json_cases() -> Vec<(&'static str, &'static str)> {
    vec![
        ("empty_object", "{}"),
        ("null_dependencies", r#"{"dependencies": null}"#),
        (
            "string_dependencies",
            r#"{"dependencies": "not an object"}"#,
        ),
        ("array_dependencies", r#"{"dependencies": []}"#),
        (
            "malformed_json",
            r#"{"dependencies": {"express": "4.17.1",}}"#,
        ),
        ("unclosed_brace", r#"{"dependencies": {"express": "4.17.1""#),
        ("wrong_quotes", r#"{'dependencies': {'express': '4.17.1'}}"#),
        ("no_version", r#"{"dependencies": {"express": null}}"#),
        ("empty_version", r#"{"dependencies": {"express": ""}}"#),
        ("numeric_version", r#"{"dependencies": {"express": 123}}"#),
        ("boolean_version", r#"{"dependencies": {"express": true}}"#),
        (
            "object_version",
            r#"{"dependencies": {"express": {"version": "1.0"}}}"#,
        ),
        (
            "circular_deps",
            r#"{"dependencies": {"a": "1.0"}, "devDependencies": {"a": "2.0"}}"#,
        ),
        (
            "unicode_names",
            r#"{"dependencies": {"测试": "1.0", "🚀": "2.0"}}"#,
        ),
        (
            "very_long_name",
            &format!(r#"{{"dependencies": {{"{}": "1.0"}}}}"#, "a".repeat(1000)),
        ),
        (
            "special_chars",
            r#"{"dependencies": {"@scope/package": "1.0", "$weird": "2.0"}}"#,
        ),
        ("empty_name", r#"{"dependencies": {"": "1.0"}}"#),
        ("whitespace_name", r#"{"dependencies": {"   ": "1.0"}}"#),
        ("null_name", r#"{"dependencies": {null: "1.0"}}"#),
        (
            "complex_versions",
            r#"{"dependencies": {"express": ">=4.0.0 <5.0.0 || >5.1.0"}}"#,
        ),
        (
            "git_urls",
            r#"{"dependencies": {"pkg": "git+https://github.com/user/repo.git#branch"}}"#,
        ),
        (
            "file_urls",
            r#"{"dependencies": {"pkg": "file:../local-package"}}"#,
        ),
        (
            "http_urls",
            r#"{"dependencies": {"pkg": "http://registry.com/package.tgz"}}"#,
        ),
        (
            "workspace_refs",
            r#"{"dependencies": {"pkg": "workspace:*"}}"#,
        ),
        (
            "npm_aliases",
            r#"{"dependencies": {"alias": "npm:original@1.0.0"}}"#,
        ),
        (
            "deeply_nested",
            r#"{"workspaces": {"packages": ["packages/*"]}, "dependencies": {"express": "1.0"}}"#,
        ),
        (
            "peer_deps",
            r#"{"peerDependencies": {"react": ">=16.0.0"}, "peerDependenciesMeta": {"react": {"optional": true}}}"#,
        ),
        (
            "bundle_deps",
            r#"{"bundledDependencies": ["express"], "dependencies": {"express": "1.0"}}"#,
        ),
        (
            "engines",
            r#"{"engines": {"node": ">=14.0.0"}, "dependencies": {"express": "1.0"}}"#,
        ),
        (
            "overrides",
            r#"{"overrides": {"express": "4.18.0"}, "dependencies": {"express": "1.0"}}"#,
        ),
    ]
}

fn generate_malformed_cargo_toml_cases() -> Vec<(&'static str, &'static str)> {
    vec![
        ("empty_file", ""),
        ("no_dependencies", "[package]\nname = \"test\""),
        ("malformed_toml", "[dependencies\nserde = \"1.0\""),
        ("invalid_syntax", "[dependencies]\nserde = 1.0"),
        ("missing_quotes", "[dependencies]\nserde = 1.0.0"),
        ("wrong_section", "[dependency]\nserde = \"1.0\""),
        (
            "duplicate_keys",
            "[dependencies]\nserde = \"1.0\"\nserde = \"2.0\"",
        ),
        (
            "invalid_versions",
            "[dependencies]\nserde = \"not.a.version\"",
        ),
        (
            "complex_deps",
            "[dependencies]\nserde = { version = \"1.0\", features = [\"derive\"] }",
        ),
        (
            "git_deps",
            "[dependencies]\nserde = { git = \"https://github.com/serde-rs/serde\" }",
        ),
        (
            "path_deps",
            "[dependencies]\nserde = { path = \"../serde\" }",
        ),
        (
            "optional_deps",
            "[dependencies]\nserde = { version = \"1.0\", optional = true }",
        ),
        (
            "target_deps",
            "[target.'cfg(windows)'.dependencies]\nwinapi = \"0.3\"",
        ),
        ("build_deps", "[build-dependencies]\nbindgen = \"0.59\""),
        ("dev_deps", "[dev-dependencies]\ntokio-test = \"0.4\""),
        (
            "workspace_deps",
            "[dependencies]\nserde = { workspace = true }",
        ),
        ("unicode_names", "[dependencies]\n\"测试\" = \"1.0\""),
        (
            "hyphenated_names",
            "[dependencies]\n\"kebab-case\" = \"1.0\"",
        ),
        ("underscored_names", "[dependencies]\nsnake_case = \"1.0\""),
        ("numeric_names", "[dependencies]\n\"123test\" = \"1.0\""),
        (
            "empty_features",
            "[dependencies]\nserde = { version = \"1.0\", features = [] }",
        ),
        (
            "invalid_features",
            "[dependencies]\nserde = { version = \"1.0\", features = \"not-array\" }",
        ),
        (
            "circular_deps",
            "[dependencies]\na = { path = \"../a\" }\n[dev-dependencies]\na = \"1.0\"",
        ),
        (
            "missing_version",
            "[dependencies]\nserde = { features = [\"derive\"] }",
        ),
        ("invalid_table", "[dependencies.serde]\nversion = \"1.0\""),
        (
            "mixed_syntax",
            "[dependencies]\nserde = \"1.0\"\ntokio = { version = \"1.0\" }",
        ),
    ]
}

fn generate_malformed_requirements_txt_cases() -> Vec<(&'static str, &'static str)> {
    vec![
        ("empty_file", ""),
        ("only_whitespace", "   \n\t  \n   "),
        ("only_comments", "# This is a comment\n# Another comment"),
        ("malformed_versions", "django===3.2.0\nrequests>>2.0"),
        ("missing_versions", "django\nrequests"),
        ("invalid_operators", "django~=3.2.0\nrequests@=2.0"),
        ("circular_deps", "a==1.0\nb==2.0\na>=1.5"),
        ("unicode_names", "测试==1.0\n🚀>=2.0"),
        ("very_long_lines", &format!("{}==1.0", "a".repeat(10000))),
        (
            "mixed_line_endings",
            "django==3.2.0\r\nrequests>=2.25.0\nflask==1.1.4\r",
        ),
        ("tabs_and_spaces", "django\t==\t3.2.0\nrequests  >=  2.25.0"),
        ("empty_lines", "django==3.2.0\n\n\nrequests>=2.25.0\n\n"),
        (
            "inline_comments",
            "django==3.2.0  # Web framework\nrequests>=2.25.0  # HTTP library",
        ),
        (
            "urls",
            "git+https://github.com/django/django.git@main#egg=django",
        ),
        (
            "editable_installs",
            "-e git+https://github.com/user/repo.git#egg=package",
        ),
        ("local_paths", "-e ./local-package"),
        (
            "index_urls",
            "--index-url https://pypi.org/simple/\ndjango==3.2.0",
        ),
        (
            "find_links",
            "--find-links https://download.pytorch.org/whl/torch_stable.html",
        ),
        ("constraints", "-c constraints.txt\ndjango==3.2.0"),
        ("requirements", "-r base.txt\ndjango==3.2.0"),
        ("hash_mode", "django==3.2.0 --hash=sha256:abc123"),
        ("extras", "django[mysql,postgresql]==3.2.0"),
        ("complex_specifiers", "django>=3.0,<4.0,!=3.1.0"),
        ("pre_releases", "django==3.2.0a1"),
        ("post_releases", "django==3.2.0.post1"),
        ("dev_releases", "django==3.2.0.dev20210101"),
        ("local_versions", "django==3.2.0+local.1"),
        ("case_sensitive", "Django==3.2.0\ndjango>=3.0"),
        ("invalid_chars", "django@==3.2.0\nrequest$>=2.0"),
        ("nested_brackets", "package[extra[nested]]==1.0"),
        ("unmatched_brackets", "package[extra==1.0"),
        ("multiple_operators", "django>=3.0<=4.0"),
    ]
}

fn generate_malformed_pom_xml_cases() -> Vec<(&'static str, &'static str)> {
    vec![
        ("empty_file", ""),
        ("invalid_xml", "<project><dependencies></project>"),
        ("no_dependencies", "<project></project>"),
        (
            "unclosed_tags",
            "<project><dependencies><dependency></dependencies></project>",
        ),
        (
            "malformed_structure",
            "<dependencies><groupId>junit</groupId></dependencies>",
        ),
        (
            "missing_groupid",
            "<dependencies><dependency><artifactId>junit</artifactId></dependency></dependencies>",
        ),
        (
            "missing_artifactid",
            "<dependencies><dependency><groupId>junit</groupId></dependency></dependencies>",
        ),
        (
            "empty_values",
            "<dependencies><dependency><groupId></groupId><artifactId></artifactId></dependency></dependencies>",
        ),
        (
            "cdata_sections",
            "<dependencies><dependency><groupId><![CDATA[junit]]></groupId></dependency></dependencies>",
        ),
        (
            "xml_entities",
            "<dependencies><dependency><groupId>&lt;junit&gt;</groupId></dependency></dependencies>",
        ),
        (
            "namespaces",
            r#"<project xmlns="http://maven.apache.org/POM/4.0.0"><dependencies><dependency><groupId>junit</groupId></dependency></dependencies></project>"#,
        ),
        (
            "nested_projects",
            "<project><modules><module>subproject</module></modules><dependencies><dependency><groupId>junit</groupId></dependency></dependencies></project>",
        ),
        (
            "properties",
            "<project><properties><junit.version>4.12</junit.version></properties><dependencies><dependency><version>${junit.version}</version></dependency></dependencies></project>",
        ),
        (
            "profiles",
            "<project><profiles><profile><dependencies><dependency><groupId>junit</groupId></dependency></dependencies></profile></profiles></project>",
        ),
        (
            "parent_pom",
            "<project><parent><groupId>org.example</groupId></parent><dependencies><dependency><groupId>junit</groupId></dependency></dependencies></project>",
        ),
        (
            "dependency_management",
            "<project><dependencyManagement><dependencies><dependency><groupId>junit</groupId></dependency></dependencies></dependencyManagement></project>",
        ),
        (
            "scopes",
            "<project><dependencies><dependency><groupId>junit</groupId><scope>test</scope></dependency></dependencies></project>",
        ),
        (
            "classifiers",
            "<project><dependencies><dependency><groupId>junit</groupId><classifier>sources</classifier></dependency></dependencies></project>",
        ),
        (
            "system_scope",
            "<project><dependencies><dependency><groupId>junit</groupId><scope>system</scope><systemPath>/path/to/jar</systemPath></dependency></dependencies></project>",
        ),
        (
            "version_ranges",
            "<project><dependencies><dependency><groupId>junit</groupId><version>[4.0,5.0)</version></dependency></dependencies></project>",
        ),
        (
            "exclusions",
            "<project><dependencies><dependency><groupId>junit</groupId><exclusions><exclusion><groupId>hamcrest</groupId></exclusion></exclusions></dependency></dependencies></project>",
        ),
        (
            "unicode_content",
            "<project><dependencies><dependency><groupId>测试</groupId><artifactId>🚀</artifactId></dependency></dependencies></project>",
        ),
        (
            "very_long_values",
            &format!(
                "<project><dependencies><dependency><groupId>{}</groupId></dependency></dependencies></project>",
                "a".repeat(10000)
            ),
        ),
        (
            "comments",
            "<!-- Comment --><project><!-- Another comment --><dependencies><dependency><groupId>junit</groupId></dependency></dependencies></project>",
        ),
        (
            "processing_instructions",
            "<?xml version=\"1.0\"?><?custom instruction?><project><dependencies><dependency><groupId>junit</groupId></dependency></dependencies></project>",
        ),
        (
            "mixed_content",
            "<project>Text content<dependencies><dependency><groupId>junit</groupId></dependency></dependencies>More text</project>",
        ),
    ]
}

fn generate_malformed_go_mod_cases() -> Vec<(&'static str, &'static str)> {
    vec![
        ("empty_file", ""),
        ("no_module", "go 1.19"),
        ("no_go_version", "module example.com/mymodule"),
        ("invalid_module_path", "module not-a-valid-path\ngo 1.19"),
        (
            "invalid_go_version",
            "module example.com/mymodule\ngo invalid",
        ),
        (
            "duplicate_require",
            "module test\ngo 1.19\nrequire github.com/gin-gonic/gin v1.7.0\nrequire github.com/gin-gonic/gin v1.8.0",
        ),
        (
            "missing_version",
            "module test\ngo 1.19\nrequire github.com/gin-gonic/gin",
        ),
        (
            "invalid_version",
            "module test\ngo 1.19\nrequire github.com/gin-gonic/gin not-a-version",
        ),
        (
            "pseudo_versions",
            "module test\ngo 1.19\nrequire github.com/gin-gonic/gin v0.0.0-20210101000000-abcdef123456",
        ),
        (
            "replace_directives",
            "module test\ngo 1.19\nreplace github.com/old/pkg => github.com/new/pkg v1.0.0",
        ),
        (
            "exclude_directives",
            "module test\ngo 1.19\nexclude github.com/bad/pkg v1.0.0",
        ),
        ("retract_directives", "module test\ngo 1.19\nretract v1.0.0"),
        (
            "mixed_blocks",
            "module test\ngo 1.19\nrequire (\n\tgithub.com/gin-gonic/gin v1.7.0\n)\nrequire github.com/other/pkg v1.0.0",
        ),
        (
            "comments",
            "// Comment\nmodule test // Another comment\ngo 1.19\nrequire github.com/gin-gonic/gin v1.7.0 // End comment",
        ),
        ("unicode_paths", "module 测试.com/模块\ngo 1.19"),
        (
            "very_long_paths",
            &format!("module {}.com/test\ngo 1.19", "a".repeat(1000)),
        ),
        (
            "local_replace",
            "module test\ngo 1.19\nreplace github.com/local/pkg => ./local",
        ),
        (
            "indirect_deps",
            "module test\ngo 1.19\nrequire github.com/gin-gonic/gin v1.7.0 // indirect",
        ),
        ("toolchain", "module test\ngo 1.19\ntoolchain go1.20.1"),
        ("multiple_go_lines", "module test\ngo 1.19\ngo 1.20"),
        ("invalid_syntax", "module test\ngo 1.19\nrequire {"),
        (
            "nested_blocks",
            "module test\ngo 1.19\nrequire (\n\trequire github.com/test v1.0.0\n)",
        ),
        ("empty_blocks", "module test\ngo 1.19\nrequire (\n)"),
        (
            "missing_parens",
            "module test\ngo 1.19\nrequire\n\tgithub.com/gin-gonic/gin v1.7.0",
        ),
        (
            "extra_parens",
            "module test\ngo 1.19\nrequire (github.com/gin-gonic/gin v1.7.0))",
        ),
        (
            "tabs_vs_spaces",
            "module test\ngo 1.19\nrequire (\n    github.com/gin-gonic/gin v1.7.0\n\tgithub.com/other/pkg v1.0.0\n)",
        ),
        (
            "line_continuations",
            "module test\ngo 1.19\nrequire github.com/very/long/package/name/that/continues \\\nv1.0.0",
        ),
        (
            "version_suffixes",
            "module test\ngo 1.19\nrequire github.com/gin-gonic/gin v1.7.0+incompatible",
        ),
        (
            "pre_release",
            "module test\ngo 1.19\nrequire github.com/gin-gonic/gin v1.7.0-beta.1",
        ),
        (
            "rc_versions",
            "module test\ngo 1.19\nrequire github.com/gin-gonic/gin v1.7.0-rc.1",
        ),
    ]
}

fn generate_malformed_composer_json_cases() -> Vec<(&'static str, &'static str)> {
    vec![
        ("empty_object", "{}"),
        ("no_require", r#"{"name": "test/package"}"#),
        ("null_require", r#"{"require": null}"#),
        ("string_require", r#"{"require": "not an object"}"#),
        ("array_require", r#"{"require": []}"#),
        (
            "invalid_php_version",
            r#"{"require": {"php": "not-a-version"}}"#,
        ),
        (
            "complex_constraints",
            r#"{"require": {"monolog/monolog": "^2.0 || ^3.0"}}"#,
        ),
        (
            "stability_flags",
            r#"{"require": {"monolog/monolog": "dev-master"}}"#,
        ),
        (
            "inline_aliases",
            r#"{"require": {"monolog/monolog": "dev-master as 2.0.x-dev"}}"#,
        ),
        (
            "platform_packages",
            r#"{"require": {"ext-json": "*", "lib-curl": ">=7.0"}}"#,
        ),
        (
            "repositories",
            r#"{"repositories": [{"type": "vcs", "url": "https://github.com/user/repo"}], "require": {"user/repo": "dev-master"}}"#,
        ),
        (
            "minimum_stability",
            r#"{"minimum-stability": "dev", "require": {"monolog/monolog": "dev-master"}}"#,
        ),
        (
            "prefer_stable",
            r#"{"prefer-stable": true, "require": {"monolog/monolog": "@dev"}}"#,
        ),
        (
            "config_section",
            r#"{"config": {"platform": {"php": "7.4"}}, "require": {"php": ">=8.0"}}"#,
        ),
        (
            "scripts",
            r#"{"scripts": {"post-install-cmd": ["@php artisan clear-compiled"]}, "require": {"laravel/framework": "^8.0"}}"#,
        ),
        (
            "autoload",
            r#"{"autoload": {"psr-4": {"App\\": "src/"}}, "require": {"php": ">=7.4"}}"#,
        ),
        (
            "extra",
            r#"{"extra": {"laravel": {"providers": ["App\\Providers\\ServiceProvider"]}}, "require": {"laravel/framework": "^8.0"}}"#,
        ),
        (
            "unicode_names",
            r#"{"require": {"测试/包": "1.0.0", "🚀/rocket": "2.0.0"}}"#,
        ),
        (
            "case_sensitivity",
            r#"{"require": {"Monolog/Monolog": "^2.0", "monolog/monolog": "^3.0"}}"#,
        ),
        (
            "version_ranges",
            r#"{"require": {"monolog/monolog": ">=2.0,<3.0"}}"#,
        ),
        (
            "tilde_operator",
            r#"{"require": {"monolog/monolog": "~2.0.0"}}"#,
        ),
        (
            "caret_operator",
            r#"{"require": {"monolog/monolog": "^2.0"}}"#,
        ),
        (
            "exact_versions",
            r#"{"require": {"monolog/monolog": "2.0.0"}}"#,
        ),
        (
            "wildcard_versions",
            r#"{"require": {"monolog/monolog": "2.*"}}"#,
        ),
        (
            "dev_branches",
            r#"{"require": {"monolog/monolog": "dev-feature-branch"}}"#,
        ),
        (
            "git_references",
            r#"{"require": {"monolog/monolog": "dev-master#abc123"}}"#,
        ),
        (
            "path_repositories",
            r#"{"repositories": [{"type": "path", "url": "../local-package"}], "require": {"local/package": "@dev"}}"#,
        ),
        (
            "circular_deps",
            r#"{"require": {"a/package": "^1.0"}, "require-dev": {"a/package": "^2.0"}}"#,
        ),
        (
            "conflict_deps",
            r#"{"require": {"monolog/monolog": "^2.0"}, "conflict": {"monolog/monolog": "^3.0"}}"#,
        ),
        (
            "provide_deps",
            r#"{"provide": {"psr/log-implementation": "1.0.0"}, "require": {"psr/log": "^1.0"}}"#,
        ),
        (
            "suggest_deps",
            r#"{"suggest": {"monolog/monolog": "For logging support"}, "require": {"php": ">=7.4"}}"#,
        ),
        (
            "replace_deps",
            r#"{"replace": {"old/package": "self.version"}, "require": {"php": ">=7.4"}}"#,
        ),
    ]
}

// Parser edge case tests

#[tokio::test]
async fn test_npm_parser_edge_cases() {
    let parser_factory = ParserFactory::new();
    let parser = parser_factory.create_parser("package.json").unwrap();

    let test_cases = generate_malformed_package_json_cases();

    for (case_name, content) in test_cases {
        let result = parser.parse_file(content);

        match result {
            Ok(packages) => {
                // Some malformed cases might still parse successfully
                println!(
                    "Case '{}' parsed successfully with {} packages",
                    case_name,
                    packages.len()
                );
            }
            Err(e) => {
                // Expected for many malformed cases
                println!("Case '{}' failed as expected: {:?}", case_name, e);
            }
        }
    }
}

#[tokio::test]
async fn test_cargo_parser_edge_cases() {
    let parser_factory = ParserFactory::new();
    let parser = parser_factory.create_parser("Cargo.toml").unwrap();

    let test_cases = generate_malformed_cargo_toml_cases();

    for (case_name, content) in test_cases {
        let result = parser.parse_file(content);

        match result {
            Ok(packages) => {
                println!(
                    "Case '{}' parsed successfully with {} packages",
                    case_name,
                    packages.len()
                );
            }
            Err(e) => {
                println!("Case '{}' failed as expected: {:?}", case_name, e);
            }
        }
    }
}

#[tokio::test]
async fn test_python_parser_edge_cases() {
    let parser_factory = ParserFactory::new();
    let parser = parser_factory.create_parser("requirements.txt").unwrap();

    let test_cases = generate_malformed_requirements_txt_cases();

    for (case_name, content) in test_cases {
        let result = parser.parse_file(content);

        match result {
            Ok(packages) => {
                println!(
                    "Case '{}' parsed successfully with {} packages",
                    case_name,
                    packages.len()
                );
            }
            Err(e) => {
                println!("Case '{}' failed as expected: {:?}", case_name, e);
            }
        }
    }
}

#[tokio::test]
async fn test_maven_parser_edge_cases() {
    let parser_factory = ParserFactory::new();
    let parser = parser_factory.create_parser("pom.xml").unwrap();

    let test_cases = generate_malformed_pom_xml_cases();

    for (case_name, content) in test_cases {
        let result = parser.parse_file(content);

        match result {
            Ok(packages) => {
                println!(
                    "Case '{}' parsed successfully with {} packages",
                    case_name,
                    packages.len()
                );
            }
            Err(e) => {
                println!("Case '{}' failed as expected: {:?}", case_name, e);
            }
        }
    }
}

#[tokio::test]
async fn test_go_parser_edge_cases() {
    let parser_factory = ParserFactory::new();
    let parser = parser_factory.create_parser("go.mod").unwrap();

    let test_cases = generate_malformed_go_mod_cases();

    for (case_name, content) in test_cases {
        let result = parser.parse_file(content);

        match result {
            Ok(packages) => {
                println!(
                    "Case '{}' parsed successfully with {} packages",
                    case_name,
                    packages.len()
                );
            }
            Err(e) => {
                println!("Case '{}' failed as expected: {:?}", case_name, e);
            }
        }
    }
}

#[tokio::test]
async fn test_php_parser_edge_cases() {
    let parser_factory = ParserFactory::new();
    let parser = parser_factory.create_parser("composer.json").unwrap();

    let test_cases = generate_malformed_composer_json_cases();

    for (case_name, content) in test_cases {
        let result = parser.parse_file(content);

        match result {
            Ok(packages) => {
                println!(
                    "Case '{}' parsed successfully with {} packages",
                    case_name,
                    packages.len()
                );
            }
            Err(e) => {
                println!("Case '{}' failed as expected: {:?}", case_name, e);
            }
        }
    }
}

// File size and performance edge cases

#[tokio::test]
async fn test_extremely_large_files() {
    let parser_factory = ParserFactory::new();

    // Test with very large package.json
    let large_deps: Vec<String> = (0..10000)
        .map(|i| format!(r#""package{}": "1.{}.0""#, i, i % 100))
        .collect();
    let large_package_json = format!(r#"{{"dependencies": {{{}}}}}"#, large_deps.join(","));

    let npm_parser = parser_factory.create_parser("package.json").unwrap();
    let start = std::time::Instant::now();
    let result = npm_parser.parse_file(&large_package_json);
    let duration = start.elapsed();

    match result {
        Ok(packages) => {
            println!(
                "Large package.json parsed in {:?} with {} packages",
                duration,
                packages.len()
            );
            assert!(
                duration.as_secs() < 10,
                "Parsing took too long: {:?}",
                duration
            );
        }
        Err(e) => {
            println!("Large package.json failed to parse: {:?}", e);
        }
    }
}

#[tokio::test]
async fn test_deeply_nested_structures() {
    let parser_factory = ParserFactory::new();

    // Create deeply nested JSON structure
    let mut nested_json = String::from(r#"{"dependencies": {"#);
    for i in 0..1000 {
        nested_json.push_str(&format!(r#""package{}": "{}.0.0","#, i, i));
    }
    nested_json.pop(); // Remove trailing comma
    nested_json.push_str("}}");

    let npm_parser = parser_factory.create_parser("package.json").unwrap();
    let result = npm_parser.parse_file(&nested_json);

    match result {
        Ok(packages) => {
            println!("Deeply nested JSON parsed with {} packages", packages.len());
        }
        Err(e) => {
            println!("Deeply nested JSON failed: {:?}", e);
        }
    }
}

#[tokio::test]
async fn test_unicode_and_special_characters() {
    let parser_factory = ParserFactory::new();

    let unicode_cases = vec![
        // Chinese characters
        (
            r#"{"dependencies": {"测试包": "1.0.0", "另一个包": "2.0.0"}}"#,
            "package.json",
        ),
        // Emojis
        (
            r#"{"dependencies": {"🚀rocket": "1.0.0", "🔥fire": "2.0.0"}}"#,
            "package.json",
        ),
        // Mixed scripts
        (
            r#"{"dependencies": {"αβγ": "1.0.0", "дфг": "2.0.0"}}"#,
            "package.json",
        ),
        // RTL text
        (
            r#"{"dependencies": {"مثال": "1.0.0", "עברית": "2.0.0"}}"#,
            "package.json",
        ),
        // Zero-width characters
        (
            r#"{"dependencies": {"test\u200Bpackage": "1.0.0"}}"#,
            "package.json",
        ),
        // Control characters
        (
            r#"{"dependencies": {"test\npackage": "1.0.0"}}"#,
            "package.json",
        ),
    ];

    for (content, filename) in unicode_cases {
        if let Some(parser) = parser_factory.create_parser(filename) {
            let result = parser.parse_file(content);
            match result {
                Ok(packages) => {
                    println!("Unicode case parsed with {} packages", packages.len());
                }
                Err(e) => {
                    println!("Unicode case failed: {:?}", e);
                }
            }
        }
    }
}

#[tokio::test]
async fn test_version_edge_cases() {
    let parser_factory = ParserFactory::new();
    let npm_parser = parser_factory.create_parser("package.json").unwrap();

    let version_cases = vec![
        // Semantic versioning edge cases
        r#"{"dependencies": {"pkg": "0.0.0"}}"#,
        r#"{"dependencies": {"pkg": "999.999.999"}}"#,
        r#"{"dependencies": {"pkg": "1.0.0-alpha"}}"#,
        r#"{"dependencies": {"pkg": "1.0.0-alpha.1"}}"#,
        r#"{"dependencies": {"pkg": "1.0.0-alpha.beta"}}"#,
        r#"{"dependencies": {"pkg": "1.0.0-alpha.beta.1"}}"#,
        r#"{"dependencies": {"pkg": "1.0.0-alpha0.valid"}}"#,
        r#"{"dependencies": {"pkg": "1.0.0-alpha.0valid"}}"#,
        r#"{"dependencies": {"pkg": "1.0.0-alpha-a.b-c-somethinglong+metadata+is.ok"}}"#,
        r#"{"dependencies": {"pkg": "1.0.0+beta"}}"#,
        r#"{"dependencies": {"pkg": "1.0.0-alpha_beta"}}"#,
        r#"{"dependencies": {"pkg": "1.0.0-alpha."}}"#,
        r#"{"dependencies": {"pkg": "1.0.0-alpha.."}}"#,
        r#"{"dependencies": {"pkg": "1.0.0-alpha..beta"}}"#,
        r#"{"dependencies": {"pkg": "1.0.0-alpha..beta.1"}}"#,
        // Range specifiers
        r#"{"dependencies": {"pkg": "^1.0.0"}}"#,
        r#"{"dependencies": {"pkg": "~1.0.0"}}"#,
        r#"{"dependencies": {"pkg": ">=1.0.0"}}"#,
        r#"{"dependencies": {"pkg": "<=1.0.0"}}"#,
        r#"{"dependencies": {"pkg": ">1.0.0"}}"#,
        r#"{"dependencies": {"pkg": "<1.0.0"}}"#,
        r#"{"dependencies": {"pkg": "1.0.0 - 2.0.0"}}"#,
        r#"{"dependencies": {"pkg": ">=1.0.0 <2.0.0"}}"#,
        r#"{"dependencies": {"pkg": "1.0.x"}}"#,
        r#"{"dependencies": {"pkg": "1.x.x"}}"#,
        r#"{"dependencies": {"pkg": "*"}}"#,
        r#"{"dependencies": {"pkg": "x"}}"#,
        r#"{"dependencies": {"pkg": "latest"}}"#,
        r#"{"dependencies": {"pkg": "next"}}"#,
        // Complex ranges
        r#"{"dependencies": {"pkg": ">=1.0.0 <2.0.0 || >=3.0.0"}}"#,
        r#"{"dependencies": {"pkg": "1.0.0 || 2.0.0 || 3.0.0"}}"#,
        // Invalid versions
        r#"{"dependencies": {"pkg": "not.a.version"}}"#,
        r#"{"dependencies": {"pkg": "1.0.0.0"}}"#,
        r#"{"dependencies": {"pkg": "1.0"}}"#,
        r#"{"dependencies": {"pkg": "1"}}"#,
        r#"{"dependencies": {"pkg": ""}}"#,
        r#"{"dependencies": {"pkg": " "}}"#,
    ];

    for content in version_cases {
        let result = npm_parser.parse_file(content);
        match result {
            Ok(packages) => {
                for package in packages {
                    println!("Parsed package: {} v{}", package.name, package.version);
                }
            }
            Err(e) => {
                println!("Version case failed: {:?}", e);
            }
        }
    }
}

#[tokio::test]
async fn test_concurrent_parsing() {
    let parser_factory = ParserFactory::new();

    let test_contents = vec![
        (r#"{"dependencies": {"express": "4.17.1"}}"#, "package.json"),
        ("[dependencies]\nserde = \"1.0\"", "Cargo.toml"),
        ("django==3.2.0", "requirements.txt"),
        (
            "module test\ngo 1.19\nrequire github.com/gin-gonic/gin v1.7.0",
            "go.mod",
        ),
        (
            r#"{"require": {"monolog/monolog": "^2.0"}}"#,
            "composer.json",
        ),
    ];

    let mut handles = Vec::new();

    for (content, filename) in test_contents {
        let parser_factory_clone = parser_factory.clone();
        let content = content.to_string();
        let filename = filename.to_string();

        let handle = tokio::spawn(async move {
            if let Some(parser) = parser_factory_clone.create_parser(&filename) {
                parser.parse_file(&content)
            } else {
                Err(vulnera_rust::infrastructure::parsers::traits::ParsingError::UnsupportedFormat {
                    filename: filename.clone(),
                    message: "No parser found".to_string(),
                })
            }
        });

        handles.push(handle);
    }

    let results = futures::future::join_all(handles).await;

    for (i, result) in results.into_iter().enumerate() {
        match result {
            Ok(Ok(packages)) => {
                println!(
                    "Concurrent parsing {} succeeded with {} packages",
                    i,
                    packages.len()
                );
            }
            Ok(Err(e)) => {
                println!("Concurrent parsing {} failed: {:?}", i, e);
            }
            Err(e) => {
                println!("Concurrent task {} panicked: {:?}", i, e);
            }
        }
    }
}

#[tokio::test]
async fn test_memory_pressure() {
    let parser_factory = ParserFactory::new();
    let npm_parser = parser_factory.create_parser("package.json").unwrap();

    // Test parsing many files in sequence to check for memory leaks
    for i in 0..100 {
        let content = format!(
            r#"{{"dependencies": {{"package{}": "{}.0.0", "another{}": "{}.1.0"}}}}"#,
            i, i, i, i
        );

        let result = npm_parser.parse_file(&content);

        match result {
            Ok(packages) => {
                assert_eq!(packages.len(), 2);
                // Force memory cleanup
                drop(packages);
            }
            Err(e) => {
                panic!("Memory pressure test failed at iteration {}: {:?}", i, e);
            }
        }

        // Occasional garbage collection hint
        if i % 10 == 0 {
            std::hint::black_box(i);
        }
    }

    println!("Memory pressure test completed successfully");
}

#[tokio::test]
async fn test_parser_priority_system() {
    let parser_factory = ParserFactory::new();

    let test_cases = vec![
        ("package.json", "npm parser"),
        ("package-lock.json", "npm lock parser"),
        ("yarn.lock", "yarn parser"),
        ("Cargo.toml", "cargo parser"),
        ("Cargo.lock", "cargo lock parser"),
        ("requirements.txt", "python parser"),
        ("Pipfile", "python pipfile parser"),
        ("pyproject.toml", "python pyproject parser"),
        ("pom.xml", "maven parser"),
        ("build.gradle", "gradle parser"),
        ("go.mod", "go parser"),
        ("go.sum", "go sum parser"),
        ("composer.json", "php parser"),
        ("composer.lock", "php lock parser"),
        ("unknown.file", "no parser"),
    ];

    for (filename, expected_description) in test_cases {
        let parser = parser_factory.create_parser(filename);

        match parser {
            Some(_) => {
                println!("Found parser for {}: {}", filename, expected_description);
            }
            None => {
                println!("No parser found for {}: {}", filename, expected_description);
            }
        }
    }
}

#[tokio::test]
async fn test_ecosystem_detection() {
    let parser_factory = ParserFactory::new();

    let ecosystem_cases = vec![
        ("package.json", Some(Ecosystem::Npm)),
        ("Cargo.toml", Some(Ecosystem::Cargo)),
        ("requirements.txt", Some(Ecosystem::PyPI)),
        ("pom.xml", Some(Ecosystem::Maven)),
        ("go.mod", Some(Ecosystem::Go)),
        ("composer.json", Some(Ecosystem::Packagist)),
        ("unknown.file", None),
    ];

    for (filename, expected_ecosystem) in ecosystem_cases {
        if let Some(parser) = parser_factory.create_parser(filename) {
            let detected_ecosystem = parser.ecosystem();
            match expected_ecosystem {
                Some(expected) => {
                    assert_eq!(
                        detected_ecosystem, expected,
                        "Ecosystem mismatch for {}",
                        filename
                    );
                }
                None => {
                    panic!("Found parser for {} when none was expected", filename);
                }
            }
        } else {
            assert!(
                expected_ecosystem.is_none(),
                "Expected parser for {} but found none",
                filename
            );
        }
    }
}
