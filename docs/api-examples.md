# Vulnera API Usage Examples

## Overview

The Vulnera API provides comprehensive vulnerability analysis for dependency files across multiple programming language ecosystems. It now also returns safe version recommendations per dependency, including nearest and most up-to-date safe versions, with upgrade impact metadata.

## Authentication

Currently, the API does not require authentication for core endpoints. For repository analysis against GitHub, providing a GitHub token via server configuration is recommended for higher rate limits.

## Base URL

- **Development**: `http://localhost:3000`
- **Production**: `VULNERA__SERVER__HOST`

## Quick Start Examples

### 1. Analyze a Node.js package.json

```bash
curl -X POST "http://localhost:3000/api/v1/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "file_content": "{\"dependencies\": {\"express\": \"4.17.1\", \"lodash\": \"4.17.20\"}}",
    "ecosystem": "npm",
    "filename": "package.json"
  }'
```

### 2. Analyze Python requirements.txt

```bash
curl -X POST "http://localhost:3000/api/v1/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "file_content": "django==3.1.0\nrequests==2.25.0\nnumpy==1.19.0",
    "ecosystem": "pypi"
  }'
```

### 3. Analyze Rust Cargo.toml

```bash
curl -X POST "http://localhost:3000/api/v1/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "file_content": "[dependencies]\nserde = \"1.0\"\ntokio = { version = \"1.0\", features = [\"full\"] }",
    "ecosystem": "cargo",
    "filename": "Cargo.toml"
  }'
```

### 4. Analyze a public GitHub repository

Scan supported dependency manifests across a repository:

```bash
curl -X POST "http://localhost:3000/api/v1/analyze/repository" \
  -H "Content-Type: application/json" \
  -d '{
    "repository_url": "https://github.com/rust-lang/cargo",
    "ref": "main",
    "include_paths": ["crates/", "src/"],
    "exclude_paths": ["tests/"],
    "return_packages": false
  }'
```

Notes:

- Server clamps file count and total bytes per scan based on `apis.github` caps in config.
- Configure a token for better GitHub rate limits.

## Supported Ecosystems

| Ecosystem | Identifier                     | Supported Files (examples)                      |
| --------- | ------------------------------ | ----------------------------------------------- |
| Node.js   | `npm`                          | package.json, package-lock.json, yarn.lock      |
| Python    | `pypi`, `pip`, `python`        | requirements.txt, Pipfile, pyproject.toml       |
| Java      | `maven`                        | pom.xml, build.gradle                           |
| Rust      | `cargo`, `rust`                | Cargo.toml, Cargo.lock                          |
| Go        | `go`                           | go.mod, go.sum                                  |
| PHP       | `packagist`, `composer`, `php` | composer.json, composer.lock                    |
| Ruby      | `rubygems`, `ruby`             | Gemfile, Gemfile.lock                           |
| .NET      | `nuget`, `.net`                | NuGet manifests (e.g., packages.config, csproj) |

## Response Examples

### Successful Analysis Response (with recommendations)

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "vulnerabilities": [
    {
      "id": "CVE-2021-23337",
      "summary": "Prototype Pollution in lodash",
      "description": "lodash versions prior to 4.17.21 are vulnerable to Prototype Pollution via the zipObjectDeep function.",
      "severity": "High",
      "affected_packages": [
        {
          "name": "lodash",
          "version": "4.17.20",
          "ecosystem": "npm",
          "vulnerable_ranges": ["< 4.17.21"],
          "fixed_versions": ["4.17.21"]
        }
      ],
      "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
        "https://github.com/advisories/GHSA-35jh-r3h4-6jhm"
      ],
      "published_at": "2021-02-15T10:30:00Z",
      "sources": ["OSV", "NVD", "GHSA"]
    }
  ],
  "metadata": {
    "total_packages": 2,
    "vulnerable_packages": 1,
    "total_vulnerabilities": 1,
    "severity_breakdown": {
      "critical": 0,
      "high": 1,
      "medium": 0,
      "low": 0
    },
    "analysis_duration_ms": 1250,
    "sources_queried": ["OSV", "NVD", "GHSA"]
  },
  "version_recommendations": [
    {
      "package": "lodash",
      "ecosystem": "npm",
      "current_version": "4.17.20",
      "nearest_safe_above_current": "4.17.21",
      "most_up_to_date_safe": "4.19.2",
      "nearest_impact": "patch",
      "most_up_to_date_impact": "minor",
      "prerelease_exclusion_applied": false,
      "notes": []
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 50,
    "total": 1,
    "total_pages": 1,
    "has_next": false,
    "has_prev": false
  }
}
```

### Repository Analysis Response (with recommendations)

```json
{
  "id": "c1a2b3c4-d5e6-7f89-0abc-def123456789",
  "repository": {
    "owner": "rust-lang",
    "repo": "cargo",
    "requested_ref": "main",
    "commit_sha": "abc123...",
    "source_url": "https://github.com/rust-lang/cargo"
  },
  "files": [
    { "path": "Cargo.toml", "ecosystem": "cargo", "packages_count": 12 }
  ],
  "vulnerabilities": [],
  "metadata": {
    "total_files_scanned": 35,
    "analyzed_files": 22,
    "skipped_files": 13,
    "unique_packages": 120,
    "total_vulnerabilities": 4,
    "severity_breakdown": { "critical": 0, "high": 1, "medium": 2, "low": 1 },
    "duration_ms": 2500,
    "file_errors": 1,
    "rate_limit_remaining": 4999,
    "truncated": false,
    "config_caps": { "max_files_scanned": 200, "max_total_bytes": 2000000 }
  },
  "version_recommendations": [
    {
      "package": "serde",
      "ecosystem": "cargo",
      "current_version": "1.0.0",
      "nearest_safe_above_current": "1.0.192",
      "most_up_to_date_safe": "1.0.204",
      "nearest_impact": "patch",
      "most_up_to_date_impact": "patch",
      "prerelease_exclusion_applied": false,
      "notes": []
    }
  ]
}
```

## Configuration

Control caching and recommendation behavior using environment variables:

- Cache directory (default: .vulnera_cache)
  - VULNERA**CACHE**DIRECTORY=.vulnera_cache
- Default cache TTL in hours (default: 24)
  - VULNERA**CACHE**TTL_HOURS=24
- Exclude prerelease versions from recommendations (default: false)
  - VULNERA**RECOMMENDATIONS**EXCLUDE_PRERELEASES=true|false

Examples:

```bash
ENV=production \
VULNERA__CACHE__DIRECTORY=.vulnera_cache \
VULNERA__CACHE__TTL_HOURS=12 \
VULNERA__RECOMMENDATIONS__EXCLUDE_PRERELEASES=true \
cargo run
```

## Corner Cases and Ecosystem Notes

- NuGet 4-segment versions
  - Some NuGet packages publish four-segment versions (e.g., 4.2.11.1). Vulnera normalizes these for comparison to ensure accurate recommendations, and tests validate this behavior.
- PyPI prerelease behavior
  - When only prerelease versions are safe, Vulnera can still recommend them. Set VULNERA**RECOMMENDATIONS**EXCLUDE_PRERELEASES=true to suppress prerelease recommendations entirely.
- Upgrade impact classification
  - Recommendations include nearest_impact and most_up_to_date_impact to classify the upgrade as major, minor, or patch, helping you assess change risk quickly.

## Advanced Usage

### Pagination

When dealing with large numbers of vulnerabilities, use pagination:

```bash
# Get first page (default)
curl "http://localhost:3000/api/v1/vulnerabilities?page=1&per_page=10"

# Get specific page
curl "http://localhost:3000/api/v1/vulnerabilities?page=2&per_page=25"

# Filter by severity
curl "http://localhost:3000/api/v1/vulnerabilities?severity=critical&page=1"
```

### Retrieve Analysis Report

```bash
curl "http://localhost:3000/api/v1/reports/550e8400-e29b-41d4-a716-446655440000"
```

### Get Vulnerability Details

```bash
curl "http://localhost:3000/api/v1/vulnerabilities/CVE-2021-23337"
```

## Health Monitoring

### Basic Health Check

```bash
curl "http://localhost:3000/health"
```

### Detailed Health Check

```bash
curl "http://localhost:3000/health/detailed"
```

### Prometheus Metrics

```bash
curl "http://localhost:3000/metrics"
```

## SDK Examples

### JavaScript/Node.js

```javascript
const axios = require("axios");

class VulneraClient {
  constructor(baseURL = "http://localhost:3000") {
    this.client = axios.create({ baseURL });
  }

  async analyzePackageJson(packageJsonContent) {
    try {
      const response = await this.client.post("/api/v1/analyze", {
        file_content: packageJsonContent,
        ecosystem: "npm",
        filename: "package.json",
      });
      return response.data;
    } catch (error) {
      throw new Error(
        `Analysis failed: ${error.response?.data?.message || error.message}`,
      );
    }
  }

  async getVulnerability(vulnerabilityId) {
    try {
      const response = await this.client.get(
        `/api/v1/vulnerabilities/${vulnerabilityId}`,
      );
      return response.data;
    } catch (error) {
      throw new Error(
        `Failed to get vulnerability: ${error.response?.data?.message || error.message}`,
      );
    }
  }
}

// Usage
const client = new VulneraClient();
const packageJson = '{"dependencies": {"express": "4.17.1"}}';
client
  .analyzePackageJson(packageJson)
  .then((result) =>
    console.log("Vulnerabilities found:", result.vulnerabilities.length),
  )
  .catch((error) => console.error("Error:", error.message));
```

### Python

```python
import requests
import json

class VulneraClient:
    def __init__(self, base_url="http://localhost:3000"):
        self.base_url = base_url
        self.session = requests.Session()

    def analyze_requirements(self, requirements_content):
        """Analyze Python requirements.txt content"""
        payload = {
            "file_content": requirements_content,
            "ecosystem": "pypi"
        }

        response = self.session.post(
            f"{self.base_url}/api/v1/analyze",
            json=payload
        )
        response.raise_for_status()
        return response.json()

    def get_vulnerability(self, vulnerability_id):
        """Get details for a specific vulnerability"""
        response = self.session.get(
            f"{self.base_url}/api/v1/vulnerabilities/{vulnerability_id}"
        )
        response.raise_for_status()
        return response.json()

# Usage
client = VulneraClient()
requirements = "django==3.1.0\nrequests==2.25.0"
result = client.analyze_requirements(requirements)
print(f"Found {len(result['vulnerabilities'])} vulnerabilities")
```

### Go

```go
package main()

// ... unchanged example from above ...
```

## Rate Limiting

The API implements rate limiting to ensure fair usage:

- **Default**: 100 requests per minute per IP
- **Burst**: Up to 10 requests in a 1-second window
- **Headers**: Rate limit information is returned in response headers:
  - `X-RateLimit-Limit`: Requests allowed per window
  - `X-RateLimit-Remaining`: Requests remaining in current window
  - `X-RateLimit-Reset`: Time when the rate limit resets

## Error Handling

The API uses standard HTTP status codes:

- **200**: Success
- **400**: Bad Request (invalid input)
- **404**: Not Found
- **422**: Unprocessable Entity (unsupported format)
- **429**: Too Many Requests (rate limited)
- **500**: Internal Server Error

All error responses include a structured error object with:

- `code`: Machine-readable error code
- `message`: Human-readable description
- `details`: Additional context (optional)
- `request_id`: Unique identifier for debugging
- `timestamp`: When the error occurred

## Best Practices

1. **Cache Results**: Results are cached (default 24h). Identical requests return cached results.
2. **Batch Processing**: For multiple files, send separate requests rather than combining files.
3. **Recommendations**: Use nearest_impact/most_up_to_date_impact to assess change risk (major/minor/patch).
4. **Prereleases**: Control prerelease suggestions with VULNERA**RECOMMENDATIONS**EXCLUDE_PRERELEASES.
5. **Pagination**: Use pagination for large result sets to avoid timeouts.
6. **Monitoring**: Use health check endpoints to monitor API availability.
7. **Timeouts**: Set appropriate timeouts (recommended: 30 seconds) for analysis requests.

## Support

For API support and questions:

- **Documentation**: Available at `/docs` endpoint
- **Email**: <mailto:degea5601@gmail.com>
- **Issues**: Report bugs and feature requests on GitHub

## Team

- Khaled Mahmoud — Project Manager, Main Developer, Rust Backend Developer
- Amr Medhat — Cloud Engineer
- Youssef Mohammed — Database Engineer
- Gasser Mohammed — Frontend Developer
- Abd El-Rahman Mossad — Frontend Developer
