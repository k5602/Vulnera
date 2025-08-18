# Vulnera API Usage Examples

## Overview

The Vulnera API provides comprehensive vulnerability analysis for dependency files across multiple programming language ecosystems. This guide provides practical examples for integrating with the API.

## Authentication

Currently, the API does not require authentication. All endpoints are publicly accessible.

## Base URL

- **Development**: `http://localhost:3000`
- **Staging**: `https://staging.vulnera.dev`
- **Production**: `https://api.vulnera.dev`

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

## Supported Ecosystems

| Ecosystem | Identifier | Supported Files |
|-----------|------------|-----------------|
| Node.js | `npm` | package.json, package-lock.json, yarn.lock |
| Python | `pypi`, `pip`, `python` | requirements.txt, Pipfile, pyproject.toml |
| Java | `maven` | pom.xml, build.gradle |
| Rust | `cargo`, `rust` | Cargo.toml, Cargo.lock |
| Go | `go` | go.mod, go.sum |
| PHP | `packagist`, `composer`, `php` | composer.json, composer.lock |

## Response Examples

### Successful Analysis Response

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

### Error Response Example

```json
{
  "code": "PARSE_ERROR",
  "message": "Failed to parse dependency file: Invalid JSON format",
  "details": {
    "field": "file_content",
    "line": 5,
    "column": 12
  },
  "request_id": "req_550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

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
const axios = require('axios');

class VulneraClient {
  constructor(baseURL = 'http://localhost:3000') {
    this.client = axios.create({ baseURL });
  }

  async analyzePackageJson(packageJsonContent) {
    try {
      const response = await this.client.post('/api/v1/analyze', {
        file_content: packageJsonContent,
        ecosystem: 'npm',
        filename: 'package.json'
      });
      return response.data;
    } catch (error) {
      throw new Error(`Analysis failed: ${error.response?.data?.message || error.message}`);
    }
  }

  async getVulnerability(vulnerabilityId) {
    try {
      const response = await this.client.get(`/api/v1/vulnerabilities/${vulnerabilityId}`);
      return response.data;
    } catch (error) {
      throw new Error(`Failed to get vulnerability: ${error.response?.data?.message || error.message}`);
    }
  }
}

// Usage
const client = new VulneraClient();
const packageJson = '{"dependencies": {"express": "4.17.1"}}';
client.analyzePackageJson(packageJson)
  .then(result => console.log('Vulnerabilities found:', result.vulnerabilities.length))
  .catch(error => console.error('Error:', error.message));
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
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
)

type VulneraClient struct {
    BaseURL string
    Client  *http.Client
}

type AnalysisRequest struct {
    FileContent string `json:"file_content"`
    Ecosystem   string `json:"ecosystem"`
    Filename    string `json:"filename,omitempty"`
}

type AnalysisResponse struct {
    ID              string                 `json:"id"`
    Vulnerabilities []VulnerabilityDto     `json:"vulnerabilities"`
    Metadata        AnalysisMetadataDto    `json:"metadata"`
    Pagination      PaginationDto          `json:"pagination"`
}

func NewVulneraClient(baseURL string) *VulneraClient {
    return &VulneraClient{
        BaseURL: baseURL,
        Client:  &http.Client{},
    }
}

func (c *VulneraClient) AnalyzeGoMod(goModContent string) (*AnalysisResponse, error) {
    req := AnalysisRequest{
        FileContent: goModContent,
        Ecosystem:   "go",
        Filename:    "go.mod",
    }

    jsonData, err := json.Marshal(req)
    if err != nil {
        return nil, err
    }

    resp, err := c.Client.Post(
        c.BaseURL+"/api/v1/analyze",
        "application/json",
        bytes.NewBuffer(jsonData),
    )
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var result AnalysisResponse
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }

    return &result, nil
}

func main() {
    client := NewVulneraClient("http://localhost:3000")
    goMod := `module example.com/myapp
go 1.19
require github.com/gin-gonic/gin v1.7.0`

    result, err := client.AnalyzeGoMod(goMod)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }

    fmt.Printf("Found %d vulnerabilities\n", len(result.Vulnerabilities))
}
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

1. **Cache Results**: Analysis results are cached for 24 hours. Identical requests will return cached results.

2. **Batch Processing**: For multiple files, send separate requests rather than combining files.

3. **Error Handling**: Always check the response status and handle errors appropriately.

4. **Pagination**: Use pagination for large result sets to avoid timeouts.

5. **Monitoring**: Use health check endpoints to monitor API availability.

6. **Timeouts**: Set appropriate timeouts (recommended: 30 seconds) for analysis requests.

## Support

For API support and questions:
- **Documentation**: Available at `/docs` endpoint
- **Email**: degea5601@gmail.com
- **Issues**: Report bugs and feature requests on GitHub
