# Vulnera Rust - Vulnerability Analysis API

A comprehensive, high-performance vulnerability analysis API built with Rust, designed to analyze software dependencies across multiple programming language ecosystems. This is the next-generation Rust backend that replaces the original Python implementation with enhanced performance, scalability, and multi-ecosystem support.

## Features

- **🚀 High Performance**: Built with Rust and Tokio for maximum concurrency and speed
- **🌐 Multi-Ecosystem Support**: Analyze dependencies from npm, PyPI, Maven, Cargo, Go, Packagist, RubyGems, and NuGet
- **🏗️ Domain-Driven Design**: Clean architecture with separation of concerns for maintainability
- **📊 Multiple Data Sources**: Integrates with OSV, NVD, and GitHub Security Advisories
- **⚡ Async Architecture**: Full async/await implementation for optimal performance
- **💾 Smart Caching**: Filesystem-based caching with configurable TTL
- **🔒 Security First**: Built-in rate limiting, input validation, and secure API handling
- **📖 OpenAPI Documentation**: Auto-generated Swagger UI for easy API exploration
- **🐳 Container Ready**: Docker support with multi-stage builds for production deployment
- **🔧 Developer Friendly**: Comprehensive tooling, linting, and development environment setup

## Requirements

- **Rust**: 1.70.0 or higher
- **System Dependencies**: OpenSSL development libraries
- **Internet Connection**: Required for vulnerability database API calls
- **Memory**: Minimum 512MB RAM (2GB+ recommended for production)
- **Storage**: ~100MB for application + cache storage

## Installation

### From Source

1. **Clone the repository:**
```bash
git clone https://github.com/vulnera/vulnera.git
cd vulnera
```

2. **Install Rust** (if not already installed):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

3. **Install system dependencies:**

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install pkg-config libssl-dev
```

**macOS:**
```bash
brew install openssl pkg-config
```

**Windows:**
```bash
# Install Visual Studio Build Tools or Visual Studio Community
# OpenSSL will be handled by vcpkg automatically
```

4. **Build the application:**
```bash
cargo build --release
```

5. **Run the application:**
```bash
cargo run
# or
./target/release/vulnera-rust
```

### Using Docker

```bash
# Build the image
docker build -t vulnera-rust .

# Run the container
docker run -p 3000:3000 vulnera-rust

# Or use docker-compose
cd scripts/docker && docker-compose up
```

### Development Setup

```bash
# Install development dependencies
make -C scripts/build_workflow install-deps

# Setup pre-commit hooks
pre-commit install

# Run in development mode with auto-reload
make dev
```

## Usage

### Starting the Server

```bash
# Using cargo
cargo run

# Using the binary
./target/release/vulnera-rust

# With custom configuration
VULNERA__SERVER__PORT=8080 cargo run

# Using Docker
docker run -p 3000:3000 -e VULNERA__SERVER__PORT=3000 vulnera-rust
```

### API Endpoints

Once the server is running, you can access:

- **API Documentation**: http://localhost:3000/docs
- **Health Check**: http://localhost:3000/health
- **Detailed Health**: http://localhost:3000/health/detailed

### Analyzing Dependencies

**POST /api/v1/analyze**

```bash
# Analyze a Python requirements.txt file
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "file_content": "django==3.2.0\nrequests>=2.25.0\nnumpy~=1.21.0",
    "ecosystem": "PyPI",
    "filename": "requirements.txt"
  }'

# Analyze a Node.js package.json
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "file_content": "{\"dependencies\": {\"express\": \"4.17.1\", \"lodash\": \"4.17.20\"}}",
    "ecosystem": "npm",
    "filename": "package.json"
  }'

# Analyze a Rust Cargo.toml
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "file_content": "[dependencies]\nserde = \"1.0\"\ntokio = { version = \"1.0\", features = [\"full\"] }",
    "ecosystem": "Cargo",
    "filename": "Cargo.toml"
  }'
```

### Getting Vulnerability Details

**GET /api/v1/vulnerabilities/{id}**

```bash
curl http://localhost:3000/api/v1/vulnerabilities/GHSA-xxxx-xxxx-xxxx
```

### Retrieving Analysis Reports

**GET /api/v1/reports/{id}**

```bash
curl http://localhost:3000/api/v1/reports/550e8400-e29b-41d4-a716-446655440000
```

### Environment Variables

The script can use an API key from the environment variable:

```bash
export VULNERABILITY_API_KEY=your_api_key_here
python vulnerability_analyzer.py requirements.txt
```

**Note**: Currently, the OSV API doesn't require an API key, but the script is designed to support it for future use or other vulnerability databases.

## Supported Ecosystems & File Formats

### Python (PyPI)
- `requirements.txt`
- `Pipfile`
- `pyproject.toml`

### Node.js (npm)
- `package.json`
- `package-lock.json`
- `yarn.lock`

### Java (Maven)
- `pom.xml`
- `build.gradle`
- `build.gradle.kts`

### Rust (Cargo)
- `Cargo.toml`
- `Cargo.lock`

### Go
- `go.mod`
- `go.sum`

### PHP (Packagist)
- `composer.json`
- `composer.lock`

### Ruby (RubyGems)
- `Gemfile`
- `Gemfile.lock`

### .NET (NuGet)
- `packages.config`
- `*.csproj`
- `Directory.Packages.props`

## API Response Examples

### Analysis Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "vulnerabilities": [
    {
      "id": "GHSA-xxxx-xxxx-xxxx",
      "summary": "Cross-site Scripting in Django",
      "description": "Django before 3.2.15 allows XSS via user-supplied data...",
      "severity": "High",
      "affected_packages": [
        {
          "name": "django",
          "version": "3.2.0",
          "ecosystem": "PyPI",
          "vulnerable_ranges": [">=3.2.0,<3.2.15"],
          "fixed_versions": ["3.2.15"]
        }
      ],
      "references": [
        "https://github.com/django/django/security/advisories/GHSA-xxxx-xxxx-xxxx"
      ],
      "published_at": "2023-08-01T10:00:00Z",
      "sources": ["OSV", "GHSA"]
    }
  ],
  "metadata": {
    "total_packages": 15,
    "vulnerable_packages": 3,
    "total_vulnerabilities": 5,
    "severity_breakdown": {
      "critical": 1,
      "high": 2,
      "medium": 1,
      "low": 1
    },
    "analysis_duration_ms": 1250,
    "sources_queried": ["OSV", "NVD", "GHSA"]
  },
  "pagination": {
    "page": 1,
    "per_page": 50,
    "total": 5,
    "total_pages": 1,
    "has_next": false,
    "has_prev": false
  }
}
```

### Health Check Response

```json
{
  "status": "healthy",
  "version": "0.1.0",
  "timestamp": "2024-01-15T10:30:00Z",
  "details": {
    "dependencies": {
      "osv_api": "healthy",
      "nvd_api": "healthy",
      "ghsa_api": "healthy"
    }
  }
}
```

## Configuration

### Environment Profiles & Variables

The application supports three environment profiles selected via the `ENV` variable: `development`, `staging`, and `production`.

Profile goals:

- Development: fast iteration, verbose logs, docs enabled, permissive CORS.
- Staging: mirrors production with docs enabled for QA, restricted CORS.
- Production: hardened; Swagger UI disabled (unless explicitly enabled), strict CORS, lean logging.

Configuration files loaded in order (later overrides earlier):
1. `config/default.toml`
2. `config/local.toml` (optional, git-ignored)
3. `config/{ENV}.toml` if `ENV` is set
4. Environment variables with prefix `VULNERA__` (highest precedence)

Key new server fields:
- `enable_docs` (bool): Expose Swagger UI at `/docs` when true.
- `request_timeout_seconds` (u64): Global per-request timeout.
- `allowed_origins` (array): CORS origins (use `[*]` only in development).

```bash
# Server Configuration
VULNERA__SERVER__HOST=0.0.0.0
VULNERA__SERVER__PORT=3000
# Disable docs in production explicitly (default in production.toml is false)
VULNERA__SERVER__ENABLE_DOCS=false
# Override timeout if needed
VULNERA__SERVER__REQUEST_TIMEOUT_SECONDS=45
# Comma separated is not supported; set via config file for multiple origins

# Cache Configuration
VULNERA__CACHE__DIRECTORY=.vulnera_cache
VULNERA__CACHE__TTL_HOURS=24

# API Keys (optional but recommended for better rate limits)
VULNERA__APIS__NVD__API_KEY=your_nvd_api_key_here
VULNERA__APIS__GHSA__TOKEN=your_github_token_here

# Logging Configuration
VULNERA__LOGGING__LEVEL=info
VULNERA__LOGGING__FORMAT=json

# Select profile
ENV=production
```

### Configuration Files

Create `config/local.toml` for local overrides:

```toml
[server]
host = "127.0.0.1"
port = 8080

[apis.nvd]
api_key = "your_api_key_here"

[apis.ghsa]
token = "your_github_token_here"

[logging]
level = "debug"
format = "pretty"
```

## Development

### Available Make Commands

```bash
# Development
make build              # Build the project
make test               # Run tests
make check              # Run cargo check
make lint               # Run clippy linter
make format             # Format code with rustfmt
make run                # Run the application
make dev                # Run with file watching

# Quality Assurance
make ci-check           # Run all CI checks
make pre-commit         # Run pre-commit checks
make audit              # Run security audit
make coverage           # Generate test coverage

# Docker
make docker-build       # Build Docker image
make docker-run         # Run Docker container

# Documentation
make docs               # Generate and open documentation
```

### Project Structure

```
vulnera-rust/
├── src/
│   ├── domain/              # Domain entities and business logic
│   │   ├── entities.rs      # Core business entities
│   │   ├── value_objects.rs # Immutable value objects
│   │   ├── services.rs      # Domain services
│   │   └── errors.rs        # Domain-specific errors
│   ├── application/         # Use cases and application services
│   │   ├── services.rs      # Application service traits
│   │   ├── use_cases.rs     # Business use cases
│   │   └── errors.rs        # Application errors
│   ├── infrastructure/      # External concerns
│   │   ├── api_clients/     # External API clients
│   │   ├── cache/           # Caching implementations
│   │   ├── parsers/         # File format parsers
│   │   └── repositories.rs  # Data access implementations
│   ├── presentation/        # Web API layer
│   │   ├── controllers/     # HTTP request handlers
│   │   ├── models.rs        # API request/response models
│   │   ├── middleware.rs    # HTTP middleware
│   │   └── routes.rs        # Route definitions
│   ├── config.rs            # Configuration management
│   ├── logging.rs           # Logging setup
│   ├── lib.rs               # Library root
│   └── main.rs              # Application entry point
├── config/                  # Configuration files
├── .github/workflows/       # CI/CD pipelines
├── .vscode/                 # VS Code settings
├── Dockerfile               # Container definition
├── docker-compose.yml       # Development compose
├── Makefile                 # Development commands
└── README.md                # This file
```

## Architecture

### Domain-Driven Design

The application follows DDD principles with clear separation of concerns:

- **Domain Layer**: Core business logic, entities, and domain services
- **Application Layer**: Use cases, application services, and orchestration
- **Infrastructure Layer**: External API clients, caching, and data persistence
- **Presentation Layer**: HTTP API, request/response handling, and OpenAPI documentation

### Key Components

1. **Multi-Ecosystem Parsers**: Pluggable parsers for different package managers
2. **Vulnerability Aggregation**: Combines data from multiple security databases
3. **Async Processing**: Full async/await for maximum concurrency
4. **Smart Caching**: Reduces API calls with intelligent cache management
5. **Rate Limiting**: Built-in protection against API rate limits
6. **Error Handling**: Comprehensive error types with graceful degradation

## Vulnerability Data Sources

### OSV (Open Source Vulnerability) Database
- **Base URL**: https://api.osv.dev/v1
- **Coverage**: Multi-ecosystem vulnerability database
- **Rate Limiting**: Built-in rate limiting with exponential backoff
- **Documentation**: https://osv.dev/

### National Vulnerability Database (NVD)
- **Base URL**: https://services.nvd.nist.gov/rest/json
- **Coverage**: Comprehensive CVE database
- **API Key**: Optional but recommended for higher rate limits
- **Documentation**: https://nvd.nist.gov/developers

### GitHub Security Advisories (GHSA)
- **Base URL**: https://api.github.com/graphql
- **Coverage**: GitHub-specific security advisories
- **Authentication**: GitHub token required
- **Documentation**: https://docs.github.com/en/graphql

## Vulnerability Severity Levels

- **CRITICAL**: CVSS score 9.0-10.0 (Immediate action required)
- **HIGH**: CVSS score 7.0-8.9 (High priority fix)
- **MEDIUM**: CVSS score 4.0-6.9 (Medium priority fix)
- **LOW**: CVSS score 0.1-3.9 (Low priority fix)
- **UNKNOWN**: No CVSS score available

## Error Handling

The script includes comprehensive error handling for:

- File not found errors
- Network connectivity issues
- API rate limiting and timeouts
- Invalid file formats
- JSON parsing errors
- Session management failures

## Performance & Scalability

- **Concurrent Processing**: Handles multiple analysis requests simultaneously
- **Async I/O**: Non-blocking operations for maximum throughput
- **Smart Caching**: Configurable TTL reduces redundant API calls
- **Rate Limiting**: Respects external API limits automatically
- **Memory Efficient**: Streaming processing for large dependency files
- **Horizontal Scaling**: Stateless design supports load balancing

## Contributing

We welcome contributions! Please follow these steps:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Follow the coding standards**:
   - Run `make format` to format code
   - Run `make lint` to check for issues
   - Run `make test` to ensure tests pass
4. **Write tests** for new functionality
5. **Update documentation** as needed
6. **Commit your changes**: `git commit -m 'Add amazing feature'`
7. **Push to the branch**: `git push origin feature/amazing-feature`
8. **Open a Pull Request**

### Development Guidelines

- Follow Rust best practices and idioms
- Maintain the Domain-Driven Design architecture
- Write comprehensive tests for new features
- Update OpenAPI documentation for API changes
- Use conventional commit messages

## Deployment

### Production Deployment

```bash
# Build optimized binary
cargo build --release

# Run with production configuration
ENV=production ./target/release/vulnera-rust
```

### Docker Deployment

```bash
# Build and run with Docker
docker build -t vulnera-rust .
docker run -d -p 3000:3000 --name vulnera vulnera-rust

# Or use docker-compose for full stack
docker-compose up -d
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnera-rust
spec:
  replicas: 3
  selector:
    matchLabels:
      app: vulnera-rust
  template:
    metadata:
      labels:
        app: vulnera-rust
    spec:
      containers:
      - name: vulnera-rust
        image: vulnera-rust:latest
        ports:
        - containerPort: 3000
        env:
        - name: VULNERA__SERVER__HOST
          value: "0.0.0.0"
        - name: VULNERA__SERVER__PORT
          value: "3000"
```

## Troubleshooting

### Common Issues

1. **Build Errors**: Ensure you have the latest Rust toolchain and system dependencies
2. **Network Errors**: Check internet connectivity and firewall settings
3. **API Rate Limits**: Configure API keys for higher rate limits
4. **Memory Issues**: Increase available memory for large dependency files
5. **Cache Issues**: Clear cache directory or adjust TTL settings

### Debugging

```bash
# Enable debug logging
VULNERA__LOGGING__LEVEL=debug cargo run

# Check health endpoints
curl http://localhost:3000/health/detailed

# View application logs
docker logs vulnera-rust
```

### Getting Help

- **Issues**: Report bugs on GitHub Issues
- **Discussions**: Join GitHub Discussions for questions
- **Documentation**: Check the `/docs` endpoint when running
- **API Reference**: Available at `/docs` when server is running
## Changelog

### v3.0.0 (Current - Rust Rewrite)

- **🚀 Complete Rewrite**: Migrated from Python to Rust for superior performance
- **🌐 Multi-Ecosystem Support**: Added support for npm, Maven, Cargo, Go, PHP, Ruby, .NET
- **🏗️ Domain-Driven Design**: Clean architecture with proper separation of concerns
- **📊 Multiple Data Sources**: Integration with OSV, NVD, and GitHub Security Advisories
- **🔧 RESTful API**: Complete HTTP API with OpenAPI documentation
- **⚡ Async Architecture**: Full async/await implementation using Tokio
- **💾 Enhanced Caching**: Configurable filesystem-based caching with TTL
- **🐳 Container Support**: Docker and Kubernetes deployment ready
- **🔒 Security Hardening**: Built-in rate limiting, input validation, and secure defaults
- **📖 Auto-Documentation**: Swagger UI integration for API exploration
- **🛠️ Developer Experience**: Comprehensive tooling, linting, and CI/CD pipelines

### v2.0.0 (Python - Legacy)

- **Breaking**: Migrated to async/await architecture using `aiohttp`
- **Added**: Concurrent package analysis for improved performance
- **Added**: Smart caching system with 24-hour expiry
- **Added**: Enhanced HTML reports with responsive design
- **Improved**: Rate limiting and error handling

### v1.0.0 (Python - Legacy)

- Initial Python implementation
- Support for requirements.txt parsing
- OSV API integration
- Basic text and HTML report generation

## License

MIT License - See LICENSE file for details

## Security Considerations

- **API Communication**: All external API calls use HTTPS with certificate validation
- **Data Privacy**: Only package names and versions are transmitted (no sensitive code)
- **API Key Security**: Store API keys securely using environment variables or secret management
- **Input Validation**: All user inputs are validated and sanitized
- **Rate Limiting**: Built-in protection against API abuse and rate limiting
- **Container Security**: Runs as non-root user in Docker containers
- **Network Security**: Consider running behind a reverse proxy in production
- **Cache Security**: Cache files contain only public vulnerability data
- **Audit Trail**: Comprehensive logging for security monitoring

## Roadmap

- [ ] **Machine Learning**: AI-powered vulnerability risk assessment
- [ ] **Integration APIs**: Webhooks and CI/CD pipeline integrations
- [ ] **Advanced Caching**: Redis and distributed caching support
- [ ] **Metrics & Monitoring**: Prometheus metrics and health monitoring
- [ ] **Authentication**: API key management and user authentication
- [ ] **Batch Processing**: Bulk analysis capabilities for large repositories
- [ ] **Custom Rules**: User-defined vulnerability filtering and scoring
- [ ] **Reporting Engine**: Advanced report templates and formats
- [ ] **Plugin System**: Extensible architecture for custom integrations
