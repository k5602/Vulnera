# API Versioning and Deprecation Policy

## Current Version: v1

The Vulnera API follows semantic versioning (SemVer) principles and maintains backward compatibility within major versions. URL versioning is coarse-grained (v1, v2...), while minor and patch versions are communicated via headers and OpenAPI docs.

## Versioning Strategy

### URL Versioning

All API endpoints are versioned through the URL path:

- Current: `/api/v1/`
- Future: `/api/v2/`, `/api/v3/`, etc.

### Version Format

- Major: Breaking changes that require client updates
- Minor: New features that are backward compatible
- Patch: Bug fixes and security updates

## Supported Versions

| Version | Status | Support Level | End of Life |
|---------|--------|---------------|-------------|
| v1.x | Current | Full Support | TBD |

## Deprecation Policy

### Deprecation Timeline

1. **Announcement**: 6 months before deprecation
2. **Warning Headers**: Added to deprecated endpoints
3. **Documentation**: Updated with migration guides
4. **Sunset**: Version becomes unavailable

### Deprecation Headers

Deprecated endpoints include these headers:

```http
Deprecation: true
Sunset: 2025-12-31T23:59:59Z
Link: </docs/migration>; rel="successor-version"
```

### Breaking Changes

Breaking changes that trigger a major version bump include:

- Removing endpoints or parameters
- Changing response formats
- Modifying authentication requirements
- Altering error response structures

## Migration Guides

### Future v2 (Planned)

**Expected Changes:**

- Enhanced vulnerability scoring system
- Improved pagination with cursor-based navigation
- Additional ecosystem support
- Real-time vulnerability notifications

**Migration Path:**

- All v1 endpoints will remain functional during transition period
- New v2 endpoints will be available alongside v1
- Gradual migration recommended over 6-month period

## Version Detection

### Request Headers

Clients can specify version preferences:

```http
Accept: application/vnd.vulnera.v1+json
```

### Response Headers

All responses include version information:

```http
API-Version: 1
Supported-Versions: 1
```

## Backward Compatibility

### Guaranteed Compatibility

Within major versions, we guarantee:

- Existing endpoints remain functional
- Response formats maintain required fields
- Authentication methods stay consistent
- Error codes remain stable

### Additive Changes

These changes are considered non-breaking:

- Adding new optional parameters
- Adding new response fields
- Adding new endpoints
- Adding new HTTP methods to existing endpoints

## Client Recommendations

### Version Pinning

Always specify the API version in your requests:

```bash
curl -H "Accept: application/vnd.vulnera.v1+json" \
     "https://api.vulnera.dev/api/v1/analyze"
```

### Error Handling

Handle version-related errors gracefully:

```json
{
  "code": "VERSION_NOT_SUPPORTED",
  "message": "API version 0.9 is no longer supported",
  "details": {
  "supported_versions": ["1"],
    "migration_guide": "https://vulnera.dev/docs/migration"
  }
}
```

### Monitoring

Monitor these response headers for deprecation notices:

- `Deprecation`
- `Sunset`
- `Link` (for migration information)

## Changelog

### v1 (Current)

- Initial stable release
- Full OpenAPI 3.0 specification
- Support for 6 package ecosystems
- Comprehensive vulnerability analysis
- Pagination support
- Health monitoring endpoints
- Repository analysis endpoint `/api/v1/analyze/repository`

### v0.9.x (Deprecated Python)

- Limited ecosystem support
- Basic vulnerability detection


## Contact

For version-specific questions or migration support:

- **Email**: <mailto:degea5601@gmail.com>
- **Documentation**: <https://vulnera.dev/docs/versioning>
- **Status Page**: <https://status.vulnera.dev>

## Team

- Khaled Mahmoud — Project Manager, Main Developer, Rust Backend Developer
- Amr Medhat — Cloud Engineer
- Youssef Mohammed — Database Engineer
- Gasser Mohammed — Frontend Developer
- Abd El-Rahman Mossad — Frontend Developer
