# API Versioning and Deprecation Policy

## Current Version: v1.0.0

The Vulnera API follows semantic versioning (SemVer) principles for API versioning and maintains backward compatibility within major versions.

## Versioning Strategy

### URL Versioning
All API endpoints are versioned through the URL path:
- Current: `/api/v1/`
- Future: `/api/v2/`, `/api/v3/`, etc.

### Version Format
- **Major Version**: Breaking changes that require client updates
- **Minor Version**: New features that are backward compatible
- **Patch Version**: Bug fixes and security updates

## Supported Versions

| Version | Status | Support Level | End of Life |
|---------|--------|---------------|-------------|
| v1.0.x | Current | Full Support | TBD |

## Deprecation Policy

### Deprecation Timeline
1. **Announcement**: 6 months before deprecation
2. **Warning Headers**: Added to deprecated endpoints
3. **Documentation**: Updated with migration guides
4. **Sunset**: Version becomes unavailable

### Deprecation Headers
Deprecated endpoints include these headers:
```
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

### Future v2.0 (Planned)
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
```
Accept: application/vnd.vulnera.v1+json
```

### Response Headers
All responses include version information:
```
API-Version: 1.0.0
Supported-Versions: 1.0
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
    "supported_versions": ["1.0"],
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

### v1.0.0 (Current)
- Initial stable release
- Full OpenAPI 3.0 specification
- Support for 6 package ecosystems
- Comprehensive vulnerability analysis
- Pagination support
- Health monitoring endpoints

### v0.9.x (Deprecated python)
- Limited ecosystem support
- Basic vulnerability detection


## Contact

For version-specific questions or migration support:
- **Email**: degea5601@gmail.com
- **Documentation**: https://vulnera.dev/docs/versioning
- **Status Page**: https://status.vulnera.dev
