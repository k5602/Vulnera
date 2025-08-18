# Vulnera "Vulnerability Analyzer Toolkit"

A high-performance async Python tool for analyzing dependency files to identify security vulnerabilities and recommend safe package updates using the OSV (Open Source Vulnerability) API.

## Features

- **Async Architecture**: Fast concurrent analysis using `aiohttp` for parallel API calls
- **Smart Caching**: Local filesystem cache with 24-hour expiry to minimize API requests
- **Multi-format Support**: Parses `requirements.txt` files with various version specifiers
- **Vulnerability Detection**: Uses the OSV (Open Source Vulnerability) API to identify known CVEs
- **Update Recommendations**: Suggests specific fixed versions or latest secure versions
- **Enhanced Reporting**: Generates reports in text (with emojis) or interactive HTML format
- **Auto-Browser Opening**: HTML reports automatically open in your default browser
- **Rate Limiting**: Optimized 0.1s delay between requests for performance
- **Comprehensive Error Handling**: Graceful degradation with detailed error messages

## Requirements

- Python 3.6 or higher
- Internet connection for API calls
- **Dependencies**: `aiohttp==3.12.15` and `tqdm==4.66.4`

## Installation

1. Clone the repository:

```bash
git clone https://github.com/k5602/Vulnera.git
cd Vulnera
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Make the analyzer executable (optional):

```bash
chmod +x vulnerability_analyzer.py
```

## Usage

### Basic Usage

```bash
python vulnerability_analyzer.py requirements.txt
```

### Enhanced Shell Wrapper

The recommended way to run the analyzer is using the enhanced shell wrapper:

```bash
# Basic analysis
./run_analyzer.sh requirements.txt

# Analyze sample file
./run_analyzer.sh -s

# Generate HTML report
./run_analyzer.sh -f html -o my_report.html requirements.txt

# Show all options
./run_analyzer.sh --help
```

### Advanced Python Usage

```bash
# Generate HTML report (auto-saved to reports/ directory)
python vulnerability_analyzer.py requirements.txt --format html

# Generate HTML with custom output path
python vulnerability_analyzer.py requirements.txt --format html --output security_report.html

# Use custom API key
python vulnerability_analyzer.py requirements.txt --api-key YOUR_API_KEY

# Save text report to file
python vulnerability_analyzer.py requirements.txt --output vulnerability_report.txt
```

### Environment Variables

The script can use an API key from the environment variable:

```bash
export VULNERABILITY_API_KEY=your_api_key_here
python vulnerability_analyzer.py requirements.txt
```

**Note**: Currently, the OSV API doesn't require an API key, but the script is designed to support it for future use or other vulnerability databases.

## Supported File Formats

The script supports various `requirements.txt` formats:

```requirements
# Exact versions
django==3.2.0
flask==1.1.0

# Minimum versions
requests>=2.25.0
numpy>=1.21.0

# Compatible releases
pandas~=1.3.0

# Range specifications
cryptography>=3.0.0,<4.0.0

# No version specified (will check latest)
setuptools
```

## Sample Output

### Text Report

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│             DEPENDENCY VULNERABILITY ANALYSIS REPORT                          │
└──────────────────────────────────────────────────────────────────────────────┘

📊 SUMMARY
   Total packages: 15
   🔴 Critical vulnerabilities: 2
   🟠 High vulnerabilities: 4
   ⚠️  Packages with vulnerabilities: 6
   📦 Packages needing updates: 9

🎯 QUICK ACTIONS NEEDED
────────────────────────────────────────
🚨 URGENT - Critical/High Risk Packages:
   django               3.2.0           → 3.2.15         (🔴1 Critical, 🟠2 High)
   pillow               8.0.0           → 8.3.2          (🔴1 Critical)

💡 SUGGESTED COMMANDS
────────────────────────────────────────
Fix critical vulnerabilities:
   pip install --upgrade django==3.2.15 pillow==8.3.2
```

### HTML Report

The HTML report provides an enhanced web interface with:

- Color-coded vulnerability severity levels with intuitive icons
- Responsive CSS Grid layout for mobile and desktop
- Interactive package cards with expandable details
- Auto-generated severity summaries and statistics
- Professional styling with modern design patterns
- Automatic browser opening when generated

## Command Line Options

```text
usage: vulnerability_analyzer.py [-h] [--format {text,html}] [--output OUTPUT] [--api-key API_KEY] file_path

positional arguments:
  file_path            Path to the dependency file (e.g., requirements.txt)

optional arguments:
  -h, --help           show this help message and exit
  --format {text,html} Output format for the report (default: text)
  --output OUTPUT      Output file path. For HTML: auto-saved to reports/ directory
  --api-key API_KEY    API key for vulnerability database (can also use VULNERABILITY_API_KEY env var)
```

## Shell Wrapper Options

```text
Usage: ./run_analyzer.sh [OPTIONS] <requirements_file>

Options:
  -h, --help          Show help message
  -f, --format FORMAT Output format (text|html) [default: text]
  -o, --output FILE   Output file path [default: stdout]
  -k, --api-key KEY   API key for vulnerability database
  -s, --sample        Analyze the sample requirements file
```

## Examples

### Example 1: Basic Analysis

```bash
python vulnerability_analyzer.py sample_requirements.txt
```

### Example 2: Generate HTML Report

```bash
./run_analyzer.sh -f html sample_requirements.txt
```

### Example 3: Save Text Report

```bash
python vulnerability_analyzer.py requirements.txt --output security_audit.txt
```

## How It Works

1. **File Parsing**: Reads and parses requirements files using regex patterns to extract package names and versions
2. **Async Vulnerability Scanning**: Concurrently queries the OSV API for each package to check for known vulnerabilities  
3. **Version Checking**: Fetches latest version information from PyPI API in parallel
4. **Smart Caching**: Stores API responses locally with 24-hour expiry to minimize redundant requests
5. **Report Generation**: Creates comprehensive reports with:
   - Current package versions and vulnerability details
   - Risk severity classification with CVSS scoring
   - Specific fixed version recommendations
   - Actionable pip update commands

## API Information

### OSV (Open Source Vulnerability) API

- **Base URL**: <https://api.osv.dev/v1>
- **Rate Limiting**: 0.1 seconds between requests (optimized for performance)
- **No API Key Required**: The OSV API is free and open
- **Documentation**: <https://osv.dev/>

### PyPI API

- **Base URL**: <https://pypi.org/pypi>
- **Purpose**: Fetching latest package version information  
- **No API Key Required**: Public API

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

## Limitations

- Currently supports Python packages (PyPI ecosystem)
- Requires internet connection for API calls
- Rate limited to optimize API usage while maintaining performance
- Some vulnerability data may not include specific fix versions
- Cache expiry is fixed at 24 hours (not configurable)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes following async/await patterns
4. Test manually using `sample_requirements.txt`
5. Submit a pull request

## Cache Management

The tool automatically creates a `.vulnera_cache/` directory for storing API responses:

- **Location**: `.vulnera_cache/` in current working directory
- **Expiry**: 24 hours automatic expiry
- **Format**: JSON files with MD5 hash-based names
- **Cleanup**: Delete the directory to force fresh analysis

## File Structure

- `vulnerability_analyzer.py`: Main async analyzer (880+ lines)
- `run_analyzer.sh`: Enhanced bash wrapper with validation and colored output
- `sample_requirements.txt`: Test file with mix of vulnerable and safe packages
- `reports/`: Auto-generated directory for HTML reports
- `.vulnera_cache/`: Local API response cache (auto-created)
- `requirements.txt`: Project dependencies (`aiohttp` and `tqdm`)

## Troubleshooting

### Common Issues

1. **Network Errors**: Ensure stable internet connection
2. **Rate Limiting**: Built-in rate limiting should prevent issues, but reduce concurrent requests if needed
3. **Invalid Requirements File**: Ensure requirements.txt follows standard pip format
4. **API Timeouts**: 30-second timeout per request with automatic retries
5. **Cache Issues**: Delete `.vulnera_cache/` directory to reset

### Getting Help

If you encounter issues:

1. Check your requirements.txt file format
2. Verify internet connectivity
3. Try running with `sample_requirements.txt` first
4. Check error messages for specific details
5. Delete cache directory if experiencing stale data issues

## Changelog

### v2.0.0 (Current)

- **Breaking**: Migrated to async/await architecture using `aiohttp`
- **Added**: Concurrent package analysis for improved performance
- **Added**: Smart caching system with 24-hour expiry
- **Added**: Enhanced HTML reports with responsive design
- **Added**: Automatic browser opening for HTML reports
- **Added**: Enhanced shell wrapper with colored output
- **Added**: Auto-generated timestamped report filenames
- **Improved**: Rate limiting reduced to 0.1s for better performance
- **Improved**: Error handling with custom exception types
- **Improved**: Text repormd+67-151
ts with emoji indicators and actionable commands

### v1.0.0

- Initial release
- Support for requirements.txt parsing
- OSV API integration
- PyPI version checking
- Text and HTML report generation
- Comprehensive error handling

## License

MIT License - See LICENSE file for details

## Security Considerations

- The tool makes HTTP requests to external APIs (OSV and PyPI)
- No sensitive data is transmitted (only package names and versions)
- API keys (if used) should be kept secure
- Uses async session management for secure connection handling
- Consider running in isolated environments for sensitive projects
- Cache files contain only public vulnerability and version data
