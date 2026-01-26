
## 📝 Changelog

### Version 1.6.0 (Current)

- **Vulnerability Scanner v1.0.0**: New comprehensive security assessment module
  - ✨ New: OWASP Top 10 2021 complete coverage
  - ✨ New: CVE detection for Apache, PHP, jQuery, WordPress, OpenSSL
  - ✨ New: Reflected XSS vulnerability testing
  - ✨ New: SQL injection error-based detection
  - ✨ New: Path traversal/LFI testing
  - ✨ New: Open redirect vulnerability detection
  - ✨ New: SSL/TLS version and cipher analysis
  - ✨ New: Security header analysis with recommendations
  - ✨ New: CORS misconfiguration detection
  - ✨ New: Sensitive file exposure scanning
  - ✨ New: Severity-based findings with OWASP mapping
  - ✨ New: Batch scanning support

- **Results Manager**: Enhanced results handling
  - ✨ New: View and clear scan results from CLI
  - ✨ New: Generate HTML security reports
  - ✨ New: Host reports via Flask server
  - ✨ New: Reports grouped by target (no duplicates)

### Version 1.5.0

- **Proxy Support**: HTTP/HTTPS proxy integration across all modules
  - ✨ New: Load proxies from text file (one per line)
  - ✨ New: Support for multiple formats (ip:port, http://, https://, user:pass@)
  - ✨ New: Random proxy rotation for all HTTP requests
  - ✨ New: Proxy status display in main menu and module status
  - ✨ New: ProxyManager class with load, rotate, and clear functions
  - 🔧 Updated: All modules (Web Analyzer, Path Finder, Subdomain) use proxies

### Version 1.4.0

- **Sensitive Path Finder v1.0.0**: New module for path discovery
  - ✨ New: Admin/Login path scanning (40+ paths)
  - ✨ New: CMS-specific paths (WordPress, Joomla, Drupal, Magento, Laravel)
  - ✨ New: API endpoint discovery (REST, GraphQL, Swagger, OpenAPI)
  - ✨ New: Sensitive file detection (.env, .git, backups, configs, logs)
  - ✨ New: Multi-threaded scanning (10 concurrent threads)
  - ✨ New: Custom wordlist support
  - ✨ New: Batch scanning with path category selection

- **Subdomain Enumeration v1.0.0**: New module for subdomain discovery
  - ✨ New: DNS bruteforce with 150+ common subdomains
  - ✨ New: Extended wordlist with 250+ subdomains for deep scans
  - ✨ New: Certificate Transparency lookup via crt.sh
  - ✨ New: Zone Transfer (AXFR) vulnerability testing
  - ✨ New: Reverse DNS scanning on /24 network range
  - ✨ New: Full enumeration combining all methods
  - ✨ New: Custom wordlist support
  - ✨ New: Batch enumeration across multiple domains

### Version 1.3.0

- **Web Analyzer v2.0.0**: Major expansion with 12 scan types
  - ✨ New: HTTP Methods vulnerability scanning (TRACE, PUT, DELETE detection)
  - ✨ New: Content analysis (emails, meta tags, sensitive paths)
  - ✨ New: Performance metrics (response time, compression, caching analysis)
  - ✨ New: Enhanced SSL analysis with certificate warnings and expiry tracking
  - ✨ New: Security headers with vulnerability recommendations
  - ✨ New: IPv6 DNS records support (AAAA records)
  - ✨ New: Expanded port scanning (21 ports including PostgreSQL, Redis, Elasticsearch)
  - 🔧 Refactored: Structured JSON output with logical sections
  - 🐛 Fixed: All spacing and formatting issues
  - 📈 Improved: Better error handling and user feedback

### Version 1.2.5

- Modular Architecture: Complete refactor to plugin system
- Dynamic Module Loading: Automatic menu generation
- Module Template: Easy module creation
- Improved Structure: Better code organization
- Bug Fixes: Banner spacing and error handling

### Version 1.2.0

- Rebranded to CobraScan
- Target Manager: Single and batch scanning
- Configuration System: Persistent settings
- Enhanced UI: Improved user interface

### Version 1.0.0

- Initial Release
- Basic Scanning: Core functionality
- JSON Export: Structured output

[View full changelog](CHANGELOG.md)
