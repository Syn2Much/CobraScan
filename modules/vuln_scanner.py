#!/usr/bin/env python3
"""
Vulnerability Scanner Module - CVE Detection & OWASP Top 10 Checks
Comprehensive security vulnerability assessment for web applications
"""

import time
import json
import datetime
import re
import socket
import ssl
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse, urljoin, quote, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.exceptions import RequestException, Timeout

from helpers.utils import Colors, clear_screen
from helpers.http_client import request_with_rotation


class VulnerabilityScanner:
    """Core vulnerability scanning functionality."""

    # OWASP Top 10 2021 Categories
    OWASP_CATEGORIES = {
        "A01": "Broken Access Control",
        "A02": "Cryptographic Failures",
        "A03": "Injection",
        "A04": "Insecure Design",
        "A05": "Security Misconfiguration",
        "A06": "Vulnerable Components",
        "A07": "Auth Failures",
        "A08": "Data Integrity Failures",
        "A09": "Logging Failures",
        "A10": "SSRF",
    }

    # XSS Test Payloads
    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        '"><script>alert(1)</script>',
        "'-alert(1)-'",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "{{7*7}}",  # Template injection
        "${7*7}",  # Template injection
    ]

    # SQL Injection Test Payloads
    SQLI_PAYLOADS = [
        "'",
        "''",
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "1' ORDER BY 1--",
        "1' ORDER BY 10--",
        "1 UNION SELECT NULL--",
        "1' AND '1'='1",
        "1' AND SLEEP(5)--",
        "1'; WAITFOR DELAY '0:0:5'--",
    ]

    # Command Injection Payloads
    CMDI_PAYLOADS = [
        "; ls",
        "| ls",
        "& ls",
        "`ls`",
        "$(ls)",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "; ping -c 3 127.0.0.1",
        "| ping -c 3 127.0.0.1",
    ]

    # Path Traversal Payloads
    LFI_PAYLOADS = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc/passwd",
        "/etc/passwd",
        "file:///etc/passwd",
    ]

    # Open Redirect Test Paths
    REDIRECT_PAYLOADS = [
        "//evil.com",
        "https://evil.com",
        "/\\evil.com",
        "//evil.com/%2f..",
    ]

    # Known vulnerable software signatures
    VULNERABLE_SIGNATURES = {
        # Apache versions with known CVEs
        "Apache/2.4.49": {
            "cve": "CVE-2021-41773",
            "severity": "CRITICAL",
            "desc": "Path Traversal & RCE",
        },
        "Apache/2.4.50": {
            "cve": "CVE-2021-42013",
            "severity": "CRITICAL",
            "desc": "Path Traversal & RCE",
        },
        "Apache/2.2": {
            "cve": "CVE-2017-3167",
            "severity": "HIGH",
            "desc": "Multiple vulnerabilities - EOL",
        },
        # Nginx
        "nginx/1.16": {
            "cve": "CVE-2019-20372",
            "severity": "MEDIUM",
            "desc": "HTTP Request Smuggling",
        },
        # PHP versions
        "PHP/5.": {
            "cve": "Multiple",
            "severity": "HIGH",
            "desc": "PHP 5.x EOL - Multiple CVEs",
        },
        "PHP/7.0": {"cve": "Multiple", "severity": "HIGH", "desc": "PHP 7.0 EOL"},
        "PHP/7.1": {"cve": "Multiple", "severity": "HIGH", "desc": "PHP 7.1 EOL"},
        "PHP/7.2": {"cve": "Multiple", "severity": "MEDIUM", "desc": "PHP 7.2 EOL"},
        # OpenSSL
        "OpenSSL/1.0": {
            "cve": "CVE-2016-2107",
            "severity": "HIGH",
            "desc": "Padding Oracle Attack",
        },
        "OpenSSL/0.9": {
            "cve": "CVE-2014-0160",
            "severity": "CRITICAL",
            "desc": "Heartbleed",
        },
        # jQuery
        "jquery/1.": {
            "cve": "CVE-2020-11022",
            "severity": "MEDIUM",
            "desc": "XSS vulnerability",
        },
        "jquery/2.": {
            "cve": "CVE-2020-11022",
            "severity": "MEDIUM",
            "desc": "XSS vulnerability",
        },
        "jquery-3.4": {
            "cve": "CVE-2020-11022",
            "severity": "MEDIUM",
            "desc": "XSS in htmlPrefilter",
        },
        # WordPress
        "WordPress 4.": {
            "cve": "Multiple",
            "severity": "HIGH",
            "desc": "WordPress 4.x - Multiple CVEs",
        },
        "WordPress 5.0": {
            "cve": "CVE-2019-8942",
            "severity": "HIGH",
            "desc": "RCE via Media",
        },
        # Drupal
        "Drupal 7": {
            "cve": "CVE-2018-7600",
            "severity": "CRITICAL",
            "desc": "Drupalgeddon2 RCE",
        },
        "Drupal 8.5": {
            "cve": "CVE-2018-7602",
            "severity": "CRITICAL",
            "desc": "Drupalgeddon3 RCE",
        },
    }

    # Security Headers to Check
    SECURITY_HEADERS = {
        "Content-Security-Policy": {
            "missing_severity": "HIGH",
            "desc": "Prevents XSS and data injection attacks",
        },
        "X-Frame-Options": {
            "missing_severity": "MEDIUM",
            "desc": "Prevents clickjacking attacks",
        },
        "X-Content-Type-Options": {
            "missing_severity": "LOW",
            "desc": "Prevents MIME type sniffing",
        },
        "Strict-Transport-Security": {
            "missing_severity": "HIGH",
            "desc": "Enforces HTTPS connections",
        },
        "X-XSS-Protection": {
            "missing_severity": "LOW",
            "desc": "Legacy XSS filter (deprecated but useful)",
        },
        "Referrer-Policy": {
            "missing_severity": "LOW",
            "desc": "Controls referrer information leakage",
        },
        "Permissions-Policy": {
            "missing_severity": "LOW",
            "desc": "Controls browser feature access",
        },
    }

    def __init__(self, url: str, timeout: int = 10, proxy_manager=None):
        self.url = self._normalize_url(url)
        self.hostname = self._extract_hostname(url)
        self.timeout = timeout
        self.proxy_manager = proxy_manager
        self.findings: List[Dict[str, Any]] = []

    def _normalize_url(self, url: str) -> str:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            return f"https://{url}"
        return url

    def _extract_hostname(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        return urlparse(url).netloc

    def _request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Make HTTP request with proxy rotation support."""
        try:
            timeout = kwargs.pop("timeout", self.timeout)
            if self.proxy_manager and self.proxy_manager.is_loaded():
                return request_with_rotation(
                    method, url, self.proxy_manager, timeout=timeout, **kwargs
                )
            return requests.request(method, url, timeout=timeout, **kwargs)
        except Exception:
            return None

    def _add_finding(
        self,
        category: str,
        title: str,
        severity: str,
        description: str,
        evidence: str = "",
        cve: str = "",
        owasp: str = "",
        remediation: str = "",
    ):
        """Add a vulnerability finding."""
        self.findings.append(
            {
                "category": category,
                "title": title,
                "severity": severity,
                "description": description,
                "evidence": evidence[:500] if evidence else "",
                "cve": cve,
                "owasp": owasp,
                "remediation": remediation,
                "timestamp": datetime.datetime.now().isoformat(),
            }
        )

    # ==================== SCAN METHODS ====================

    def scan_security_headers(self) -> Dict[str, Any]:
        """Check for missing security headers (OWASP A05)."""
        results = {"headers_checked": 0, "missing": [], "present": [], "issues": []}

        try:
            resp = self._request("GET", self.url)
            if not resp:
                return results

            headers = {k.lower(): v for k, v in resp.headers.items()}

            for header, info in self.SECURITY_HEADERS.items():
                results["headers_checked"] += 1
                header_lower = header.lower()

                if header_lower in headers:
                    results["present"].append(
                        {
                            "header": header,
                            "value": headers[header_lower][:100],
                        }
                    )
                else:
                    results["missing"].append(
                        {
                            "header": header,
                            "severity": info["missing_severity"],
                            "description": info["desc"],
                        }
                    )
                    self._add_finding(
                        category="Security Headers",
                        title=f"Missing {header}",
                        severity=info["missing_severity"],
                        description=info["desc"],
                        owasp="A05",
                        remediation=f"Add {header} header to HTTP responses",
                    )

            # Check for information disclosure headers
            disclosure_headers = [
                "Server",
                "X-Powered-By",
                "X-AspNet-Version",
                "X-AspNetMvc-Version",
            ]
            for h in disclosure_headers:
                if h.lower() in headers:
                    results["issues"].append(
                        {
                            "header": h,
                            "value": headers[h.lower()],
                            "issue": "Information Disclosure",
                        }
                    )
                    self._add_finding(
                        category="Information Disclosure",
                        title=f"{h} Header Exposes Server Info",
                        severity="LOW",
                        description=f"The {h} header reveals server technology information",
                        evidence=f"{h}: {headers[h.lower()]}",
                        owasp="A05",
                        remediation=f"Remove or obfuscate the {h} header",
                    )

        except Exception as e:
            results["error"] = str(e)

        return results

    def scan_version_disclosure(self) -> Dict[str, Any]:
        """Detect vulnerable software versions (OWASP A06)."""
        results = {"versions_found": [], "vulnerabilities": []}

        try:
            resp = self._request("GET", self.url)
            if not resp:
                return results

            # Check headers
            headers_to_check = ["Server", "X-Powered-By", "X-Generator"]
            for header in headers_to_check:
                if header in resp.headers:
                    version_str = resp.headers[header]
                    results["versions_found"].append(
                        {
                            "source": f"Header: {header}",
                            "value": version_str,
                        }
                    )

                    # Check against known vulnerabilities
                    for pattern, vuln_info in self.VULNERABLE_SIGNATURES.items():
                        if pattern.lower() in version_str.lower():
                            results["vulnerabilities"].append(
                                {
                                    "component": version_str,
                                    "cve": vuln_info["cve"],
                                    "severity": vuln_info["severity"],
                                    "description": vuln_info["desc"],
                                }
                            )
                            self._add_finding(
                                category="Vulnerable Component",
                                title=f"Vulnerable {pattern} Detected",
                                severity=vuln_info["severity"],
                                description=vuln_info["desc"],
                                evidence=f"{header}: {version_str}",
                                cve=vuln_info["cve"],
                                owasp="A06",
                                remediation="Update to the latest patched version",
                            )

            # Check page content for version strings
            content = resp.text[:50000]  # Limit content check

            # jQuery version detection
            jquery_match = re.search(r"jquery[/-]?(\d+\.\d+\.?\d*)", content, re.I)
            if jquery_match:
                version = jquery_match.group(1)
                results["versions_found"].append(
                    {
                        "source": "JavaScript",
                        "value": f"jQuery {version}",
                    }
                )
                if version.startswith(("1.", "2.", "3.0", "3.1", "3.2", "3.3", "3.4")):
                    results["vulnerabilities"].append(
                        {
                            "component": f"jQuery {version}",
                            "cve": "CVE-2020-11022/CVE-2020-11023",
                            "severity": "MEDIUM",
                            "description": "XSS vulnerability in jQuery",
                        }
                    )
                    self._add_finding(
                        category="Vulnerable Component",
                        title=f"Vulnerable jQuery {version}",
                        severity="MEDIUM",
                        description="jQuery versions < 3.5.0 have XSS vulnerabilities",
                        evidence=f"jQuery version: {version}",
                        cve="CVE-2020-11022",
                        owasp="A06",
                        remediation="Update jQuery to version 3.5.0 or later",
                    )

            # WordPress version
            wp_match = re.search(r"WordPress\s+(\d+\.\d+\.?\d*)", content, re.I)
            if wp_match:
                results["versions_found"].append(
                    {
                        "source": "CMS",
                        "value": f"WordPress {wp_match.group(1)}",
                    }
                )

            # Generator meta tag
            gen_match = re.search(
                r'<meta[^>]+generator[^>]+content=["\']([^"\']+)', content, re.I
            )
            if gen_match:
                results["versions_found"].append(
                    {
                        "source": "Meta Generator",
                        "value": gen_match.group(1),
                    }
                )

        except Exception as e:
            results["error"] = str(e)

        return results

    def scan_xss_reflected(self, params: List[str] = None) -> Dict[str, Any]:
        """Test for reflected XSS vulnerabilities (OWASP A03)."""
        results = {"tests_run": 0, "vulnerable_params": [], "safe_params": []}

        # If no params provided, try to find them
        if not params:
            params = [
                "q",
                "search",
                "query",
                "s",
                "keyword",
                "id",
                "name",
                "page",
                "url",
                "redirect",
                "next",
                "return",
            ]

        for param in params:
            for payload in self.XSS_PAYLOADS[:5]:  # Limit payloads for speed
                results["tests_run"] += 1
                test_url = f"{self.url}?{param}={quote(payload)}"

                try:
                    resp = self._request("GET", test_url, allow_redirects=False)
                    if resp and payload in resp.text:
                        results["vulnerable_params"].append(
                            {
                                "parameter": param,
                                "payload": payload,
                                "reflected": True,
                            }
                        )
                        self._add_finding(
                            category="Cross-Site Scripting",
                            title=f"Reflected XSS in '{param}' parameter",
                            severity="HIGH",
                            description="User input is reflected in the response without proper encoding",
                            evidence=f"Parameter: {param}, Payload: {payload}",
                            owasp="A03",
                            remediation="Implement proper input validation and output encoding",
                        )
                        break  # Found vuln, move to next param
                except Exception:
                    continue

        return results

    def scan_sql_injection(self, params: List[str] = None) -> Dict[str, Any]:
        """Test for SQL injection vulnerabilities (OWASP A03)."""
        results = {"tests_run": 0, "potential_vulns": [], "errors_found": []}

        sql_error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"MySqlException",
            r"valid MySQL result",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_",
            r"ORA-\d{5}",
            r"Oracle.*Driver",
            r"SQLite.*error",
            r"sqlite3\.OperationalError",
            r"Microsoft.*ODBC.*SQL Server",
            r"SQLServer.*Error",
            r"Unclosed quotation mark",
            r"SQLSTATE\[",
            r"syntax error.*SQL",
        ]

        if not params:
            params = [
                "id",
                "page",
                "cat",
                "category",
                "product",
                "item",
                "user",
                "order",
                "sort",
            ]

        for param in params:
            for payload in self.SQLI_PAYLOADS[:5]:
                results["tests_run"] += 1
                test_url = f"{self.url}?{param}={quote(payload)}"

                try:
                    resp = self._request("GET", test_url)
                    if not resp:
                        continue

                    content = resp.text
                    for pattern in sql_error_patterns:
                        if re.search(pattern, content, re.I):
                            results["errors_found"].append(
                                {
                                    "parameter": param,
                                    "payload": payload,
                                    "error_pattern": pattern,
                                }
                            )
                            self._add_finding(
                                category="SQL Injection",
                                title=f"Potential SQLi in '{param}' parameter",
                                severity="CRITICAL",
                                description="SQL error message detected, indicating potential SQL injection",
                                evidence=f"Parameter: {param}, Error pattern: {pattern}",
                                owasp="A03",
                                remediation="Use parameterized queries/prepared statements",
                            )
                            break
                except Exception:
                    continue

        return results

    def scan_directory_traversal(self) -> Dict[str, Any]:
        """Test for directory traversal/LFI vulnerabilities (OWASP A01)."""
        results = {"tests_run": 0, "vulnerabilities": []}

        # Common parameters that might be vulnerable
        params = [
            "file",
            "path",
            "page",
            "include",
            "template",
            "doc",
            "folder",
            "pg",
            "style",
            "lang",
        ]

        # Indicators of successful traversal
        success_patterns = [
            "root:x:0:0",  # /etc/passwd
            "[extensions]",  # win.ini
            "\\[boot loader\\]",  # boot.ini
        ]

        for param in params:
            for payload in self.LFI_PAYLOADS[:4]:
                results["tests_run"] += 1
                test_url = f"{self.url}?{param}={quote(payload)}"

                try:
                    resp = self._request("GET", test_url)
                    if not resp:
                        continue

                    for pattern in success_patterns:
                        if re.search(pattern, resp.text, re.I):
                            results["vulnerabilities"].append(
                                {
                                    "parameter": param,
                                    "payload": payload,
                                    "evidence": pattern,
                                }
                            )
                            self._add_finding(
                                category="Path Traversal",
                                title=f"LFI/Directory Traversal in '{param}'",
                                severity="CRITICAL",
                                description="Application allows reading arbitrary files from the server",
                                evidence=f"Parameter: {param}, Payload: {payload}",
                                owasp="A01",
                                remediation="Validate and sanitize file paths, use allowlists",
                            )
                            break
                except Exception:
                    continue

        return results

    def scan_open_redirect(self) -> Dict[str, Any]:
        """Test for open redirect vulnerabilities (OWASP A01)."""
        results = {"tests_run": 0, "vulnerabilities": []}

        params = [
            "url",
            "redirect",
            "next",
            "return",
            "returnUrl",
            "goto",
            "destination",
            "redir",
            "redirect_uri",
            "continue",
        ]

        for param in params:
            for payload in self.REDIRECT_PAYLOADS:
                results["tests_run"] += 1
                test_url = f"{self.url}?{param}={quote(payload)}"

                try:
                    resp = self._request("GET", test_url, allow_redirects=False)
                    if not resp:
                        continue

                    # Check for redirect to external domain
                    if resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get("Location", "")
                        if "evil.com" in location or location.startswith("//"):
                            results["vulnerabilities"].append(
                                {
                                    "parameter": param,
                                    "payload": payload,
                                    "redirect_location": location,
                                }
                            )
                            self._add_finding(
                                category="Open Redirect",
                                title=f"Open Redirect via '{param}' parameter",
                                severity="MEDIUM",
                                description="Application redirects to attacker-controlled URLs",
                                evidence=f"Parameter: {param}, Redirects to: {location}",
                                owasp="A01",
                                remediation="Validate redirect URLs against an allowlist",
                            )
                            break
                except Exception:
                    continue

        return results

    def scan_sensitive_files(self) -> Dict[str, Any]:
        """Check for exposed sensitive files (OWASP A05)."""
        results = {"files_checked": 0, "exposed": []}

        sensitive_files = [
            ("/.git/config", "Git repository exposed"),
            ("/.git/HEAD", "Git repository exposed"),
            ("/.svn/entries", "SVN repository exposed"),
            ("/.env", "Environment file exposed"),
            ("/.env.local", "Environment file exposed"),
            ("/.env.production", "Environment file exposed"),
            ("/config.php", "Config file exposed"),
            ("/config.yml", "Config file exposed"),
            ("/config.json", "Config file exposed"),
            ("/wp-config.php.bak", "WordPress config backup"),
            ("/web.config", "ASP.NET config exposed"),
            ("/phpinfo.php", "PHP info page exposed"),
            ("/info.php", "PHP info page exposed"),
            ("/test.php", "Test file exposed"),
            ("/debug.log", "Debug log exposed"),
            ("/error.log", "Error log exposed"),
            ("/access.log", "Access log exposed"),
            ("/.htaccess", "Apache config exposed"),
            ("/.htpasswd", "Password file exposed"),
            ("/server-status", "Apache server status"),
            ("/server-info", "Apache server info"),
            ("/backup.sql", "Database backup exposed"),
            ("/dump.sql", "Database dump exposed"),
            ("/database.sql", "Database file exposed"),
            ("/db.sql", "Database file exposed"),
            ("/.DS_Store", "macOS metadata exposed"),
            ("/Thumbs.db", "Windows metadata exposed"),
            ("/crossdomain.xml", "Flash cross-domain policy"),
            ("/clientaccesspolicy.xml", "Silverlight policy"),
            ("/robots.txt", "Robots file (informational)"),
            ("/sitemap.xml", "Sitemap (informational)"),
            ("/.well-known/security.txt", "Security policy"),
        ]

        base_url = self.url.rstrip("/")

        for path, description in sensitive_files:
            results["files_checked"] += 1
            test_url = f"{base_url}{path}"

            try:
                resp = self._request("GET", test_url)
                if not resp:
                    continue

                if resp.status_code == 200:
                    # Verify it's not a generic error page
                    content_length = len(resp.content)
                    if (
                        content_length > 0 and content_length < 1000000
                    ):  # Skip huge files
                        # Check for actual content indicators
                        content = resp.text[:1000].lower()

                        # Skip if it looks like an error page
                        if (
                            "not found" in content
                            or "404" in content
                            or "error" in content
                        ):
                            continue

                        severity = (
                            "HIGH"
                            if any(
                                x in path
                                for x in [".env", "config", ".git", "password", ".sql"]
                            )
                            else "MEDIUM"
                        )

                        results["exposed"].append(
                            {
                                "path": path,
                                "description": description,
                                "size": content_length,
                                "severity": severity,
                            }
                        )

                        self._add_finding(
                            category="Sensitive File Exposure",
                            title=description,
                            severity=severity,
                            description=f"Sensitive file accessible at {path}",
                            evidence=f"URL: {test_url}, Size: {content_length} bytes",
                            owasp="A05",
                            remediation="Remove or restrict access to sensitive files",
                        )

            except Exception:
                continue

        return results

    def scan_ssl_tls(self) -> Dict[str, Any]:
        """Check SSL/TLS configuration (OWASP A02)."""
        results = {"ssl_enabled": False, "issues": [], "certificate": {}}

        try:
            parsed = urlparse(self.url)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)

            if parsed.scheme != "https":
                self._add_finding(
                    category="Cryptographic Failures",
                    title="HTTPS Not Enabled",
                    severity="HIGH",
                    description="Site does not use HTTPS encryption",
                    owasp="A02",
                    remediation="Enable HTTPS with a valid SSL certificate",
                )
                return results

            results["ssl_enabled"] = True

            # Create SSL context and connect
            context = ssl.create_default_context()

            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    results["certificate"] = {
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "version": version,
                        "cipher": cipher[0] if cipher else None,
                    }

                    # Check TLS version
                    if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                        results["issues"].append(
                            {
                                "issue": f"Weak TLS version: {version}",
                                "severity": "HIGH",
                            }
                        )
                        self._add_finding(
                            category="Cryptographic Failures",
                            title=f"Weak TLS Version ({version})",
                            severity="HIGH",
                            description=f"Server supports deprecated {version}",
                            owasp="A02",
                            remediation="Disable TLS 1.0/1.1, use TLS 1.2 or higher",
                        )

                    # Check cipher strength
                    if cipher:
                        cipher_name = cipher[0].upper()
                        weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT"]
                        for weak in weak_ciphers:
                            if weak in cipher_name:
                                results["issues"].append(
                                    {
                                        "issue": f"Weak cipher: {cipher_name}",
                                        "severity": "HIGH",
                                    }
                                )
                                self._add_finding(
                                    category="Cryptographic Failures",
                                    title=f"Weak Cipher Suite",
                                    severity="HIGH",
                                    description=f"Server uses weak cipher: {cipher_name}",
                                    owasp="A02",
                                    remediation="Configure server to use strong cipher suites",
                                )
                                break

                    # Check certificate expiry
                    not_after = cert.get("notAfter")
                    if not_after:
                        from datetime import datetime

                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days_left = (expiry - datetime.now()).days
                        results["certificate"]["days_until_expiry"] = days_left

                        if days_left < 0:
                            self._add_finding(
                                category="Cryptographic Failures",
                                title="SSL Certificate Expired",
                                severity="CRITICAL",
                                description=f"Certificate expired {abs(days_left)} days ago",
                                owasp="A02",
                                remediation="Renew the SSL certificate immediately",
                            )
                        elif days_left < 30:
                            self._add_finding(
                                category="Cryptographic Failures",
                                title="SSL Certificate Expiring Soon",
                                severity="MEDIUM",
                                description=f"Certificate expires in {days_left} days",
                                owasp="A02",
                                remediation="Renew the SSL certificate before expiry",
                            )

        except ssl.SSLError as e:
            results["issues"].append(
                {"issue": f"SSL Error: {str(e)}", "severity": "HIGH"}
            )
        except Exception as e:
            results["error"] = str(e)

        return results

    def scan_cors_misconfig(self) -> Dict[str, Any]:
        """Check for CORS misconfiguration (OWASP A05)."""
        results = {"cors_enabled": False, "misconfigured": False, "details": {}}

        try:
            # Test with arbitrary origin
            test_origin = "https://evil-attacker.com"
            headers = {"Origin": test_origin}

            resp = self._request("GET", self.url, headers=headers)
            if not resp:
                return results

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao:
                results["cors_enabled"] = True
                results["details"]["allowed_origin"] = acao
                results["details"]["allow_credentials"] = acac

                # Check for wildcard with credentials
                if acao == "*" and acac.lower() == "true":
                    results["misconfigured"] = True
                    self._add_finding(
                        category="CORS Misconfiguration",
                        title="CORS Wildcard with Credentials",
                        severity="HIGH",
                        description="CORS allows any origin with credentials",
                        evidence=f"ACAO: {acao}, ACAC: {acac}",
                        owasp="A05",
                        remediation="Restrict CORS to specific trusted origins",
                    )

                # Check if arbitrary origin is reflected
                elif acao == test_origin:
                    results["misconfigured"] = True
                    self._add_finding(
                        category="CORS Misconfiguration",
                        title="CORS Origin Reflection",
                        severity="MEDIUM" if acac.lower() != "true" else "HIGH",
                        description="CORS reflects arbitrary Origin header",
                        evidence=f"Reflected origin: {acao}",
                        owasp="A05",
                        remediation="Validate Origin against an allowlist",
                    )

        except Exception as e:
            results["error"] = str(e)

        return results

    def run_full_scan(self) -> Dict[str, Any]:
        """Run all vulnerability scans."""
        self.findings = []  # Reset findings

        results = {
            "target": self.url,
            "hostname": self.hostname,
            "scan_timestamp": datetime.datetime.now().isoformat(),
            "scans": {},
            "summary": {},
        }

        print(
            f"\n{Colors.OKCYAN}[*] Starting vulnerability scan on {self.url}{Colors.ENDC}\n"
        )

        # Run all scans
        scans = [
            ("security_headers", "Security Headers", self.scan_security_headers),
            ("version_disclosure", "Version Disclosure", self.scan_version_disclosure),
            ("ssl_tls", "SSL/TLS Configuration", self.scan_ssl_tls),
            ("sensitive_files", "Sensitive Files", self.scan_sensitive_files),
            ("cors", "CORS Configuration", self.scan_cors_misconfig),
            ("xss", "XSS Testing", self.scan_xss_reflected),
            ("sqli", "SQL Injection", self.scan_sql_injection),
            ("lfi", "Directory Traversal", self.scan_directory_traversal),
            ("open_redirect", "Open Redirect", self.scan_open_redirect),
        ]

        for scan_key, scan_name, scan_func in scans:
            print(
                f"  {Colors.OKBLUE}[~] {scan_name}...{Colors.ENDC}", end=" ", flush=True
            )
            try:
                results["scans"][scan_key] = scan_func()
                print(f"{Colors.OKGREEN}✓{Colors.ENDC}")
            except Exception as e:
                results["scans"][scan_key] = {"error": str(e)}
                print(f"{Colors.FAIL}✗{Colors.ENDC}")

        # Generate summary
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for finding in self.findings:
            sev = finding.get("severity", "INFO")
            if sev in severity_counts:
                severity_counts[sev] += 1

        results["findings"] = self.findings
        results["summary"] = {
            "total_findings": len(self.findings),
            "by_severity": severity_counts,
            "critical_high": severity_counts["CRITICAL"] + severity_counts["HIGH"],
        }

        return results


class VulnerabilityScannerModule:
    """Module interface for the vulnerability scanner."""

    def __init__(self):
        self.name = "Vulnerability Scanner"
        self.version = "1.0.0"
        self.description = "CVE detection and OWASP Top 10 security checks"

    def run(self, config, target_manager, proxy_manager=None):
        """Main entry point for the module."""
        self.proxy_manager = proxy_manager

        while True:
            clear_screen()
            self._print_banner()
            self._print_status(config, target_manager)
            self._print_menu()

            choice = input(f"{Colors.OKCYAN}Select option: {Colors.ENDC}").strip()

            if choice == "1":
                self._full_scan(config, target_manager)
            elif choice == "2":
                self._quick_scan(config, target_manager)
            elif choice == "3":
                self._owasp_scan(config, target_manager)
            elif choice == "4":
                self._injection_scan(config, target_manager)
            elif choice == "5":
                self._ssl_headers_scan(config, target_manager)
            elif choice == "6":
                self._batch_scan(config, target_manager)
            elif choice.upper() == "B" or choice == "0":
                break
            else:
                print(f"{Colors.FAIL}[✗] Invalid option{Colors.ENDC}")
                time.sleep(1)

    def _print_banner(self):
        banner = f"""
{Colors.HEADER}═══════════════════════════════════════════════════════════════
               🔓 VULNERABILITY SCANNER v{self.version}
                  CVE Detection & OWASP Top 10
═══════════════════════════════════════════════════════════════{Colors.ENDC}"""
        print(banner)

    def _print_status(self, config, target_manager):
        target_count = target_manager.get_target_count()
        current = target_manager.get_current_target()

        if target_count == 0:
            target_display = f"{Colors.FAIL}No target loaded{Colors.ENDC}"
        elif current:
            target_display = f"{Colors.OKGREEN}{current[:45]}{Colors.ENDC}"
        else:
            target_display = f"{Colors.OKGREEN}{target_count} targets{Colors.ENDC}"

        proxy_count = self.proxy_manager.get_count() if self.proxy_manager else 0
        proxy_display = (
            f"{Colors.OKGREEN}{proxy_count} loaded{Colors.ENDC}"
            if proxy_count
            else f"{Colors.WARNING}None{Colors.ENDC}"
        )

        print(
            f"""
{Colors.OKCYAN}Scanner Status:{Colors.ENDC}
┌─────────────────────────────────────────────────────────────┐
│ Target:     {target_display:<50}│
│ Proxies:    {proxy_display:<50}│
│ Timeout:    {config['timeout']}s{' ' * 48}│
└─────────────────────────────────────────────────────────────┘"""
        )

    def _print_menu(self):
        menu = f"""
{Colors.OKBLUE}Scan Options:{Colors.ENDC}
┌─────────────────────────────────────────────────────────────┐
│ 1. 🔍 Full Vulnerability Scan (All checks)                  │
│ 2. ⚡ Quick Scan (Headers + Versions + Files)               │
│ 3. 📋 OWASP Top 10 Assessment                               │
│ 4. 💉 Injection Testing (XSS, SQLi, LFI)                    │
│ 5. 🔒 SSL/TLS & Headers Check                               │
│ 6. 📦 Batch Scan (All Targets)                              │
│                                                             │
│ B. Back to Main Menu                                        │
└─────────────────────────────────────────────────────────────┘"""
        print(menu)

    def _get_target(self, target_manager):
        """Get target for scanning."""
        current = target_manager.get_current_target()
        if current:
            return current

        targets = target_manager.get_target_list()
        if targets:
            print(
                f"{Colors.WARNING}[!] {len(targets)} targets loaded. Enter number or 'N' for new:{Colors.ENDC}"
            )
            for i, t in enumerate(targets[:10], 1):
                print(f"  {i}. {t}")
            if len(targets) > 10:
                print(f"  ... and {len(targets) - 10} more")

            choice = input(f"{Colors.OKCYAN}Select: {Colors.ENDC}").strip()
            if choice.upper() == "N":
                return input(f"{Colors.OKCYAN}Enter target URL: {Colors.ENDC}").strip()
            elif choice.isdigit():
                idx = int(choice) - 1
                return target_manager.get_target_by_index(idx)
        else:
            target = input(f"{Colors.OKCYAN}Enter target URL: {Colors.ENDC}").strip()
            if target:
                target_manager.load_single_target(target)
            return target
        return None

    def _save_results(self, data, output_file):
        """Save scan results to JSON."""
        try:
            try:
                with open(output_file, "r") as f:
                    existing = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                existing = []

            if not isinstance(existing, list):
                existing = [existing]

            existing.append(data)
            with open(output_file, "w") as f:
                json.dump(existing, f, indent=2)

            print(f"{Colors.OKGREEN}[✓] Results saved to {output_file}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error saving: {str(e)}{Colors.ENDC}")

    def _display_findings(self, results):
        """Display scan findings in a formatted way."""
        findings = results.get("findings", [])
        summary = results.get("summary", {})

        print(f"\n{Colors.HEADER}═══ Scan Results ═══{Colors.ENDC}\n")

        # Summary
        print(f"{Colors.OKCYAN}Summary:{Colors.ENDC}")
        print(f"  Total Findings: {summary.get('total_findings', 0)}")

        by_sev = summary.get("by_severity", {})
        if by_sev.get("CRITICAL"):
            print(f"  {Colors.FAIL}CRITICAL: {by_sev['CRITICAL']}{Colors.ENDC}")
        if by_sev.get("HIGH"):
            print(f"  {Colors.FAIL}HIGH: {by_sev['HIGH']}{Colors.ENDC}")
        if by_sev.get("MEDIUM"):
            print(f"  {Colors.WARNING}MEDIUM: {by_sev['MEDIUM']}{Colors.ENDC}")
        if by_sev.get("LOW"):
            print(f"  {Colors.OKCYAN}LOW: {by_sev['LOW']}{Colors.ENDC}")

        # Group by severity
        if findings:
            print(f"\n{Colors.OKBLUE}Findings:{Colors.ENDC}")
            for finding in sorted(
                findings,
                key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(
                    x.get("severity", "INFO")
                ),
            ):
                sev = finding.get("severity", "INFO")
                if sev == "CRITICAL":
                    color = Colors.FAIL
                elif sev == "HIGH":
                    color = Colors.FAIL
                elif sev == "MEDIUM":
                    color = Colors.WARNING
                else:
                    color = Colors.OKCYAN

                print(f"\n  {color}[{sev}]{Colors.ENDC} {finding['title']}")
                print(f"       Category: {finding.get('category', 'N/A')}")
                if finding.get("owasp"):
                    print(
                        f"       OWASP: {finding['owasp']} - {VulnerabilityScanner.OWASP_CATEGORIES.get(finding['owasp'], '')}"
                    )
                if finding.get("cve"):
                    print(f"       CVE: {finding['cve']}")
                print(f"       {finding.get('description', '')}")

    def _full_scan(self, config, target_manager):
        """Run full vulnerability scan."""
        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return

        scanner = VulnerabilityScanner(target, config["timeout"], self.proxy_manager)
        results = scanner.run_full_scan()
        results["scan_type"] = "full_vuln_scan"

        self._display_findings(results)

        if config.get("auto_save"):
            self._save_results(results, config["output_file"])

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _quick_scan(self, config, target_manager):
        """Run quick scan (headers, versions, sensitive files)."""
        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return

        scanner = VulnerabilityScanner(target, config["timeout"], self.proxy_manager)

        print(f"\n{Colors.OKCYAN}[*] Quick scan on {target}{Colors.ENDC}\n")

        results = {
            "target": target,
            "scan_type": "quick_vuln_scan",
            "scan_timestamp": datetime.datetime.now().isoformat(),
            "scans": {},
        }

        for name, func in [
            ("security_headers", scanner.scan_security_headers),
            ("version_disclosure", scanner.scan_version_disclosure),
            ("sensitive_files", scanner.scan_sensitive_files),
        ]:
            print(f"  {Colors.OKBLUE}[~] {name}...{Colors.ENDC}", end=" ", flush=True)
            results["scans"][name] = func()
            print(f"{Colors.OKGREEN}✓{Colors.ENDC}")

        results["findings"] = scanner.findings
        results["summary"] = {
            "total_findings": len(scanner.findings),
        }

        self._display_findings(results)

        if config.get("auto_save"):
            self._save_results(results, config["output_file"])

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _owasp_scan(self, config, target_manager):
        """Run OWASP Top 10 focused scan."""
        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return

        scanner = VulnerabilityScanner(target, config["timeout"], self.proxy_manager)

        print(f"\n{Colors.OKCYAN}[*] OWASP Top 10 Assessment on {target}{Colors.ENDC}")
        print(
            f"{Colors.OKCYAN}    Testing for common web vulnerabilities...{Colors.ENDC}\n"
        )

        results = scanner.run_full_scan()
        results["scan_type"] = "owasp_assessment"

        # Group findings by OWASP category
        owasp_grouped = {}
        for finding in results.get("findings", []):
            owasp = finding.get("owasp", "N/A")
            if owasp not in owasp_grouped:
                owasp_grouped[owasp] = []
            owasp_grouped[owasp].append(finding)

        print(f"\n{Colors.HEADER}═══ OWASP Top 10 Assessment ═══{Colors.ENDC}\n")

        for owasp_id in [
            "A01",
            "A02",
            "A03",
            "A04",
            "A05",
            "A06",
            "A07",
            "A08",
            "A09",
            "A10",
        ]:
            category_name = VulnerabilityScanner.OWASP_CATEGORIES.get(
                owasp_id, "Unknown"
            )
            findings = owasp_grouped.get(owasp_id, [])

            if findings:
                max_sev = max(
                    ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(
                        f.get("severity", "INFO")
                    )
                    for f in findings
                )
                if max_sev <= 1:
                    status = f"{Colors.FAIL}⚠ VULNERABLE{Colors.ENDC}"
                elif max_sev == 2:
                    status = f"{Colors.WARNING}⚠ ISSUES{Colors.ENDC}"
                else:
                    status = f"{Colors.OKCYAN}ℹ INFO{Colors.ENDC}"
            else:
                status = f"{Colors.OKGREEN}✓ PASS{Colors.ENDC}"

            print(f"  {owasp_id}: {category_name:<30} {status}")
            for f in findings[:3]:  # Show max 3 findings per category
                print(f"       └─ [{f.get('severity', 'INFO')}] {f.get('title', '')}")

        if config.get("auto_save"):
            self._save_results(results, config["output_file"])

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _injection_scan(self, config, target_manager):
        """Run injection-focused scan."""
        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return

        scanner = VulnerabilityScanner(target, config["timeout"], self.proxy_manager)

        print(f"\n{Colors.OKCYAN}[*] Injection testing on {target}{Colors.ENDC}")
        print(f"{Colors.WARNING}    ⚠ This may trigger WAF/IDS alerts{Colors.ENDC}\n")

        results = {
            "target": target,
            "scan_type": "injection_scan",
            "scan_timestamp": datetime.datetime.now().isoformat(),
            "scans": {},
        }

        for name, func in [
            ("xss_reflected", scanner.scan_xss_reflected),
            ("sql_injection", scanner.scan_sql_injection),
            ("directory_traversal", scanner.scan_directory_traversal),
            ("open_redirect", scanner.scan_open_redirect),
        ]:
            print(f"  {Colors.OKBLUE}[~] {name}...{Colors.ENDC}", end=" ", flush=True)
            results["scans"][name] = func()
            print(f"{Colors.OKGREEN}✓{Colors.ENDC}")

        results["findings"] = scanner.findings
        results["summary"] = {"total_findings": len(scanner.findings)}

        self._display_findings(results)

        if config.get("auto_save"):
            self._save_results(results, config["output_file"])

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _ssl_headers_scan(self, config, target_manager):
        """Run SSL/TLS and headers scan."""
        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return

        scanner = VulnerabilityScanner(target, config["timeout"], self.proxy_manager)

        print(
            f"\n{Colors.OKCYAN}[*] SSL/TLS & Headers check on {target}{Colors.ENDC}\n"
        )

        results = {
            "target": target,
            "scan_type": "ssl_headers_scan",
            "scan_timestamp": datetime.datetime.now().isoformat(),
            "scans": {},
        }

        for name, func in [
            ("ssl_tls", scanner.scan_ssl_tls),
            ("security_headers", scanner.scan_security_headers),
            ("cors", scanner.scan_cors_misconfig),
        ]:
            print(f"  {Colors.OKBLUE}[~] {name}...{Colors.ENDC}", end=" ", flush=True)
            results["scans"][name] = func()
            print(f"{Colors.OKGREEN}✓{Colors.ENDC}")

        results["findings"] = scanner.findings
        results["summary"] = {"total_findings": len(scanner.findings)}

        self._display_findings(results)

        if config.get("auto_save"):
            self._save_results(results, config["output_file"])

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _batch_scan(self, config, target_manager):
        """Run scan on all loaded targets."""
        targets = target_manager.get_target_list()
        if not targets:
            print(f"{Colors.WARNING}[!] No targets loaded{Colors.ENDC}")
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return

        print(
            f"\n{Colors.OKCYAN}[*] Batch scanning {len(targets)} targets{Colors.ENDC}\n"
        )

        all_results = []
        for i, target in enumerate(targets, 1):
            print(f"\n{Colors.HEADER}[{i}/{len(targets)}] {target}{Colors.ENDC}")

            scanner = VulnerabilityScanner(
                target, config["timeout"], self.proxy_manager
            )
            results = scanner.run_full_scan()
            results["scan_type"] = "batch_vuln_scan"
            all_results.append(results)

            # Brief summary
            total = results.get("summary", {}).get("total_findings", 0)
            critical = (
                results.get("summary", {}).get("by_severity", {}).get("CRITICAL", 0)
            )
            high = results.get("summary", {}).get("by_severity", {}).get("HIGH", 0)
            print(f"  → {total} findings ({critical} critical, {high} high)")

        if config.get("auto_save"):
            for result in all_results:
                self._save_results(result, config["output_file"])

        print(
            f"\n{Colors.OKGREEN}[✓] Batch scan complete. {len(all_results)} targets scanned.{Colors.ENDC}"
        )
        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
