#!/usr/bin/env python3
"""
Web Analyzer Module - Advanced Web Reconnaissance
Core web analysis functionality with security scanning
"""

import requests
from requests.exceptions import (
    RequestException,
    ProxyError,
    ConnectTimeout,
    ReadTimeout,
)
import socket
import ssl
import dns.resolver
from urllib.parse import urlparse
from typing import Dict, Any, List
import datetime
import json
import time
import re

from helpers.utils import Colors, clear_screen


class WebAnalyzer:
    """Core web analysis functionality with comprehensive scanning."""

    def __init__(self, url, timeout=10, proxies=None, proxy_manager=None):
        """Initialize web analyzer."""
        self.url = self._normalize_url(url)
        self.hostname = self._extract_hostname(url)
        self.timeout = timeout
        self.proxies = proxies  # Dict with 'http' and 'https' keys (legacy)
        self.proxy_manager = proxy_manager
        self.data = None
        self.start_time = None

    def _current_proxy(self):
        """Return current proxy dict from manager or provided static proxies."""
        if self.proxy_manager and self.proxy_manager.is_loaded():
            return self.proxy_manager.get_proxy()
        return self.proxies

    def _rotate_proxy(self):
        """Advance to next proxy if manager is present."""
        if self.proxy_manager and self.proxy_manager.is_loaded():
            return self.proxy_manager.get_next_proxy()
        return None

    def _mark_failed_proxy(self, proxy_dict):
        if self.proxy_manager:
            self.proxy_manager.mark_failed(proxy_dict)

    def _request_with_rotation(self, method: str, url: str, **kwargs):
        """Perform a requests call with fast proxy rotation on failures.

        Tries available proxies quickly until one succeeds. If all proxies fail,
        attempts a direct connection once before raising the error.

        Fast timeouts are used when a proxy is in use (min(self.timeout, 5)).
        """
        # Base kwargs
        allow_redirects = kwargs.pop("allow_redirects", True)
        verify = kwargs.pop("verify", True)
        timeout = kwargs.pop("timeout", None)
        # Use quicker timeout when using proxy to avoid long stalls
        proxy_timeout = min(self.timeout, 5)

        last_error = None

        proxies_available = (
            self.proxy_manager.is_loaded() if self.proxy_manager else False
        )
        attempts = 0
        max_attempts = (
            self.proxy_manager.get_count() if proxies_available else 1
        ) * 2 or 1

        # Try proxies first (if available)
        if proxies_available:
            # Start with current proxy and rotate on failure
            for _ in range(max_attempts):
                attempts += 1
                proxy_dict = self._current_proxy()
                try:
                    resp = requests.request(
                        method,
                        url,
                        timeout=proxy_timeout,
                        allow_redirects=allow_redirects,
                        verify=verify,
                        proxies=proxy_dict,
                    )
                    resp.raise_for_status()
                    # Annotate response with proxy used
                    try:
                        resp._used_proxy = (
                            proxy_dict.get("http")
                            if isinstance(proxy_dict, dict)
                            else proxy_dict
                        )
                    except Exception:
                        resp._used_proxy = None
                    return resp
                except (ProxyError, ConnectTimeout, ReadTimeout) as e:
                    # Mark and rotate on proxy-specific or timeout errors
                    self._mark_failed_proxy(proxy_dict)
                    last_error = e
                    self._rotate_proxy()
                    continue
                except RequestException as e:
                    # Other request errors (e.g., 4xx/5xx) still rotate proxies
                    self._mark_failed_proxy(proxy_dict)
                    last_error = e
                    self._rotate_proxy()
                    continue

        # Fallback: try direct connection once
        try:
            resp = requests.request(
                method,
                url,
                timeout=timeout or self.timeout,
                allow_redirects=allow_redirects,
                verify=verify,
                proxies=None,
            )
            resp.raise_for_status()
            # Direct connection (no proxy)
            resp._used_proxy = None
            return resp
        except RequestException as e:
            last_error = e

        raise Exception(f"Error fetching {url}: {last_error}")

    def _normalize_url(self, url: str) -> str:
        """Normalize URL to ensure it has a proper protocol."""
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            return f"https://{url}"
        return url

    def _extract_hostname(self, url: str) -> str:
        """Extract hostname from URL for DNS/IP/SSL operations."""
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        parsed = urlparse(url)
        hostname = parsed.netloc if parsed.netloc else parsed.path.split("/")[0]
        hostname = hostname.split(":")[0]
        return hostname

    def fetch(self):
        """Perform HTTP GET request with proxy rotation if configured."""
        self.start_time = time.time()
        self.data = self._request_with_rotation("GET", self.url)
        return self.data

    def quick_scan(self):
        """Quick scan - basic HTTP info only."""
        if self.data is None:
            self.fetch()

        return {
            "url": self.data.url,
            "hostname": self.hostname,
            "status_code": self.data.status_code,
            "ok": self.data.ok,
            "reason": self.data.reason,
            "elapsed_seconds": self.data.elapsed.total_seconds(),
            "encoding": self.data.encoding,
            "content_length": len(self.data.content),
            "server": self.data.headers.get("Server", "Not disclosed"),
            "is_https": self.url.startswith("https://"),
        }

    def get_dns_info(self):
        """Get DNS resolution information."""
        dns_info = {}
        try:
            hostname = self.hostname

            # A records (IPv4)
            try:
                a_records = dns.resolver.resolve(hostname, "A")
                dns_info["a_records"] = [str(record) for record in a_records]
            except Exception:
                dns_info["a_records"] = "No A records found"

            # AAAA records (IPv6)
            try:
                aaaa_records = dns.resolver.resolve(hostname, "AAAA")
                dns_info["aaaa_records"] = [str(record) for record in aaaa_records]
            except Exception:
                dns_info["aaaa_records"] = "No AAAA records found"

            # MX records (mail servers)
            try:
                mx_records = dns.resolver.resolve(hostname, "MX")
                dns_info["mx_records"] = [str(record) for record in mx_records]
            except Exception:
                dns_info["mx_records"] = "No MX records found"

            # TXT records
            try:
                txt_records = dns.resolver.resolve(hostname, "TXT")
                dns_info["txt_records"] = [str(record) for record in txt_records]
            except Exception:
                dns_info["txt_records"] = "No TXT records found"

            # NS records (nameservers)
            try:
                ns_records = dns.resolver.resolve(hostname, "NS")
                dns_info["ns_records"] = [str(record) for record in ns_records]
            except Exception:
                dns_info["ns_records"] = "No NS records found"

        except Exception as e:
            dns_info["error"] = str(e)

        return dns_info

    def get_ip_info(self):
        """Get IP address and geolocation information."""
        ip_info = {}
        try:
            hostname = self.hostname
            ip_address = socket.gethostbyname(hostname)
            ip_info["ip_address"] = ip_address

            # Reverse DNS
            try:
                reverse_hostname = socket.gethostbyaddr(ip_address)[0]
                ip_info["reverse_dns"] = reverse_hostname
            except Exception:
                ip_info["reverse_dns"] = "Not available"

            # Geolocation
            try:
                response = self._request_with_rotation(
                    "GET",
                    f"http://ip-api.com/json/{ip_address}",
                    timeout=5,
                )
                if response.status_code == 200:
                    geo_data = response.json()
                    ip_info["geolocation"] = {
                        "country": geo_data.get("country"),
                        "region": geo_data.get("regionName"),
                        "city": geo_data.get("city"),
                        "isp": geo_data.get("isp"),
                        "org": geo_data.get("org"),
                    }
            except Exception:
                ip_info["geolocation"] = "Geolocation lookup failed"

        except Exception as e:
            ip_info["error"] = str(e)

        return ip_info

    def get_ssl_info(self):
        """Get SSL/TLS certificate information with validation."""
        ssl_info = {}
        try:
            hostname = self.hostname
            context = ssl.create_default_context()

            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cert_binary = ssock.getpeercert(binary_form=True)

                    # Extract certificate details
                    ssl_info["certificate"] = {
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "version": cert.get("version"),
                        "serialNumber": cert.get("serialNumber"),
                        "notBefore": cert.get("notBefore"),
                        "notAfter": cert.get("notAfter"),
                    }

                    # Check SANs (Subject Alternative Names)
                    sans = []
                    for san_type, san_value in cert.get("subjectAltName", []):
                        if san_type == "DNS":
                            sans.append(san_value)
                    ssl_info["subject_alternative_names"] = sans if sans else []

                    # Check certificate expiration
                    not_after = cert.get("notAfter")
                    if not_after:
                        expire_date = datetime.datetime.strptime(
                            not_after, "%b %d %H:%M:%S %Y %Z"
                        )
                        days_until_expiry = (expire_date - datetime.datetime.now()).days
                        ssl_info["days_until_expiry"] = days_until_expiry
                        ssl_info["expiry_date"] = expire_date.isoformat()

                        # Certificate validity status
                        if days_until_expiry < 0:
                            ssl_info["cert_valid"] = False
                            ssl_info["cert_status"] = "EXPIRED"
                        elif days_until_expiry < 30:
                            ssl_info["cert_valid"] = True
                            ssl_info["cert_status"] = "EXPIRING_SOON"
                        else:
                            ssl_info["cert_valid"] = True
                            ssl_info["cert_status"] = "VALID"

                    # TLS version and cipher
                    ssl_info["tls_version"] = ssock.version()
                    ssl_info["cipher"] = (
                        ssock.cipher()[0] if ssock.cipher() else "Unknown"
                    )

        except socket.timeout:
            ssl_info["error"] = "Connection timeout on port 443"
        except Exception as e:
            ssl_info["error"] = str(e)

        return ssl_info

    def analyze_headers(self):
        """Analyze security headers with recommendations."""
        if self.data is None:
            self.fetch()

        headers = dict(self.data.headers)
        analysis = {}

        security_headers = {
            "Content-Security-Policy": "Prevents XSS attacks by controlling resource loading",
            "Strict-Transport-Security": "Enforces HTTPS connections",
            "X-Frame-Options": "Prevents clickjacking attacks",
            "X-Content-Type-Options": "Prevents MIME type sniffing",
            "X-XSS-Protection": "Legacy XSS protection header",
            "Referrer-Policy": "Controls referrer information",
            "Permissions-Policy": "Controls browser features and APIs",
            "X-Permitted-Cross-Domain-Policies": "Controls cross-domain policies",
        }

        vulnerabilities = []

        for header, description in security_headers.items():
            if header in headers:
                analysis[header] = {
                    "present": True,
                    "value": headers[header],
                    "description": description,
                }
            else:
                analysis[header] = {
                    "present": False,
                    "value": None,
                    "description": description,
                }
                vulnerabilities.append(f"Missing {header}")

        analysis["vulnerabilities"] = vulnerabilities
        return analysis

    def scan_http_methods(self) -> Dict[str, Any]:
        """Scan for allowed HTTP methods and potential vulnerabilities."""
        methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "PATCH"]
        allowed_methods = []
        vulnerable_methods = []

        try:
            for method in methods:
                try:
                    response = self._request_with_rotation(
                        method,
                        self.url,
                        timeout=self.timeout,
                    )
                    allowed_methods.append(method)

                    # Check for dangerous methods
                    if method in ["PUT", "DELETE", "TRACE"]:
                        vulnerable_methods.append(
                            {
                                "method": method,
                                "risk": "HIGH",
                                "description": f"{method} method is enabled - potential security risk",
                            }
                        )
                except Exception:
                    continue

            return {
                "allowed_methods": allowed_methods,
                "vulnerable_methods": vulnerable_methods,
                "method_count": len(allowed_methods),
            }
        except Exception as e:
            return {"error": str(e)}

    def analyze_content(self) -> Dict[str, Any]:
        """Extract content information including emails, meta tags, and links."""
        if self.data is None:
            self.fetch()

        content_analysis = {}
        text = self.data.text

        # Extract email addresses
        email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        emails = list(set(re.findall(email_pattern, text)))
        content_analysis["emails"] = emails

        # Extract phone numbers (basic US format)
        phone_pattern = r"\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}"
        phones = list(set(re.findall(phone_pattern, text)))
        content_analysis["phone_numbers"] = phones

        # Extract meta tags
        meta_pattern = r'<meta[^>]*name=["\'](.*?)["\'][^>]*content=["\'](.*?)["\']'
        meta_tags = re.findall(meta_pattern, text, re.IGNORECASE)
        content_analysis["meta_tags"] = {tag[0]: tag[1] for tag in meta_tags}

        # Extract title
        title_pattern = r"<title[^>]*>([^<]*)</title>"
        title = re.search(title_pattern, text, re.IGNORECASE)
        content_analysis["page_title"] = title.group(1) if title else "No title found"

        # Check for common paths
        sensitive_paths = [
            "/admin",
            "/admin/",
            "/wp-admin",
            "/login",
            "/api",
            "/.env",
            "/.git",
            "/config",
        ]
        found_paths = [path for path in sensitive_paths if path in text]
        content_analysis["sensitive_paths"] = found_paths

        # Word count
        content_analysis["word_count"] = len(text.split())

        return content_analysis

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get detailed performance metrics."""
        if self.data is None:
            self.fetch()

        metrics = {
            "response_time_ms": round(self.data.elapsed.total_seconds() * 1000, 2),
            "content_size_bytes": len(self.data.content),
            "content_size_kb": round(len(self.data.content) / 1024, 2),
            "headers_count": len(self.data.headers),
            "gzip_enabled": "gzip"
            in self.data.headers.get("Content-Encoding", "").lower(),
            "cache_control": self.data.headers.get("Cache-Control", "Not set"),
            "compression": self.data.headers.get("Content-Encoding", "None"),
        }

        # Determine performance rating
        if metrics["response_time_ms"] < 500:
            metrics["performance_rating"] = "EXCELLENT"
        elif metrics["response_time_ms"] < 1000:
            metrics["performance_rating"] = "GOOD"
        elif metrics["response_time_ms"] < 3000:
            metrics["performance_rating"] = "ACCEPTABLE"
        else:
            metrics["performance_rating"] = "SLOW"

        return metrics

    def scan_ports(self):
        """Scan common ports."""
        common_ports = [
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            143,
            443,
            465,
            587,
            993,
            995,
            3306,
            3389,
            5432,
            5984,
            6379,
            8080,
            8443,
            9200,
        ]
        open_ports = []

        try:
            hostname = self.hostname
            ip_address = socket.gethostbyname(hostname)

            for port in common_ports:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(1)
                        result = sock.connect_ex((ip_address, port))
                        if result == 0:
                            open_ports.append(
                                {
                                    "port": port,
                                    "service": self._get_service_name(port),
                                    "status": "open",
                                }
                            )
                except Exception:
                    continue

        except Exception as e:
            open_ports.append({"error": str(e)})

        return open_ports

    def _get_service_name(self, port):
        """Get common service name for a port."""
        service_map = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            465: "SMTPS",
            587: "SMTP",
            993: "IMAPS",
            995: "POP3S",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5984: "CouchDB",
            6379: "Redis",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            9200: "Elasticsearch",
        }
        return service_map.get(port, "Unknown")

    def detect_technologies(self):
        """Detect web technologies and frameworks."""
        if self.data is None:
            self.fetch()

        technologies = {}
        text = self.data.text.lower()
        headers = {k.lower(): v.lower() for k, v in self.data.headers.items()}

        # CMS Detection
        cms_signatures = {
            "wordpress": ["wordpress", "/wp-content/", "/wp-includes/", "wp-json"],
            "drupal": ["drupal", "/sites/default/", "drupal.org"],
            "joomla": ["joomla", "/components/com_", "/modules/mod_"],
            "magento": ["/media/js/", "/skin/frontend/", "magento"],
            "shopify": ["cdn.shopify.com", "myshopify.com"],
            "wix": ["wix.com", "editorx"],
        }

        for cms, signatures in cms_signatures.items():
            if any(sig in text for sig in signatures):
                technologies["cms"] = cms.title()
                break

        # JavaScript Libraries & Frameworks
        js_libs = {
            "jquery": ["jquery", "/jquery.min.js"],
            "react": ["react", "/react.js", "facebook/react"],
            "vue": ["vue.js", "/vue.min.js"],
            "angular": ["angular", "/angular.min.js"],
            "bootstrap": ["bootstrap.min.js", "/bootstrap/"],
            "axios": ["axios", "/axios.min.js"],
            "d3.js": ["d3.js", "/d3.min.js"],
            "three.js": ["three.js", "threejs"],
        }

        detected_js = []
        for lib, signatures in js_libs.items():
            if any(sig in text for sig in signatures):
                detected_js.append(lib)

        if detected_js:
            technologies["javascript_libraries"] = detected_js

        # CSS Frameworks
        css_frameworks = {
            "bootstrap": ["bootstrap.min.css", "/bootstrap/", "getbootstrap.com"],
            "tailwind": ["tailwindcss", "/tailwind.css"],
            "materialize": ["materialize.css", "materializecss.com"],
            "bulma": ["bulma.css", "bulmaio.com"],
        }

        detected_css = []
        for fw, signatures in css_frameworks.items():
            if any(sig in text for sig in signatures):
                detected_css.append(fw)

        if detected_css:
            technologies["css_frameworks"] = detected_css

        # Backend Detection
        backend = {}

        # Web Server
        server = headers.get("server", "")
        if "apache" in server:
            backend["web_server"] = "Apache"
        elif "nginx" in server:
            backend["web_server"] = "Nginx"
        elif "iis" in server or "microsoft" in server:
            backend["web_server"] = "Microsoft IIS"
        elif "cloudflare" in server:
            backend["web_server"] = "Cloudflare"

        # Backend language detection
        if "x-powered-by" in headers:
            backend["powered_by"] = headers["x-powered-by"]

        if "php" in server or "php" in text[:2000]:
            backend["language"] = "PHP"
        elif any(sig in text for sig in ["nodejs", "express", "next.js"]):
            backend["language"] = "Node.js"
        elif "python" in server or "django" in text or "flask" in text:
            backend["language"] = "Python"
        elif "java" in server or "tomcat" in server:
            backend["language"] = "Java"

        if backend:
            technologies["backend"] = backend

        # Analytics & Tracking
        analytics = []
        if "google-analytics" in text or "gtag" in text:
            analytics.append("Google Analytics")
        if "mixpanel" in text:
            analytics.append("Mixpanel")
        if "segment.com" in text:
            analytics.append("Segment")
        if "hotjar" in text:
            analytics.append("Hotjar")
        if "intercom" in text:
            analytics.append("Intercom")

        if analytics:
            technologies["analytics"] = analytics

        return technologies

    def full_recon_scan(self):
        """Comprehensive reconnaissance scan with all analysis."""
        if self.data is None:
            self.fetch()

        report = {
            "scan_info": {
                "url": self.data.url,
                "requested_url": self.url,
                "hostname": self.hostname,
                "scan_timestamp": datetime.datetime.now().isoformat(),
                "proxy_used": getattr(self.data, "_used_proxy", None) or "DIRECT",
                "proxy_mode": (
                    "PROXY" if getattr(self.data, "_used_proxy", None) else "DIRECT"
                ),
            },
            "http_info": {
                "status_code": self.data.status_code,
                "reason": self.data.reason,
                "is_ok": self.data.ok,
                "encoding": self.data.encoding,
                "apparent_encoding": self.data.apparent_encoding,
            },
            "headers": dict(self.data.headers),
            "cookies": self.data.cookies.get_dict(),
            "redirects": [resp.url for resp in self.data.history],
            "performance": self.get_performance_metrics(),
            "content_analysis": self.analyze_content(),
            "dns_info": self.get_dns_info(),
            "ip_info": self.get_ip_info(),
            "ssl_info": self.get_ssl_info(),
            "http_methods": self.scan_http_methods(),
            "security_headers": self.analyze_headers(),
            "open_ports": self.scan_ports(),
            "technologies": self.detect_technologies(),
        }
        return report


class WebAnalyzerModule:
    """Module interface for web analysis - handles all presentation."""

    def __init__(self):
        self.name = "Web Analyzer"
        self.version = "2.0.0"
        self.proxy_manager = None

    def run(self, config, target_manager, proxy_manager=None):
        """Run the web analyzer module with its own menu."""
        self.proxy_manager = proxy_manager
        while True:
            clear_screen()
            self._print_module_banner()
            self._print_module_status(config, target_manager)
            self._print_module_menu()

            choice = input(f"{Colors.OKCYAN}Select option: {Colors.ENDC}").strip()

            if choice == "1":
                self._quick_scan(config, target_manager)
            elif choice == "2":
                self._dns_recon(config, target_manager)
            elif choice == "3":
                self._ip_info(config, target_manager)
            elif choice == "4":
                self._ssl_analysis(config, target_manager)
            elif choice == "5":
                self._headers_analysis(config, target_manager)
            elif choice == "6":
                self._http_methods(config, target_manager)
            elif choice == "7":
                self._content_analysis(config, target_manager)
            elif choice == "8":
                self._performance_metrics(config, target_manager)
            elif choice == "9":
                self._port_scan(config, target_manager)
            elif choice == "10":
                self._tech_detection(config, target_manager)
            elif choice == "11":
                self._full_recon(config, target_manager)
            elif choice == "12":
                self._batch_scan(config, target_manager)
            elif choice.upper() == "B" or choice == "0":
                break
            else:
                print(f"{Colors.FAIL}[✗] Invalid option{Colors.ENDC}")
                time.sleep(1)

    def _print_module_banner(self):
        """Print the module banner."""
        banner = f"""
{Colors.HEADER}
═══════════════════════════════════════════════════════════════
                   WEB ANALYZER MODULE v2.0
                 Advanced Web Reconnaissance
══════════════════════════════════════════════════════════════{Colors.ENDC}
        """
        print(banner)

    def _print_module_status(self, config, target_manager):
        """Print module status."""
        current = target_manager.get_current_target()
        target_list = target_manager.get_target_list()

        if current:
            target_display = f"Single: {current[:35]}..."
        elif target_list:
            target_display = f"Batch: {len(target_list)} targets"
        else:
            target_display = "No target loaded"

        # Proxy status
        proxy_count = self.proxy_manager.get_count() if self.proxy_manager else 0
        proxy_display = (
            f"{proxy_count} proxies" if proxy_count > 0 else "Direct connection"
        )

        status = f"""{Colors.OKCYAN}Module Status:{Colors.ENDC}
┌─────────────────────────────────────────────────────────────┐
│ Current Target:   {target_display: <45}
│ Proxy Mode:       {proxy_display: <45}
│ Timeout:          {config['timeout']} seconds{' ' * 36}
└─────────────────────────────────────────────────────────────┘"""
        print(status)

    def _get_proxy(self):
        """Get proxy dict for requests."""
        if self.proxy_manager and self.proxy_manager.is_loaded():
            return self.proxy_manager.get_random_proxy()
        return None

    def _print_module_menu(self):
        """Print the module menu."""
        menu = f"""
{Colors.OKBLUE}Scan Options:{Colors.ENDC}
┌─────────────────────────────────────────────────────────────┐
│  1. Quick Scan (Basic HTTP Info)                            │
│  2. DNS Reconnaissance                                      │
│  3. IP & Geolocation Info                                   │
│  4. SSL/TLS Certificate Analysis                            │
│  5. Security Headers Analysis                               │
│  6. HTTP Methods Scan (TRACE, PUT, DELETE)                  │
│  7. Content Analysis (Emails, Meta, Links)                  │
│  8. Performance Metrics (Speed, Compression)                │
│  9. Port Scanning                                           │
│ 10. Technology Detection                                    │
│ 11. Full Reconnaissance Scan (All Checks)                   │
│ 12. Batch Scan from Loaded Targets                          │
│                                                             │
│  B. Back to Main Menu                                       │
└─────────────────────────────────────────────────────────────┘
        """
        print(menu)

    def _get_target(self, target_manager):
        """Get target for scanning."""
        current = target_manager.get_current_target()
        target_list = target_manager.get_target_list()

        if current:
            return current
        elif target_list:
            print(
                f"{Colors.WARNING}[!] You have {len(target_list)} targets loaded from file.{Colors.ENDC}"
            )
            print(
                f"{Colors.WARNING}[!] Use 'Batch Scan' (option 12) to scan all targets.{Colors.ENDC}"
            )

            choice = (
                input(
                    f"{Colors.OKCYAN}Enter target number to scan (or 'N' for new): {Colors.ENDC}"
                )
                .strip()
                .upper()
            )

            if choice == "N":
                target = input(
                    f"{Colors.OKCYAN}Enter target URL or hostname: {Colors.ENDC}"
                ).strip()
                return target
            elif choice.isdigit():
                idx = int(choice) - 1
                targets = target_list
                if 0 <= idx < len(targets):
                    return targets[idx]
                else:
                    print(f"{Colors.FAIL}[✗] Invalid target number{Colors.ENDC}")
                    time.sleep(1)
                    return None
            else:
                return None
        else:
            print(
                f"{Colors.WARNING}[!] No target loaded. Please load a target first.{Colors.ENDC}"
            )
            choice = input(
                f"{Colors.OKCYAN}Enter a target now? (Y/n): {Colors.ENDC}"
            ).strip()
            if choice.lower() != "n":
                target = input(
                    f"{Colors.OKCYAN}Enter target URL or hostname: {Colors.ENDC}"
                ).strip()
                if target:
                    target_manager.load_single_target(target)
                return target
            return None

    def _quick_scan(self, config, target_manager):
        """Execute and display quick scan."""
        print(f"\n{Colors.HEADER}═══ Quick Scan ═══{Colors.ENDC}")
        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return

        print(f"{Colors.WARNING}[*] Scanning {target}...{Colors.ENDC}")
        try:
            analyzer = WebAnalyzer(
                target,
                timeout=config["timeout"],
                proxies=self._get_proxy(),
                proxy_manager=self.proxy_manager,
            )
            result = analyzer.quick_scan()
            print(f"\n{Colors.OKGREEN}[✓] Scan Complete!{Colors.ENDC}\n")
            print(f"{Colors.OKCYAN}URL:{Colors.ENDC} {result['url']}")
            print(
                f"{Colors.OKCYAN}Status:{Colors.ENDC} {result['status_code']} {result['reason']}"
            )
            print(
                f"{Colors.OKCYAN}Response Time:{Colors.ENDC} {result['elapsed_seconds']:.3f}s"
            )
            print(
                f"{Colors.OKCYAN}Content Length:{Colors.ENDC} {result['content_length']} bytes"
            )
            print(f"{Colors.OKCYAN}Server:{Colors.ENDC} {result['server']}")
            print(
                f"{Colors.OKCYAN}HTTPS:{Colors.ENDC} {'Yes' if result['is_https'] else 'No'}"
            )
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error: {str(e)}{Colors.ENDC}")
        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _dns_recon(self, config, target_manager):
        """Execute DNS reconnaissance."""
        print(f"\n{Colors.HEADER}═══ DNS Reconnaissance ═══{Colors.ENDC}")
        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return
        print(f"{Colors.WARNING}[*] DNS lookup for {target}...{Colors.ENDC}")
        try:
            analyzer = WebAnalyzer(
                target,
                timeout=config["timeout"],
                proxies=self._get_proxy(),
                proxy_manager=self.proxy_manager,
            )
            result = analyzer.get_dns_info()
            print(f"\n{Colors.OKGREEN}[✓] DNS Lookup Complete!{Colors.ENDC}\n")
            print(json.dumps(result, indent=2))
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error: {str(e)}{Colors.ENDC}")
        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _ip_info(self, config, target_manager):
        """Execute IP info lookup."""
        print(f"\n{Colors.HEADER}═══ IP & Geolocation ═══{Colors.ENDC}")
        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return
        print(f"{Colors.WARNING}[*] Resolving IP for {target}...{Colors.ENDC}")
        try:
            analyzer = WebAnalyzer(
                target,
                timeout=config["timeout"],
                proxies=self._get_proxy(),
                proxy_manager=self.proxy_manager,
            )
            result = analyzer.get_ip_info()
            print(f"\n{Colors.OKGREEN}[✓] IP Lookup Complete!{Colors.ENDC}\n")
            print(json.dumps(result, indent=2))
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error: {str(e)}{Colors.ENDC}")
        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _ssl_analysis(self, config, target_manager):
        """Execute SSL certificate analysis."""
        print(f"\n{Colors.HEADER}═══ SSL/TLS Analysis ═══{Colors.ENDC}")
        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return
        print(f"{Colors.WARNING}[*] Analyzing SSL for {target}...{Colors.ENDC}")
        try:
            analyzer = WebAnalyzer(
                target,
                timeout=config["timeout"],
                proxies=self._get_proxy(),
                proxy_manager=self.proxy_manager,
            )
            result = analyzer.get_ssl_info()
            print(f"\n{Colors.OKGREEN}[✓] SSL Analysis Complete!{Colors.ENDC}\n")
            print(json.dumps(result, indent=2))
            if "days_until_expiry" in result:
                days = result["days_until_expiry"]
                if days < 0:
                    print(
                        f"\n{Colors.FAIL}[!] CRITICAL: Certificate EXPIRED!{Colors.ENDC}"
                    )
                elif days < 30:
                    print(
                        f"\n{Colors.FAIL}[!] WARNING: Expires in {days} days!{Colors.ENDC}"
                    )
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error: {str(e)}{Colors.ENDC}")
        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _headers_analysis(self, config, target_manager):
        """Execute security headers analysis."""
        print(f"\n{Colors.HEADER}═══ Security Headers ═══{Colors.ENDC}")
        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return
        print(f"{Colors.WARNING}[*] Analyzing headers for {target}...{Colors.ENDC}")
        try:
            analyzer = WebAnalyzer(
                target,
                timeout=config["timeout"],
                proxies=self._get_proxy(),
                proxy_manager=self.proxy_manager,
            )
            result = analyzer.analyze_headers()
            print(f"\n{Colors.OKGREEN}[✓] Headers Analysis Complete!{Colors.ENDC}\n")
            vulns = result.pop("vulnerabilities", [])
            for header, info in result.items():
                status = (
                    f"{Colors.OKGREEN}✓ Present"
                    if info["present"]
                    else f"{Colors.FAIL}✗ Missing"
                )
                print(f"{Colors.OKCYAN}{header}:{Colors.ENDC} {status}{Colors.ENDC}")
            if vulns:
                print(f"\n{Colors.FAIL}Vulnerabilities:{Colors.ENDC}")
                for v in vulns:
                    print(f"  {Colors.FAIL}• {v}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error: {str(e)}{Colors.ENDC}")
        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _http_methods(self, config, target_manager):
        """Execute HTTP methods scan."""
        print(f"\n{Colors.HEADER}═══ HTTP Methods Scan ═══{Colors.ENDC}")
        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return
        print(f"{Colors.WARNING}[*] Scanning HTTP methods for {target}...{Colors.ENDC}")
        try:
            analyzer = WebAnalyzer(
                target,
                timeout=config["timeout"],
                proxies=self._get_proxy(),
                proxy_manager=self.proxy_manager,
            )
            result = analyzer.scan_http_methods()
            print(f"\n{Colors.OKGREEN}[✓] Scan Complete!{Colors.ENDC}\n")
            print(
                f"{Colors.OKCYAN}Allowed Methods: {', '.join(result['allowed_methods'])}{Colors.ENDC}"
            )
            if result["vulnerable_methods"]:
                print(f"\n{Colors.FAIL}Vulnerable Methods:{Colors.ENDC}")
                for v in result["vulnerable_methods"]:
                    print(
                        f"  {Colors.FAIL}• {v['method']} - {v['description']}{Colors.ENDC}"
                    )
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error: {str(e)}{Colors.ENDC}")
        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _content_analysis(self, config, target_manager):
        """Execute content analysis."""
        print(f"\n{Colors.HEADER}═══ Content Analysis ═══{Colors.ENDC}")
        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return
        print(f"{Colors.WARNING}[*] Analyzing content for {target}...{Colors.ENDC}")
        try:
            analyzer = WebAnalyzer(
                target,
                timeout=config["timeout"],
                proxies=self._get_proxy(),
                proxy_manager=self.proxy_manager,
            )
            result = analyzer.analyze_content()
            print(f"\n{Colors.OKGREEN}[✓] Analysis Complete!{Colors.ENDC}\n")
            print(f"{Colors.OKCYAN}Title:{Colors.ENDC} {result['page_title']}")
            print(f"{Colors.OKCYAN}Words:{Colors.ENDC} {result['word_count']}")
            if result["emails"]:
                print(
                    f"\n{Colors.OKCYAN}Emails Found ({len(result['emails'])}):{Colors.ENDC}"
                )
                for e in result["emails"][:5]:
                    print(f"  • {e}")
            if result["sensitive_paths"]:
                print(f"\n{Colors.FAIL}Sensitive Paths:{Colors.ENDC}")
                for p in result["sensitive_paths"]:
                    print(f"  {Colors.FAIL}• {p}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error: {str(e)}{Colors.ENDC}")
        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _performance_metrics(self, config, target_manager):
        """Execute performance analysis."""
        print(f"\n{Colors.HEADER}═══ Performance Metrics ═══{Colors.ENDC}")
        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return
        print(f"{Colors.WARNING}[*] Analyzing performance for {target}...{Colors.ENDC}")
        try:
            analyzer = WebAnalyzer(
                target,
                timeout=config["timeout"],
                proxies=self._get_proxy(),
                proxy_manager=self.proxy_manager,
            )
            result = analyzer.get_performance_metrics()
            print(f"\n{Colors.OKGREEN}[✓] Analysis Complete!{Colors.ENDC}\n")
            rating_color = {
                "EXCELLENT": Colors.OKGREEN,
                "GOOD": Colors.OKGREEN,
                "ACCEPTABLE": Colors.WARNING,
                "SLOW": Colors.FAIL,
            }.get(result["performance_rating"], Colors.OKCYAN)
            print(
                f"{Colors.OKCYAN}Rating:{Colors.ENDC} {rating_color}{result['performance_rating']}{Colors.ENDC}"
            )
            print(
                f"{Colors.OKCYAN}Response Time:{Colors.ENDC} {result['response_time_ms']} ms"
            )
            print(
                f"{Colors.OKCYAN}Content Size:{Colors.ENDC} {result['content_size_kb']} KB"
            )
            print(
                f"{Colors.OKCYAN}Gzip:{Colors.ENDC} {'Yes' if result['gzip_enabled'] else 'No'}"
            )
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error: {str(e)}{Colors.ENDC}")
        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _port_scan(self, config, target_manager):
        """Execute port scan."""
        print(f"\n{Colors.HEADER}═══ Port Scan ═══{Colors.ENDC}")
        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return
        print(f"{Colors.WARNING}[*] Scanning ports for {target}...{Colors.ENDC}")
        try:
            analyzer = WebAnalyzer(
                target,
                timeout=config["timeout"],
                proxies=self._get_proxy(),
                proxy_manager=self.proxy_manager,
            )
            result = analyzer.scan_ports()
            print(f"\n{Colors.OKGREEN}[✓] Scan Complete!{Colors.ENDC}\n")
            if result:
                print(f"{Colors.OKCYAN}Open Ports ({len(result)}):{Colors.ENDC}")
                for p in result:
                    print(
                        f"  {Colors.OKGREEN}[OPEN]{Colors.ENDC} {p['port']} - {p['service']}"
                    )
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error: {str(e)}{Colors.ENDC}")
        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _tech_detection(self, config, target_manager):
        """Execute technology detection."""
        print(f"\n{Colors.HEADER}═══ Technology Detection ═══{Colors.ENDC}")
        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return
        print(
            f"{Colors.WARNING}[*] Detecting technologies for {target}...{Colors.ENDC}"
        )
        try:
            analyzer = WebAnalyzer(
                target,
                timeout=config["timeout"],
                proxies=self._get_proxy(),
                proxy_manager=self.proxy_manager,
            )
            result = analyzer.detect_technologies()
            print(f"\n{Colors.OKGREEN}[✓] Detection Complete!{Colors.ENDC}\n")
            if result:
                for k, v in result.items():
                    print(f"{Colors.OKCYAN}{k.title()}:{Colors.ENDC} {v}")
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error: {str(e)}{Colors.ENDC}")
        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _full_recon(self, config, target_manager):
        """Execute full reconnaissance scan."""
        print(f"\n{Colors.HEADER}═══ Full Recon Scan ═══{Colors.ENDC}")
        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return
        print(f"{Colors.WARNING}[*] Full scan for {target}...{Colors.ENDC}")
        try:
            analyzer = WebAnalyzer(
                target, timeout=config["timeout"], proxies=self._get_proxy()
            )
            for i, step in enumerate(
                [
                    "Fetching HTTP",
                    "DNS",
                    "IP",
                    "SSL",
                    "Headers",
                    "Methods",
                    "Ports",
                    "Tech",
                ],
                1,
            ):
                print(f"[*] Step {i}/8: {step}...")
                time.sleep(0.2)
            result = analyzer.full_recon_scan()
            print(f"\n{Colors.OKGREEN}[✓] Scan Complete!{Colors.ENDC}")
            self._save_results(result, config["output_file"])
            print(
                f"{Colors.OKCYAN}Status: {result['http_info']['status_code']} {result['http_info']['reason']}{Colors.ENDC}"
            )
            print(
                f"{Colors.OKCYAN}IP: {result['ip_info'].get('ip_address', 'N/A')}{Colors.ENDC}"
            )
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error: {str(e)}{Colors.ENDC}")
        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _batch_scan(self, config, target_manager):
        """Execute batch scan."""
        print(f"\n{Colors.HEADER}═══ Batch Scan ═══{Colors.ENDC}")
        targets = target_manager.get_target_list()
        if not targets:
            print(f"{Colors.WARNING}[!] No targets loaded{Colors.ENDC}")
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return

        confirm = input(
            f"{Colors.OKCYAN}Scan {len(targets)} targets? (Y/n): {Colors.ENDC}"
        ).strip()
        if confirm.lower() == "n":
            return

        try:
            results = []
            for i, target in enumerate(targets, 1):
                print(f"[{i}/{len(targets)}] {target}...")
                try:
                    analyzer = WebAnalyzer(
                        target,
                        timeout=config["timeout"],
                        proxies=self._get_proxy(),
                        proxy_manager=self.proxy_manager,
                    )
                    result = analyzer.full_recon_scan()
                    results.append(result)
                    print(f"{Colors.OKGREEN}[✓]{Colors.ENDC}")
                except Exception as e:
                    print(f"{Colors.FAIL}[✗]{Colors.ENDC}")
                    results.append({"url": target, "error": str(e)})
                time.sleep(0.5)

            batch_file = (
                f"batch_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
            with open(batch_file, "w") as f:
                json.dump(results, f, indent=2)
            print(f"\n{Colors.OKGREEN}[✓] Saved to: {batch_file}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error: {str(e)}{Colors.ENDC}")
        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _save_results(self, data, output_file):
        """Save results to JSON."""
        try:
            try:
                with open(output_file, "r") as f:
                    existing = json.load(f)
            except:
                existing = []

            if not isinstance(existing, list):
                existing = [existing]
            existing.append(data)

            with open(output_file, "w") as f:
                json.dump(existing, f, indent=2)
            print(f"{Colors.OKGREEN}[✓] Saved to {output_file}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Save error: {str(e)}{Colors.ENDC}")
