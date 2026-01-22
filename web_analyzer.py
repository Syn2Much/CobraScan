#!/usr/bin/env python3
"""
Web Analyzer Module
Core web analysis functionality for reconnaissance
"""

import requests
import socket
import ssl
import dns. resolver
from urllib.parse import urlparse
from typing import Dict, Any
import datetime


class WebAnalyzer:
    """Core web analysis functionality."""
    
    def __init__(self, url, timeout=10):
        """Initialize web analyzer."""
        self.url = self._normalize_url(url)
        self.hostname = self._extract_hostname(url)
        self.timeout = timeout
        self.data = None

    def _normalize_url(self, url: str) -> str:
        """Normalize URL to ensure it has a proper protocol."""
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            return f'https://{url}'
        return url

    def _extract_hostname(self, url: str) -> str:
        """Extract hostname from URL for DNS/IP/SSL operations."""
        if not url. startswith(('http://', 'https://')):
            url = f'http://{url}'
        parsed = urlparse(url)
        hostname = parsed.netloc if parsed.netloc else parsed.path. split('/')[0]
        hostname = hostname.split(':')[0]
        return hostname

    def fetch(self):
        """Perform HTTP GET request."""
        try:
            self.data = requests.get(self.url, timeout=self.timeout, allow_redirects=True)
            self.data.raise_for_status()
            return self.data
        except requests.RequestException as e:
            raise Exception(f"Error fetching {self.url}: {e}")

    def quick_scan(self):
        """Quick scan - basic HTTP info only."""
        if self.data is None:
            self.fetch()
        
        return {
            "url": self.data.url,
            "hostname":  self.hostname,
            "status_code": self.data.status_code,
            "ok": self.data.ok,
            "reason": self.data.reason,
            "elapsed_seconds": self.data.elapsed.total_seconds(),
            "encoding": self.data.encoding,
            "content_length": len(self.data.content),
            "server": self.data.headers.get('Server', 'Not disclosed')
        }

    def get_dns_info(self):
        """Get DNS resolution information."""
        dns_info = {}
        try:
            hostname = self.hostname
            
            # A records (IPv4)
            try:
                a_records = dns.resolver.resolve(hostname, 'A')
                dns_info["a_records"] = [str(record) for record in a_records]
            except:
                dns_info["a_records"] = "No A records found"
            
            # MX records (mail servers)
            try:
                mx_records = dns.resolver.resolve(hostname, 'MX')
                dns_info["mx_records"] = [str(record) for record in mx_records]
            except:
                dns_info["mx_records"] = "No MX records found"
                
            # TXT records
            try:
                txt_records = dns.resolver.resolve(hostname, 'TXT')
                dns_info["txt_records"] = [str(record) for record in txt_records]
            except:
                dns_info["txt_records"] = "No TXT records found"
                
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
            except:
                ip_info["reverse_dns"] = "Not available"
                
            # Geolocation
            try: 
                response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
                if response.status_code == 200:
                    geo_data = response.json()
                    ip_info["geolocation"] = {
                        "country": geo_data.get("country"),
                        "region": geo_data.get("regionName"),
                        "city":  geo_data.get("city"),
                        "isp": geo_data.get("isp"),
                        "org": geo_data.get("org"),
                    }
            except:
                ip_info["geolocation"] = "Geolocation lookup failed"
                
        except Exception as e:
            ip_info["error"] = str(e)
            
        return ip_info

    def get_ssl_info(self):
        """Get SSL/TLS certificate information."""
        ssl_info = {}
        try: 
            hostname = self.hostname
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info["certificate"] = {
                        "issuer": dict(x[0] for x in cert. get('issuer', [])),
                        "subject": dict(x[0] for x in cert. get('subject', [])),
                        "version": cert.get('version'),
                        "serialNumber": cert.get('serialNumber'),
                        "notBefore": cert.get('notBefore'),
                        "notAfter": cert.get('notAfter'),
                    }
                    
                    # Check certificate expiration
                    not_after = cert.get('notAfter')
                    if not_after: 
                        expire_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (expire_date - datetime.datetime.now()).days
                        ssl_info["days_until_expiry"] = days_until_expiry
                        
                    # TLS version
                    ssl_info["tls_version"] = ssock.version()
                    
        except Exception as e:
            ssl_info["error"] = str(e)
            
        return ssl_info

    def analyze_headers(self):
        """Analyze security headers."""
        if self.data is None:
            self.fetch()
            
        headers = dict(self.data.headers)
        analysis = {}
        
        security_headers = [
            'Content-Security-Policy',
            'Strict-Transport-Security',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Referrer-Policy',
        ]
        
        for header in security_headers:
            if header in headers:
                analysis[header] = {"present": True, "value": headers[header]}
            else:
                analysis[header] = {"present": False, "value": None}
                
        return analysis

    def scan_ports(self):
        """Scan common ports."""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 8080, 8443]
        open_ports = []
        
        try:
            hostname = self.hostname
            ip_address = socket.gethostbyname(hostname)
            
            for port in common_ports: 
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(1)
                        result = sock. connect_ex((ip_address, port))
                        if result == 0:
                            open_ports.append({
                                "port": port,
                                "service": self._get_service_name(port),
                                "status": "open"
                            })
                except:
                    continue
                    
        except Exception as e:
            open_ports. append({"error": str(e)})
            
        return open_ports

    def _get_service_name(self, port):
        """Get common service name for a port."""
        service_map = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 465: 'SMTPS', 587: 'SMTP',
            993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL',
            3389: 'RDP', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
        }
        return service_map.get(port, 'Unknown')

    def detect_technologies(self):
        """Detect web technologies."""
        if self.data is None:
            self.fetch()
            
        technologies = {}
        text = self.data.text. lower()
        headers = dict(self.data.headers)
        
        # CMS Detection
        if 'wordpress' in text or '/wp-content/' in text:
            technologies['cms'] = 'WordPress'
        elif 'drupal' in text: 
            technologies['cms'] = 'Drupal'
        elif 'joomla' in text:
            technologies['cms'] = 'Joomla'
        
        # JavaScript Libraries
        if 'jquery' in text: 
            technologies['javascript'] = 'jQuery'
        if 'react' in text: 
            technologies['framework'] = 'React'
        if 'vue' in text: 
            technologies['framework'] = 'Vue. js'
        if 'angular' in text: 
            technologies['framework'] = 'Angular'
        
        # CSS Frameworks
        if 'bootstrap' in text:
            technologies['css_framework'] = 'Bootstrap'
        if 'tailwind' in text:
            technologies['css_framework'] = 'Tailwind CSS'
        
        # Web Server
        server = headers.get('Server', '').lower()
        if 'apache' in server:
            technologies['web_server'] = 'Apache'
        elif 'nginx' in server:
            technologies['web_server'] = 'nginx'
        elif 'iis' in server: 
            technologies['web_server'] = 'Microsoft IIS'
        elif 'cloudflare' in server:
            technologies['web_server'] = 'Cloudflare'
        
        # Analytics
        if 'google-analytics. com' in text or 'gtag' in text:
            technologies['analytics'] = 'Google Analytics'
            
        return technologies

    def full_recon_scan(self):
        """Comprehensive reconnaissance scan."""
        if self.data is None:
            self.fetch()

        report = {
            "url": self.data.url,
            "requested_url": self.url,
            "hostname": self. hostname,
            "status_code": self.data.status_code,
            "ok":  self.data.ok,
            "reason": self.data.reason,
            "elapsed_seconds":  self.data.elapsed.total_seconds(),
            "encoding": self.data.encoding,
            "apparent_encoding": self.data.apparent_encoding,
            "headers": dict(self.data.headers),
            "cookies": self.data.cookies. get_dict(),
            "history": [resp.url for resp in self.data.history],
            "content_length": len(self.data.content),
            "dns_info": self.get_dns_info(),
            "ip_info": self.get_ip_info(),
            "ssl_info": self.get_ssl_info(),
            "headers_analysis": self.analyze_headers(),
            "open_ports": self.scan_ports(),
            "technologies": self. detect_technologies(),
            "scan_timestamp": datetime.datetime.now().isoformat()
        }
        return report
