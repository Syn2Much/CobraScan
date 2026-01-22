#!/usr/bin/env python3
"""
Web Analyzer Module
Core web analysis functionality and presentation
"""

import requests
import socket
import ssl
import dns.resolver
from urllib.parse import urlparse
from typing import Dict, Any
import datetime
import json
import time

from utils import Colors, clear_screen


class WebAnalyzer:
    """Core web analysis functionality."""
    
    def __init__(self, url, timeout=10):
        """Initialize web analyzer."""
        self. url = self._normalize_url(url)
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
            "hostname": self.hostname,
            "status_code": self.data.status_code,
            "ok": self.data.ok,
            "reason": self.data.reason,
            "elapsed_seconds": self.data.elapsed. total_seconds(),
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
                analysis[header] = {"present":  False, "value": None}
                
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
                        sock. settimeout(1)
                        result = sock.connect_ex((ip_address, port))
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
        if self. data is None:
            self. fetch()
            
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


class WebAnalyzerModule:
    """Module interface for web analysis - handles all presentation."""
    
    def __init__(self):
        self.name = "Web Analyzer"
        self. version = "1.0.0"
    
    def run(self, config, target_manager):
        """Run the web analyzer module with its own menu."""
        while True:
            clear_screen()
            self._print_module_banner()
            self._print_module_status(config, target_manager)
            self._print_module_menu()
            
            choice = input(f"{Colors.OKCYAN}Select option: {Colors. ENDC}").strip()
            
            if choice == '1':
                self._quick_scan(config, target_manager)
            elif choice == '2':
                self._dns_recon(config, target_manager)
            elif choice == '3': 
                self._ip_info(config, target_manager)
            elif choice == '4': 
                self._ssl_analysis(config, target_manager)
            elif choice == '5': 
                self._headers_analysis(config, target_manager)
            elif choice == '6':
                self._port_scan(config, target_manager)
            elif choice == '7': 
                self._tech_detection(config, target_manager)
            elif choice == '8':
                self._full_recon(config, target_manager)
            elif choice == '9':
                self._batch_scan(config, target_manager)
            elif choice. upper() == 'B' or choice == '0':
                break
            else: 
                print(f"{Colors. FAIL}[✗] Invalid option{Colors. ENDC}")
                time.sleep(1)
    
    def _print_module_banner(self):
        """Print the module banner."""
        banner = f"""
{Colors.HEADER}
═══════════════════════════════════════════════════════════════
                      WEB ANALYZER MODULE
══════════════════════════════════════════════════════════════{Colors.ENDC}
        """
        print(banner)
    
    def _print_module_status(self, config, target_manager):
        """Print module status."""
        target_display = target_manager.get_status_string()
        
        status = f"""{Colors.OKCYAN}Module Status:{Colors.ENDC}
┌─────────────────────────────────────────────────────────────┐
│ Current Target:     {target_display: <45}
│ Timeout:          {config['timeout']} seconds{' ' * 36}
└─────────────────────────────────────────────────────────────┘"""
        print(status)
    
    def _print_module_menu(self):
        """Print the module menu."""
        menu = f"""
{Colors. OKBLUE}Scan Options:{Colors.ENDC}
┌─────────────────────────────────────────────────────────────┐
│ 1. Quick Scan (Basic HTTP Info)                             │
│ 2. DNS Reconnaissance                                       │
│ 3. IP & Geolocation Info                                    │
│ 4. SSL/TLS Certificate Analysis                             │
│ 5. Security Headers Analysis                                │
│ 6. Port Scanning                                            │
│ 7. Technology Detection                                     │
│ 8. Full Reconnaissance Scan (Save to JSON)                  │
│ 9. Batch Scan from Loaded Targets                           │
│                                                             │
│ B. Back to Main Menu                                        │
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
            print(f"{Colors.WARNING}[!] You have {len(target_list)} targets loaded from file. {Colors.ENDC}")
            print(f"{Colors.WARNING}[!] Use 'Batch Scan' (option 9) to scan all targets.{Colors.ENDC}")
            
            choice = input(f"{Colors. OKCYAN}Enter target number to scan (or 'N' for new): {Colors.ENDC}").strip().upper()
            
            if choice == 'N':
                target = input(f"{Colors.OKCYAN}Enter target URL or hostname: {Colors.ENDC}").strip()
                return target
            elif choice. isdigit():
                idx = int(choice) - 1
                target = target_manager.get_target_by_index(idx)
                if target:
                    return target
                else:
                    print(f"{Colors.FAIL}[✗] Invalid target number{Colors.ENDC}")
                    time.sleep(1)
                    return None
            else:
                return None
        else:
            print(f"{Colors.WARNING}[!] No target loaded.  Please load a target first.{Colors. ENDC}")
            choice = input(f"{Colors. OKCYAN}Enter a target now?  (Y/n): {Colors.ENDC}").strip()
            if choice.lower() != 'n':
                target = input(f"{Colors. OKCYAN}Enter target URL or hostname: {Colors.ENDC}").strip()
                if target:
                    target_manager.load_single_target(target)
                return target
            return None
    
    def _quick_scan(self, config, target_manager):
        """Execute and display quick scan."""
        print(f"\n{Colors.HEADER}═══ Quick Scan ═══{Colors.ENDC}")
        
        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors. ENDC}")
            return
        
        print(f"{Colors. WARNING}[*] Scanning {target}...{Colors.ENDC}")
        
        try:
            analyzer = WebAnalyzer(target, timeout=config['timeout'])
            result = analyzer.quick_scan()
            
            print(f"\n{Colors. OKGREEN}[✓] Scan Complete! {Colors.ENDC}\n")
            print(f"{Colors.OKCYAN}URL:{Colors.ENDC} {result['url']}")
            print(f"{Colors.OKCYAN}Hostname:{Colors.ENDC} {result['hostname']}")
            print(f"{Colors. OKCYAN}Status:{Colors.ENDC} {result['status_code']} {result['reason']}")
            print(f"{Colors. OKCYAN}Response Time:{Colors.ENDC} {result['elapsed_seconds']:. 3f}s")
            print(f"{Colors.OKCYAN}Content Length:{Colors.ENDC} {result['content_length']} bytes")
            print(f"{Colors.OKCYAN}Encoding:{Colors.ENDC} {result['encoding']}")
            print(f"{Colors. OKCYAN}Server:{Colors.ENDC} {result['server']}")
            
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error:  {str(e)}{Colors.ENDC}")
        
        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
    
    def _dns_recon(self, config, target_manager):
        """Execute and display DNS reconnaissance."""
        print(f"\n{Colors.HEADER}═══ DNS Reconnaissance ═══{Colors.ENDC}")
        
        target = self._get_target(target_manager)
        if not target: 
            input(f"\n{Colors.WARNING}Press Enter to continue... {Colors.ENDC}")
            return
        
        print(f"{Colors.WARNING}[*] Performing DNS lookup for {target}... {Colors.ENDC}")
        
        try:
            analyzer = WebAnalyzer(target, timeout=config['timeout'])
            result = analyzer.get_dns_info()
            
            print(f"\n{Colors.OKGREEN}[✓] DNS Lookup Complete!{Colors.ENDC}\n")
            print(json.dumps(result, indent=2))
            
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error: {str(e)}{Colors.ENDC}")
        
        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
    
    def _ip_info(self, config, target_manager):
        """Execute and display IP & geolocation info."""
        print(f"\n{Colors.HEADER}═══ IP & Geolocation Info ═══{Colors.ENDC}")
        
        target = self._get_target(target_manager)
        if not target: 
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return
        
        print(f"{Colors.WARNING}[*] Resolving IP and geolocation for {target}... {Colors.ENDC}")
        
        try:
            analyzer = WebAnalyzer(target, timeout=config['timeout'])
            result = analyzer.get_ip_info()
            
            print(f"\n{Colors.OKGREEN}[✓] IP Lookup Complete!{Colors.ENDC}\n")
            print(json.dumps(result, indent=2))
            
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error: {str(e)}{Colors.ENDC}")
        
        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
    
    def _ssl_analysis(self, config, target_manager):
        """Execute and display SSL/TLS analysis."""
        print(f"\n{Colors.HEADER}═══ SSL/TLS Certificate Analysis ═══{Colors. ENDC}")
        
        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return
        
        print(f"{Colors.WARNING}[*] Analyzing SSL certificate for {target}...{Colors. ENDC}")
        
        try:
            analyzer = WebAnalyzer(target, timeout=config['timeout'])
            result = analyzer. get_ssl_info()
            
            print(f"\n{Colors.OKGREEN}[✓] SSL Analysis Complete!{Colors. ENDC}\n")
            print(json.dumps(result, indent=2))
            
            if 'days_until_expiry' in result:
                days = result['days_until_expiry']
                if days < 30:
                    print(f"\n{Colors.FAIL}[! ] WARNING: Certificate expires in {days} days! {Colors.ENDC}")
                elif days < 90:
                    print(f"\n{Colors.WARNING}[! ] Certificate expires in {days} days{Colors.ENDC}")
                else:
                    print(f"\n{Colors.OKGREEN}[✓] Certificate valid for {days} days{Colors. ENDC}")
            
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error: {str(e)}{Colors.ENDC}")
        
        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors. ENDC}")
    
    def _headers_analysis(self, config, target_manager):
        """Execute and display security headers analysis."""
        print(f"\n{Colors.HEADER}═══ Security Headers Analysis ═══{Colors.ENDC}")
        
        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors. ENDC}")
            return
        
        print(f"{Colors. WARNING}[*] Analyzing security headers for {target}...{Colors.ENDC}")
        
        try:
            analyzer = WebAnalyzer(target, timeout=config['timeout'])
            result = analyzer.analyze_headers()
            
            print(f"\n{Colors.OKGREEN}[✓] Headers Analysis Complete!{Colors.ENDC}\n")
            
            for header, info in result.items():
                status = f"{Colors.OKGREEN}✓ Present" if info['present'] else f"{Colors. FAIL}✗ Missing"
                print(f"{Colors.OKCYAN}{header}:{Colors.ENDC} {status}{Colors.ENDC}")
                if info['present'] and info['value']:
                    print(f"  Value: {info['value'][: 80]}...")
            
        except Exception as e: 
            print(f"{Colors. FAIL}[✗] Error:  {str(e)}{Colors.ENDC}")
        
        input(f"\n{Colors. WARNING}Press Enter to continue...{Colors.ENDC}")
    
    def _port_scan(self, config, target_manager):
        """Execute and display port scan."""
        print(f"\n{Colors.HEADER}═══ Port Scanning ═══{Colors.ENDC}")
        
        target = self._get_target(target_manager)
        if not target: 
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return
        
        print(f"{Colors.WARNING}[*] Scanning common ports for {target}...{Colors.ENDC}")
        print(f"{Colors.WARNING}[*] This may take a moment...{Colors.ENDC}")
        
        try:
            analyzer = WebAnalyzer(target, timeout=config['timeout'])
            result = analyzer.scan_ports()
            
            print(f"\n{Colors.OKGREEN}[✓] Port Scan Complete!{Colors.ENDC}\n")
            
            if result and not any('error' in r for r in result):
                print(f"{Colors.OKCYAN}Open Ports:{Colors.ENDC}")
                for port_info in result:
                    print(f"  {Colors.OKGREEN}[OPEN]{Colors.ENDC} Port {port_info['port']} - {port_info['service']}")
            else:
                print(f"{Colors.WARNING}No open ports found or scan failed{Colors.ENDC}")
            
        except Exception as e: 
            print(f"{Colors. FAIL}[✗] Error:  {str(e)}{Colors.ENDC}")
        
        input(f"\n{Colors. WARNING}Press Enter to continue...{Colors.ENDC}")
    
    def _tech_detection(self, config, target_manager):
        """Execute and display technology detection."""
        print(f"\n{Colors.HEADER}═══ Technology Detection ═══{Colors.ENDC}")
        
        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors. ENDC}")
            return
        
        print(f"{Colors. WARNING}[*] Detecting technologies for {target}...{Colors. ENDC}")
        
        try:
            analyzer = WebAnalyzer(target, timeout=config['timeout'])
            result = analyzer.detect_technologies()
            
            print(f"\n{Colors.OKGREEN}[✓] Technology Detection Complete!{Colors. ENDC}\n")
            
            if result:
                for tech_type, tech_name in result.items():
                    print(f"{Colors.OKCYAN}{tech_type. replace('_', ' ').title()}:{Colors.ENDC} {tech_name}")
            else:
                print(f"{Colors. WARNING}No technologies detected{Colors.ENDC}")
            
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error: {str(e)}{Colors.ENDC}")
        
        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
    
    def _full_recon(self, config, target_manager):
        """Execute and display full reconnaissance scan."""
        print(f"\n{Colors.HEADER}═══ Full Reconnaissance Scan ═══{Colors.ENDC}")
        
        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors. WARNING}Press Enter to continue...{Colors.ENDC}")
            return
        
        print(f"{Colors.WARNING}[*] Performing comprehensive scan of {target}...{Colors. ENDC}")
        print(f"{Colors.WARNING}[*] This will take several seconds...{Colors.ENDC}\n")
        
        try: 
            analyzer = WebAnalyzer(target, timeout=config['timeout'])
            
            # Progress indicators
            print(f"[*] Step 1/8: Fetching HTTP data...")
            analyzer.fetch()
            time.sleep(0.3)
            
            print(f"[*] Step 2/8: DNS lookup...")
            time.sleep(0.3)
            
            print(f"[*] Step 3/8: IP resolution...")
            time.sleep(0.3)
            
            print(f"[*] Step 4/8: SSL certificate check...")
            time.sleep(0.3)
            
            print(f"[*] Step 5/8: Security headers analysis...")
            time.sleep(0.3)
            
            print(f"[*] Step 6/8: Port scanning...")
            time.sleep(0.3)
            
            print(f"[*] Step 7/8: Technology detection...")
            time.sleep(0.3)
            
            print(f"[*] Step 8/8: Compiling results...")
            result = analyzer.full_recon_scan()
            
            print(f"\n{Colors.OKGREEN}[✓] Full Scan Complete!{Colors.ENDC}")
            
            # Save to JSON
            self._save_results(result, config['output_file'])
            
            # Show summary
            print(f"\n{Colors.OKCYAN}═══ Scan Summary ═══{Colors. ENDC}")
            print(f"URL: {result['url']}")
            print(f"Hostname: {result['hostname']}")
            print(f"Status:  {result['status_code']} {result['reason']}")
            print(f"IP:  {result['ip_info']. get('ip_address', 'N/A')}")
            print(f"Open Ports: {len([p for p in result['open_ports'] if 'port' in p])}")
            print(f"Technologies: {len(result['technologies'])}")
            
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error: {str(e)}{Colors.ENDC}")
        
        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors. ENDC}")
    
    def _batch_scan(self, config, target_manager):
        """Execute and display batch scan."""
        print(f"\n{Colors.HEADER}═══ Batch Scan ═══{Colors.ENDC}")
        
        targets = target_manager.get_target_list()
        
        if not targets:
            print(f"{Colors.WARNING}[!] No targets available for batch scan{Colors.ENDC}")
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return
        
        print(f"{Colors. OKGREEN}[✓] Found {len(targets)} targets{Colors.ENDC}")
        print(f"{Colors.WARNING}[*] Starting batch scan... {Colors.ENDC}\n")
        
        confirm = input(f"{Colors. OKCYAN}Scan all {len(targets)} targets? (Y/n): {Colors.ENDC}").strip()
        if confirm.lower() == 'n':
            return
        
        try:
            results = []
            for i, target in enumerate(targets, 1):
                print(f"[{i}/{len(targets)}] Scanning {target}...")
                try:
                    analyzer = WebAnalyzer(target, timeout=config['timeout'])
                    result = analyzer.full_recon_scan()
                    results.append(result)
                    print(f"{Colors.OKGREEN}[✓] Complete{Colors.ENDC}")
                except Exception as e:
                    print(f"{Colors.FAIL}[✗] Failed: {str(e)}{Colors.ENDC}")
                    results.append({"url": target, "error": str(e)})
                time.sleep(0.5)
            
            # Save all results
            batch_file = f"batch_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(batch_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            print(f"\n{Colors. OKGREEN}[✓] Batch scan complete!{Colors.ENDC}")
            print(f"{Colors. OKCYAN}Results saved to: {batch_file}{Colors.ENDC}")
            
        except Exception as e: 
            print(f"{Colors. FAIL}[✗] Error:  {str(e)}{Colors.ENDC}")
        
        input(f"\n{Colors. WARNING}Press Enter to continue...{Colors.ENDC}")
    
    def _save_results(self, data, output_file):
        """Save scan results to JSON file."""
        try:
            try:
                with open(output_file, 'r') as f:
                    existing_data = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                existing_data = []
            
            if not isinstance(existing_data, list):
                existing_data = [existing_data]
            
            existing_data.append(data)
            
            with open(output_file, 'w') as f:
                json.dump(existing_data, f, indent=2)
            
            print(f"{Colors.OKGREEN}[✓] Results saved to {output_file}{Colors.ENDC}")
            
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error saving to JSON: {str(e)}{Colors.ENDC}")