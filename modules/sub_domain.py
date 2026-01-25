#!/usr/bin/env python3
"""
SubDomain Module - Subdomain Enumeration and Discovery
Discovers subdomains using DNS brute-force, certificate transparency, and more
"""

import time
import json
import datetime
import socket
import requests
import dns.resolver
import dns.zone
import dns.query
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from helpers.utils import Colors, clear_screen


class SubDomainEnumerator:
    """Core subdomain enumeration functionality."""

    # Common subdomain wordlist
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
        'ns3', 'ns4', 'dns', 'dns1', 'dns2', 'mx', 'mx1', 'mx2', 'email', 'cloud',
        'api', 'dev', 'staging', 'stage', 'test', 'testing', 'qa', 'uat', 'prod',
        'production', 'admin', 'administrator', 'cpanel', 'panel', 'login', 'secure',
        'portal', 'vpn', 'remote', 'git', 'gitlab', 'github', 'svn', 'repo',
        'blog', 'shop', 'store', 'cdn', 'static', 'assets', 'media', 'images', 'img',
        'files', 'download', 'downloads', 'upload', 'uploads', 'backup', 'backups',
        'db', 'database', 'mysql', 'sql', 'postgres', 'mongodb', 'redis', 'cache',
        'app', 'apps', 'mobile', 'ios', 'android', 'web', 'webapp', 'www2', 'www3',
        'old', 'new', 'beta', 'alpha', 'demo', 'sandbox', 'internal', 'intranet',
        'extranet', 'corp', 'corporate', 'office', 'home', 'gateway', 'proxy',
        'server', 'server1', 'server2', 'node', 'node1', 'node2', 'host', 'hosting',
        'support', 'help', 'helpdesk', 'ticket', 'tickets', 'service', 'services',
        'status', 'monitor', 'monitoring', 'nagios', 'grafana', 'kibana', 'elastic',
        'jenkins', 'ci', 'cd', 'build', 'deploy', 'release', 'docker', 'k8s',
        'kubernetes', 'aws', 'azure', 'gcp', 's3', 'ec2', 'lambda', 'api-gateway',
        'auth', 'oauth', 'sso', 'ldap', 'identity', 'accounts', 'account', 'user',
        'users', 'customer', 'customers', 'client', 'clients', 'partner', 'partners',
        'affiliate', 'affiliates', 'merchant', 'merchants', 'vendor', 'vendors',
        'order', 'orders', 'cart', 'checkout', 'payment', 'payments', 'pay', 'billing',
        'invoice', 'invoices', 'crm', 'erp', 'hr', 'legal', 'finance', 'marketing',
        'sales', 'analytics', 'tracking', 'ads', 'ad', 'promo', 'promotions',
        'news', 'press', 'events', 'event', 'forum', 'forums', 'community', 'social',
        'chat', 'messaging', 'video', 'stream', 'streaming', 'live', 'tv', 'radio',
        'docs', 'doc', 'documentation', 'wiki', 'kb', 'knowledge', 'faq', 'search',
        'api1', 'api2', 'api3', 'v1', 'v2', 'v3', 'rest', 'graphql', 'soap', 'rpc',
        'exchange', 'outlook', 'autodiscover', 'lyncdiscover', 'sip', 'meet',
        'm', 'wap', 'imap', 'pop3', 'smtp2', 'relay', 'mail2', 'mailhost',
    ]

    # Extended wordlist for deep scan
    EXTENDED_SUBDOMAINS = COMMON_SUBDOMAINS + [
        'admin1', 'admin2', 'administrator1', 'root', 'superuser', 'master',
        'primary', 'secondary', 'main', 'core', 'origin', 'src', 'source',
        'dev1', 'dev2', 'dev3', 'development', 'develop', 'devops', 'ops',
        'stage1', 'stage2', 'staging1', 'staging2', 'preprod', 'pre-prod',
        'test1', 'test2', 'test3', 'testing1', 'qa1', 'qa2', 'qat',
        'uat1', 'uat2', 'acceptance', 'integration', 'sit', 'perf', 'performance',
        'load', 'stress', 'pen', 'pentest', 'security', 'sec', 'audit',
        'log', 'logs', 'logging', 'syslog', 'splunk', 'elk', 'logstash',
        'metrics', 'prometheus', 'datadog', 'newrelic', 'apm', 'trace', 'tracing',
        'vault', 'secrets', 'config', 'configuration', 'settings', 'env',
        'registry', 'artifact', 'artifactory', 'nexus', 'maven', 'npm', 'pypi',
        'mirror', 'proxy1', 'proxy2', 'lb', 'loadbalancer', 'haproxy', 'nginx',
        'apache', 'tomcat', 'jboss', 'weblogic', 'websphere', 'iis',
        'oracle', 'mssql', 'sqlserver', 'mariadb', 'cassandra', 'couchdb', 'neo4j',
        'rabbitmq', 'kafka', 'activemq', 'zeromq', 'nats', 'pulsar',
        'memcached', 'varnish', 'akamai', 'cloudflare', 'fastly', 'cloudfront',
        'sentry', 'bugsnag', 'rollbar', 'airbrake', 'crashlytics',
        'jira', 'confluence', 'bitbucket', 'bamboo', 'teamcity', 'circleci', 'travis',
        'sonar', 'sonarqube', 'codecov', 'coveralls', 'snyk', 'dependabot',
        'terraform', 'ansible', 'puppet', 'chef', 'salt', 'consul', 'nomad',
        'rancher', 'openshift', 'mesos', 'marathon', 'swarm', 'compose',
        'mail3', 'mail4', 'mail5', 'mx3', 'mx4', 'mx5', 'smtp3', 'relay1', 'relay2',
        'webmail2', 'owa', 'activesync', 'eas', 'ews',
        'sftp', 'ftps', 'tftp', 'nfs', 'smb', 'cifs', 'afp', 'webdav',
        'ssh', 'telnet', 'rdp', 'vnc', 'citrix', 'xen', 'vmware', 'hyperv',
        'wireless', 'wifi', 'wlan', 'radius', 'tacacs', 'nac', 'ise',
        'firewall', 'fw', 'pfsense', 'fortigate', 'paloalto', 'checkpoint',
        'ids', 'ips', 'waf', 'ddos', 'siem', 'qradar', 'arcsight',
    ]

    def __init__(self, domain, timeout=5, threads=20, proxies=None):
        """Initialize subdomain enumerator."""
        self.domain = self._extract_domain(domain)
        self.timeout = timeout
        self.threads = threads
        self.proxies = proxies
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        self.found_subdomains = []

    def _extract_domain(self, domain):
        """Extract base domain from URL or hostname."""
        domain = domain.strip()
        if domain.startswith(('http://', 'https://')):
            parsed = urlparse(domain)
            domain = parsed.netloc
        domain = domain.split(':')[0]  # Remove port
        # Remove www. prefix if present
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain

    def _resolve_subdomain(self, subdomain):
        """Try to resolve a subdomain and return results."""
        full_domain = f"{subdomain}.{self.domain}"
        result = {
            'subdomain': subdomain,
            'full_domain': full_domain,
            'found': False,
            'ip_addresses': [],
            'cname': None
        }

        try:
            # Try A record
            answers = self.resolver.resolve(full_domain, 'A')
            result['found'] = True
            result['ip_addresses'] = [str(rdata) for rdata in answers]
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            # Domain exists but no A record, try CNAME
            try:
                cname_answers = self.resolver.resolve(full_domain, 'CNAME')
                result['found'] = True
                result['cname'] = str(cname_answers[0])
            except:
                pass
        except dns.resolver.Timeout:
            result['error'] = 'timeout'
        except Exception as e:
            result['error'] = str(e)

        return result

    def dns_bruteforce(self, wordlist=None, callback=None):
        """Brute-force subdomains using DNS resolution."""
        if wordlist is None:
            wordlist = self.COMMON_SUBDOMAINS

        results = []
        found = []
        total = len(wordlist)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._resolve_subdomain, sub): sub for sub in wordlist}
            for i, future in enumerate(as_completed(futures), 1):
                result = future.result()
                results.append(result)
                if result['found']:
                    found.append(result)
                if callback:
                    callback(i, total, result)

        return {'all_results': results, 'found': found, 'total_checked': total}

    def dns_bruteforce_deep(self, callback=None):
        """Deep brute-force with extended wordlist."""
        return self.dns_bruteforce(wordlist=self.EXTENDED_SUBDOMAINS, callback=callback)

    def certificate_transparency(self):
        """Query Certificate Transparency logs via crt.sh."""
        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=30, proxies=self.proxies)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    # Split on newlines (crt.sh returns multiple names per entry)
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub.endswith(self.domain) and '*' not in sub:
                            subdomains.add(sub)
            return {
                'source': 'crt.sh',
                'found': list(subdomains),
                'count': len(subdomains)
            }
        except Exception as e:
            return {'source': 'crt.sh', 'error': str(e), 'found': [], 'count': 0}

    def zone_transfer(self):
        """Attempt DNS zone transfer (AXFR)."""
        subdomains = []
        ns_servers = []

        try:
            # Get nameservers
            ns_records = self.resolver.resolve(self.domain, 'NS')
            ns_servers = [str(ns).rstrip('.') for ns in ns_records]
        except Exception as e:
            return {'source': 'zone_transfer', 'error': f'Failed to get NS records: {e}', 'found': [], 'vulnerable': False}

        for ns in ns_servers:
            try:
                # Attempt zone transfer
                zone = dns.zone.from_xfr(dns.query.xfr(ns, self.domain, timeout=10))
                for name, node in zone.nodes.items():
                    subdomain = str(name)
                    if subdomain != '@':
                        full_domain = f"{subdomain}.{self.domain}"
                        subdomains.append(full_domain)
                return {
                    'source': 'zone_transfer',
                    'vulnerable_ns': ns,
                    'vulnerable': True,
                    'found': subdomains,
                    'count': len(subdomains)
                }
            except Exception:
                continue

        return {
            'source': 'zone_transfer',
            'vulnerable': False,
            'ns_checked': ns_servers,
            'found': [],
            'count': 0
        }

    def reverse_dns_range(self, ip_range=None, callback=None):
        """Perform reverse DNS lookups on IP range."""
        if ip_range is None:
            # Try to get IP of main domain and scan nearby
            try:
                main_ip = socket.gethostbyname(self.domain)
                # Parse IP and create range (scan /24)
                parts = main_ip.split('.')
                base = '.'.join(parts[:3])
                ip_range = [f"{base}.{i}" for i in range(1, 255)]
            except Exception as e:
                return {'source': 'reverse_dns', 'error': str(e), 'found': []}

        found = []
        total = len(ip_range)

        for i, ip in enumerate(ip_range, 1):
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                if self.domain in hostname:
                    found.append({'ip': ip, 'hostname': hostname})
            except:
                pass
            if callback:
                callback(i, total, {'ip': ip, 'found': len(found)})

        return {
            'source': 'reverse_dns',
            'found': found,
            'count': len(found),
            'ips_scanned': total
        }

    def resolve_found_subdomains(self, subdomains):
        """Resolve a list of found subdomains to get their IPs."""
        results = []
        for sub in subdomains:
            try:
                # Extract subdomain name if it's a full domain
                if sub.endswith(self.domain):
                    subdomain_name = sub[:-len(self.domain)-1]
                else:
                    subdomain_name = sub

                ips = []
                try:
                    answers = self.resolver.resolve(sub if '.' in sub else f"{sub}.{self.domain}", 'A')
                    ips = [str(rdata) for rdata in answers]
                except:
                    pass

                results.append({
                    'subdomain': subdomain_name,
                    'full_domain': sub if '.' in sub else f"{sub}.{self.domain}",
                    'ip_addresses': ips,
                    'found': True
                })
            except Exception as e:
                results.append({
                    'subdomain': sub,
                    'error': str(e),
                    'found': False
                })
        return results

    def scan_custom_wordlist(self, wordlist_path, callback=None):
        """Scan using a custom wordlist file."""
        try:
            with open(wordlist_path, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            return self.dns_bruteforce(wordlist=wordlist, callback=callback)
        except FileNotFoundError:
            raise Exception(f"Wordlist not found: {wordlist_path}")
        except Exception as e:
            raise Exception(f"Error reading wordlist: {str(e)}")


class SubDomainModule:
    """Module interface for subdomain enumeration."""

    def __init__(self):
        self.name = "Subdomain Enumeration"
        self.version = "1.0.0"
        self.description = "Discovers subdomains using DNS, certificate transparency, and more"
        self.proxy_manager = None

    def run(self, config, target_manager, proxy_manager=None):
        """Main entry point for the module."""
        self.proxy_manager = proxy_manager
        while True:
            clear_screen()
            self._print_module_banner()
            self._print_module_status(config, target_manager)
            self._print_module_menu()

            choice = input(f"{Colors.OKCYAN}Select option: {Colors.ENDC}").strip()

            if choice == "1":
                self._quick_enum(config, target_manager)
            elif choice == "2":
                self._deep_enum(config, target_manager)
            elif choice == "3":
                self._cert_transparency(config, target_manager)
            elif choice == "4":
                self._zone_transfer(config, target_manager)
            elif choice == "5":
                self._reverse_dns(config, target_manager)
            elif choice == "6":
                self._full_enum(config, target_manager)
            elif choice == "7":
                self._custom_wordlist(config, target_manager)
            elif choice == "8":
                self._batch_operation(config, target_manager)
            elif choice.upper() == "B" or choice == "0":
                break
            else:
                print(f"{Colors.FAIL}[!] Invalid option{Colors.ENDC}")
                time.sleep(1)

    def _print_module_banner(self):
        """Print the module banner."""
        banner = f"""
{Colors.HEADER}
===============================================================
              SUBDOMAIN ENUMERATION v{self.version}
                 Discover Hidden Subdomains
==============================================================={Colors.ENDC}
        """
        print(banner)

    def _print_module_status(self, config, target_manager):
        """Print current module status."""
        current = target_manager.get_current_target()
        target_list = target_manager.get_target_list()

        if current:
            target_display = f"Single: {current[:40]}..."
        elif target_list:
            target_display = f"Batch: {len(target_list)} targets"
        else:
            target_display = "No target loaded"

        # Proxy status
        proxy_count = self.proxy_manager.get_count() if self.proxy_manager else 0
        proxy_display = f"{proxy_count} proxies" if proxy_count > 0 else "Direct connection"

        status = f"""{Colors.OKCYAN}Module Status:{Colors.ENDC}
+-------------------------------------------------------------+
| Current Target:   {target_display: <42}|
| Proxy Mode:       {proxy_display: <42}|
| Timeout:          {config['timeout']} seconds{' ' * 36}|
| Output File:      {config['output_file']: <41}|
+-------------------------------------------------------------+"""
        print(status)

    def _get_proxy(self):
        """Get proxy dict for requests."""
        if self.proxy_manager and self.proxy_manager.is_loaded():
            return self.proxy_manager.get_random_proxy()
        return None

    def _print_module_menu(self):
        """Print the module menu options."""
        menu = f"""
{Colors.OKBLUE}Enumeration Options:{Colors.ENDC}
+-------------------------------------------------------------+
|  1. Quick Enum (Common)    ({len(SubDomainEnumerator.COMMON_SUBDOMAINS)} subdomains)              |
|  2. Deep Enum (Extended)   ({len(SubDomainEnumerator.EXTENDED_SUBDOMAINS)} subdomains)             |
|  3. Certificate Transparency (crt.sh)                       |
|  4. Zone Transfer (AXFR)                                    |
|  5. Reverse DNS Scan                                        |
|  6. Full Enumeration (All Methods)                          |
|  7. Custom Wordlist                                         |
|  8. Batch Scan (All Targets)                                |
|                                                             |
|  B. Back to Main Menu                                       |
+-------------------------------------------------------------+
        """
        print(menu)

    def _get_target(self, target_manager):
        """Get target for scanning."""
        current = target_manager.get_current_target()
        target_list = target_manager.get_target_list()

        if current:
            return current
        elif target_list:
            print(f"{Colors.WARNING}[!] You have {len(target_list)} targets loaded.{Colors.ENDC}")
            print(f"{Colors.WARNING}[!] Use 'Batch Scan' (option 8) to scan all.{Colors.ENDC}")

            choice = input(
                f"{Colors.OKCYAN}Enter target number (or 'N' for new): {Colors.ENDC}"
            ).strip().upper()

            if choice == "N":
                target = input(
                    f"{Colors.OKCYAN}Enter domain (e.g., example.com): {Colors.ENDC}"
                ).strip()
                return target
            elif choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(target_list):
                    return target_list[idx]
                else:
                    print(f"{Colors.FAIL}[!] Invalid target number{Colors.ENDC}")
                    time.sleep(1)
                    return None
            else:
                return None
        else:
            print(f"{Colors.WARNING}[!] No target loaded.{Colors.ENDC}")
            choice = input(
                f"{Colors.OKCYAN}Enter a domain now? (Y/n): {Colors.ENDC}"
            ).strip()
            if choice.lower() != "n":
                target = input(
                    f"{Colors.OKCYAN}Enter domain (e.g., example.com): {Colors.ENDC}"
                ).strip()
                if target:
                    target_manager.load_single_target(target)
                return target
            return None

    def _print_progress(self, current, total, result):
        """Print scan progress."""
        percentage = (current / total) * 100
        bar_length = 30
        filled = int(bar_length * current / total)
        bar = "=" * filled + "-" * (bar_length - filled)

        status = ""
        if result.get('found'):
            status = f"{Colors.OKGREEN}[FOUND]{Colors.ENDC}"

        print(
            f"\r{Colors.OKCYAN}[{bar}] {percentage:.0f}% ({current}/{total}) {status}{Colors.ENDC}",
            end="",
            flush=True,
        )

    def _display_results(self, results, scan_type):
        """Display enumeration results."""
        found = results.get('found', [])

        print(f"\n\n{Colors.HEADER}{'=' * 60}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Scan Complete: {scan_type}{Colors.ENDC}")
        print(f"{Colors.HEADER}{'=' * 60}{Colors.ENDC}")

        if 'total_checked' in results:
            print(f"{Colors.OKCYAN}Subdomains Checked: {results['total_checked']}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}Subdomains Found:   {len(found)}{Colors.ENDC}")

        if found:
            print(f"\n{Colors.OKGREEN}Found Subdomains:{Colors.ENDC}")
            print(f"{Colors.OKCYAN}{'Subdomain':<40} {'IP Address(es)':<30}{Colors.ENDC}")
            print("-" * 70)

            for item in found:
                if isinstance(item, dict):
                    subdomain = item.get('full_domain', item.get('subdomain', 'N/A'))
                    ips = ', '.join(item.get('ip_addresses', [])) or item.get('cname', 'CNAME')
                    print(f"{Colors.OKGREEN}{subdomain:<40} {ips:<30}{Colors.ENDC}")
                else:
                    print(f"{Colors.OKGREEN}{item:<40}{Colors.ENDC}")
        else:
            print(f"\n{Colors.WARNING}[!] No subdomains found{Colors.ENDC}")

        return found

    def _save_results(self, data, output_file):
        """Save scan results to JSON file."""
        try:
            try:
                with open(output_file, "r") as f:
                    existing_data = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                existing_data = []

            if not isinstance(existing_data, list):
                existing_data = [existing_data]

            existing_data.append(data)

            with open(output_file, "w") as f:
                json.dump(existing_data, f, indent=2)

            print(f"{Colors.OKGREEN}[+] Results saved to {output_file}{Colors.ENDC}")

        except Exception as e:
            print(f"{Colors.FAIL}[!] Error saving: {str(e)}{Colors.ENDC}")

    def _quick_enum(self, config, target_manager):
        """Quick subdomain enumeration with common wordlist."""
        print(f"\n{Colors.HEADER}=== Quick Subdomain Enumeration ==={Colors.ENDC}")

        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return

        print(f"{Colors.WARNING}[*] Enumerating subdomains for {target}...{Colors.ENDC}")
        print(f"{Colors.OKCYAN}[*] Checking {len(SubDomainEnumerator.COMMON_SUBDOMAINS)} common subdomains...{Colors.ENDC}\n")

        try:
            enumerator = SubDomainEnumerator(target, timeout=config['timeout'], proxies=self._get_proxy())
            results = enumerator.dns_bruteforce(callback=self._print_progress)
            found = self._display_results(results, "Quick Enumeration")

            if config.get("auto_save") and found:
                scan_data = {
                    "domain": enumerator.domain,
                    "scan_type": "quick_enum",
                    "timestamp": datetime.datetime.now().isoformat(),
                    "subdomains_checked": results['total_checked'],
                    "subdomains_found": len(found),
                    "found_subdomains": found
                }
                self._save_results(scan_data, config["output_file"])

        except Exception as e:
            print(f"\n{Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _deep_enum(self, config, target_manager):
        """Deep subdomain enumeration with extended wordlist."""
        print(f"\n{Colors.HEADER}=== Deep Subdomain Enumeration ==={Colors.ENDC}")

        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return

        print(f"{Colors.WARNING}[*] Deep enumeration for {target}...{Colors.ENDC}")
        print(f"{Colors.OKCYAN}[*] Checking {len(SubDomainEnumerator.EXTENDED_SUBDOMAINS)} subdomains...{Colors.ENDC}\n")

        try:
            enumerator = SubDomainEnumerator(target, timeout=config['timeout'], proxies=self._get_proxy())
            results = enumerator.dns_bruteforce_deep(callback=self._print_progress)
            found = self._display_results(results, "Deep Enumeration")

            if config.get("auto_save") and found:
                scan_data = {
                    "domain": enumerator.domain,
                    "scan_type": "deep_enum",
                    "timestamp": datetime.datetime.now().isoformat(),
                    "subdomains_checked": results['total_checked'],
                    "subdomains_found": len(found),
                    "found_subdomains": found
                }
                self._save_results(scan_data, config["output_file"])

        except Exception as e:
            print(f"\n{Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _cert_transparency(self, config, target_manager):
        """Query Certificate Transparency logs."""
        print(f"\n{Colors.HEADER}=== Certificate Transparency Lookup ==={Colors.ENDC}")

        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return

        print(f"{Colors.WARNING}[*] Querying crt.sh for {target}...{Colors.ENDC}")
        print(f"{Colors.OKCYAN}[*] This may take a moment...{Colors.ENDC}\n")

        try:
            enumerator = SubDomainEnumerator(target, timeout=30, proxies=self._get_proxy())
            results = enumerator.certificate_transparency()

            if 'error' in results:
                print(f"{Colors.FAIL}[!] Error: {results['error']}{Colors.ENDC}")
            else:
                found = results.get('found', [])
                print(f"\n{Colors.HEADER}{'=' * 60}{Colors.ENDC}")
                print(f"{Colors.OKGREEN}[+] Certificate Transparency Results{Colors.ENDC}")
                print(f"{Colors.HEADER}{'=' * 60}{Colors.ENDC}")
                print(f"{Colors.OKCYAN}Subdomains Found: {len(found)}{Colors.ENDC}")

                if found:
                    print(f"\n{Colors.OKGREEN}Found Subdomains:{Colors.ENDC}")
                    for sub in sorted(found):
                        print(f"  {Colors.OKGREEN}{sub}{Colors.ENDC}")

                    # Resolve found subdomains
                    print(f"\n{Colors.WARNING}[*] Resolving found subdomains...{Colors.ENDC}")
                    resolved = enumerator.resolve_found_subdomains(found)

                    if config.get("auto_save"):
                        scan_data = {
                            "domain": enumerator.domain,
                            "scan_type": "cert_transparency",
                            "source": "crt.sh",
                            "timestamp": datetime.datetime.now().isoformat(),
                            "subdomains_found": len(found),
                            "found_subdomains": resolved
                        }
                        self._save_results(scan_data, config["output_file"])

        except Exception as e:
            print(f"\n{Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _zone_transfer(self, config, target_manager):
        """Attempt DNS zone transfer."""
        print(f"\n{Colors.HEADER}=== DNS Zone Transfer (AXFR) ==={Colors.ENDC}")

        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return

        print(f"{Colors.WARNING}[*] Attempting zone transfer for {target}...{Colors.ENDC}\n")

        try:
            enumerator = SubDomainEnumerator(target, timeout=config['timeout'], proxies=self._get_proxy())
            results = enumerator.zone_transfer()

            print(f"\n{Colors.HEADER}{'=' * 60}{Colors.ENDC}")
            print(f"{Colors.OKGREEN}[+] Zone Transfer Results{Colors.ENDC}")
            print(f"{Colors.HEADER}{'=' * 60}{Colors.ENDC}")

            if results.get('vulnerable'):
                print(f"{Colors.FAIL}[!] VULNERABLE! Zone transfer successful on {results['vulnerable_ns']}{Colors.ENDC}")
                print(f"{Colors.OKCYAN}Subdomains Found: {results['count']}{Colors.ENDC}")

                if results.get('found'):
                    print(f"\n{Colors.OKGREEN}Found Subdomains:{Colors.ENDC}")
                    for sub in results['found']:
                        print(f"  {Colors.OKGREEN}{sub}{Colors.ENDC}")

                if config.get("auto_save"):
                    scan_data = {
                        "domain": enumerator.domain,
                        "scan_type": "zone_transfer",
                        "vulnerable": True,
                        "vulnerable_ns": results['vulnerable_ns'],
                        "timestamp": datetime.datetime.now().isoformat(),
                        "found_subdomains": results['found']
                    }
                    self._save_results(scan_data, config["output_file"])
            else:
                print(f"{Colors.OKGREEN}[+] Not vulnerable - Zone transfer denied{Colors.ENDC}")
                if results.get('ns_checked'):
                    print(f"{Colors.OKCYAN}NS Servers Checked: {', '.join(results['ns_checked'])}{Colors.ENDC}")

        except Exception as e:
            print(f"\n{Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _reverse_dns(self, config, target_manager):
        """Perform reverse DNS scan."""
        print(f"\n{Colors.HEADER}=== Reverse DNS Scan ==={Colors.ENDC}")

        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return

        print(f"{Colors.WARNING}[*] Performing reverse DNS scan for {target}...{Colors.ENDC}")
        print(f"{Colors.OKCYAN}[*] Scanning /24 network range...{Colors.ENDC}\n")

        try:
            enumerator = SubDomainEnumerator(target, timeout=config['timeout'], proxies=self._get_proxy())

            def rdns_callback(current, total, result):
                percentage = (current / total) * 100
                bar_length = 30
                filled = int(bar_length * current / total)
                bar = "=" * filled + "-" * (bar_length - filled)
                found_count = result.get('found', 0)
                print(
                    f"\r{Colors.OKCYAN}[{bar}] {percentage:.0f}% ({current}/{total}) Found: {found_count}{Colors.ENDC}",
                    end="",
                    flush=True,
                )

            results = enumerator.reverse_dns_range(callback=rdns_callback)

            print(f"\n\n{Colors.HEADER}{'=' * 60}{Colors.ENDC}")
            print(f"{Colors.OKGREEN}[+] Reverse DNS Results{Colors.ENDC}")
            print(f"{Colors.HEADER}{'=' * 60}{Colors.ENDC}")
            print(f"{Colors.OKCYAN}IPs Scanned: {results['ips_scanned']}{Colors.ENDC}")
            print(f"{Colors.OKCYAN}Subdomains Found: {results['count']}{Colors.ENDC}")

            if results.get('found'):
                print(f"\n{Colors.OKGREEN}Found Hosts:{Colors.ENDC}")
                print(f"{Colors.OKCYAN}{'IP Address':<20} {'Hostname':<45}{Colors.ENDC}")
                print("-" * 65)
                for item in results['found']:
                    print(f"{Colors.OKGREEN}{item['ip']:<20} {item['hostname']:<45}{Colors.ENDC}")

                if config.get("auto_save"):
                    scan_data = {
                        "domain": enumerator.domain,
                        "scan_type": "reverse_dns",
                        "timestamp": datetime.datetime.now().isoformat(),
                        "ips_scanned": results['ips_scanned'],
                        "found_hosts": results['found']
                    }
                    self._save_results(scan_data, config["output_file"])

        except Exception as e:
            print(f"\n{Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _full_enum(self, config, target_manager):
        """Full enumeration using all methods."""
        print(f"\n{Colors.HEADER}=== Full Subdomain Enumeration ==={Colors.ENDC}")

        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return

        print(f"{Colors.WARNING}[*] Running full enumeration for {target}...{Colors.ENDC}\n")

        all_subdomains = set()
        scan_results = {}

        try:
            enumerator = SubDomainEnumerator(target, timeout=config['timeout'], proxies=self._get_proxy())

            # 1. Certificate Transparency
            print(f"{Colors.OKCYAN}[1/4] Certificate Transparency...{Colors.ENDC}")
            ct_results = enumerator.certificate_transparency()
            if ct_results.get('found'):
                all_subdomains.update(ct_results['found'])
                print(f"      {Colors.OKGREEN}Found {len(ct_results['found'])} subdomains{Colors.ENDC}")
            scan_results['cert_transparency'] = ct_results

            # 2. Zone Transfer
            print(f"{Colors.OKCYAN}[2/4] Zone Transfer...{Colors.ENDC}")
            zt_results = enumerator.zone_transfer()
            if zt_results.get('found'):
                all_subdomains.update(zt_results['found'])
                print(f"      {Colors.FAIL}VULNERABLE! Found {len(zt_results['found'])} subdomains{Colors.ENDC}")
            else:
                print(f"      {Colors.OKGREEN}Not vulnerable{Colors.ENDC}")
            scan_results['zone_transfer'] = zt_results

            # 3. DNS Bruteforce (Extended)
            print(f"{Colors.OKCYAN}[3/4] DNS Bruteforce ({len(SubDomainEnumerator.EXTENDED_SUBDOMAINS)} subdomains)...{Colors.ENDC}")
            bf_results = enumerator.dns_bruteforce_deep(callback=self._print_progress)
            for item in bf_results.get('found', []):
                all_subdomains.add(item['full_domain'])
            print(f"\n      {Colors.OKGREEN}Found {len(bf_results['found'])} subdomains{Colors.ENDC}")
            scan_results['dns_bruteforce'] = bf_results

            # 4. Reverse DNS (optional - can be slow)
            print(f"{Colors.OKCYAN}[4/4] Reverse DNS...{Colors.ENDC}")
            rdns_results = enumerator.reverse_dns_range()
            for item in rdns_results.get('found', []):
                all_subdomains.add(item['hostname'])
            print(f"      {Colors.OKGREEN}Found {len(rdns_results['found'])} hosts{Colors.ENDC}")
            scan_results['reverse_dns'] = rdns_results

            # Summary
            print(f"\n{Colors.HEADER}{'=' * 60}{Colors.ENDC}")
            print(f"{Colors.OKGREEN}[+] Full Enumeration Complete{Colors.ENDC}")
            print(f"{Colors.HEADER}{'=' * 60}{Colors.ENDC}")
            print(f"{Colors.OKCYAN}Total Unique Subdomains: {len(all_subdomains)}{Colors.ENDC}")

            if all_subdomains:
                print(f"\n{Colors.OKGREEN}All Found Subdomains:{Colors.ENDC}")
                for sub in sorted(all_subdomains):
                    print(f"  {Colors.OKGREEN}{sub}{Colors.ENDC}")

                if config.get("auto_save"):
                    scan_data = {
                        "domain": enumerator.domain,
                        "scan_type": "full_enumeration",
                        "timestamp": datetime.datetime.now().isoformat(),
                        "total_unique": len(all_subdomains),
                        "all_subdomains": sorted(list(all_subdomains)),
                        "scan_results": {
                            "cert_transparency": len(ct_results.get('found', [])),
                            "zone_transfer_vulnerable": zt_results.get('vulnerable', False),
                            "dns_bruteforce": len(bf_results.get('found', [])),
                            "reverse_dns": len(rdns_results.get('found', []))
                        }
                    }
                    self._save_results(scan_data, config["output_file"])

        except Exception as e:
            print(f"\n{Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _custom_wordlist(self, config, target_manager):
        """Scan using a custom wordlist."""
        print(f"\n{Colors.HEADER}=== Custom Wordlist Scan ==={Colors.ENDC}")

        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return

        wordlist_path = input(
            f"{Colors.OKCYAN}Enter path to wordlist file: {Colors.ENDC}"
        ).strip()

        if not wordlist_path:
            print(f"{Colors.FAIL}[!] No wordlist provided{Colors.ENDC}")
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return

        try:
            enumerator = SubDomainEnumerator(target, timeout=config['timeout'], proxies=self._get_proxy())
            print(f"{Colors.WARNING}[*] Loading wordlist: {wordlist_path}...{Colors.ENDC}")

            results = enumerator.scan_custom_wordlist(wordlist_path, callback=self._print_progress)
            found = self._display_results(results, f"Custom Wordlist ({wordlist_path})")

            if config.get("auto_save") and found:
                scan_data = {
                    "domain": enumerator.domain,
                    "scan_type": "custom_wordlist",
                    "wordlist": wordlist_path,
                    "timestamp": datetime.datetime.now().isoformat(),
                    "subdomains_checked": results['total_checked'],
                    "subdomains_found": len(found),
                    "found_subdomains": found
                }
                self._save_results(scan_data, config["output_file"])

        except Exception as e:
            print(f"\n{Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _batch_operation(self, config, target_manager):
        """Batch enumeration on all loaded targets."""
        print(f"\n{Colors.HEADER}=== Batch Subdomain Enumeration ==={Colors.ENDC}")

        targets = target_manager.get_target_list()

        if not targets:
            print(f"{Colors.WARNING}[!] No targets loaded for batch operation{Colors.ENDC}")
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return

        print(f"{Colors.OKGREEN}[+] Found {len(targets)} targets{Colors.ENDC}")

        # Select scan type
        print(f"\n{Colors.OKCYAN}Select enumeration type:{Colors.ENDC}")
        print("  1. Quick (Common subdomains)")
        print("  2. Deep (Extended wordlist)")
        print("  3. Certificate Transparency only")

        scan_choice = input(f"{Colors.OKCYAN}Choice [1-3]: {Colors.ENDC}").strip()

        if scan_choice not in ['1', '2', '3']:
            print(f"{Colors.FAIL}[!] Invalid choice{Colors.ENDC}")
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return

        confirm = input(
            f"{Colors.OKCYAN}Scan {len(targets)} targets? (Y/n): {Colors.ENDC}"
        ).strip()
        if confirm.lower() == "n":
            return

        try:
            all_results = []
            for i, target in enumerate(targets, 1):
                print(f"\n{Colors.HEADER}[{i}/{len(targets)}] Enumerating {target}...{Colors.ENDC}")

                try:
                    enumerator = SubDomainEnumerator(target, timeout=config['timeout'], proxies=self._get_proxy())

                    if scan_choice == '1':
                        results = enumerator.dns_bruteforce(callback=self._print_progress)
                        scan_type = 'quick_enum'
                    elif scan_choice == '2':
                        results = enumerator.dns_bruteforce_deep(callback=self._print_progress)
                        scan_type = 'deep_enum'
                    else:
                        results = enumerator.certificate_transparency()
                        scan_type = 'cert_transparency'

                    found = results.get('found', [])
                    print(f"\n{Colors.OKGREEN}[+] Found {len(found)} subdomains{Colors.ENDC}")

                    all_results.append({
                        "domain": enumerator.domain,
                        "scan_type": scan_type,
                        "timestamp": datetime.datetime.now().isoformat(),
                        "subdomains_found": len(found),
                        "found_subdomains": found
                    })

                except Exception as e:
                    print(f"{Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")
                    all_results.append({
                        "domain": target,
                        "error": str(e)
                    })

            # Save batch results
            batch_file = f"batch_subdomain_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(batch_file, "w") as f:
                json.dump(all_results, f, indent=2)

            # Summary
            print(f"\n{Colors.HEADER}{'=' * 60}{Colors.ENDC}")
            print(f"{Colors.OKGREEN}[+] Batch Enumeration Complete!{Colors.ENDC}")
            print(f"{Colors.HEADER}{'=' * 60}{Colors.ENDC}")
            print(f"{Colors.OKCYAN}Domains Scanned: {len(targets)}{Colors.ENDC}")

            total_found = sum(r.get('subdomains_found', 0) for r in all_results if 'subdomains_found' in r)
            print(f"{Colors.OKCYAN}Total Subdomains Found: {total_found}{Colors.ENDC}")
            print(f"{Colors.OKCYAN}Results Saved: {batch_file}{Colors.ENDC}")

        except Exception as e:
            print(f"{Colors.FAIL}[!] Batch error: {str(e)}{Colors.ENDC}")

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
