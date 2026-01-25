#!/usr/bin/env python3
"""
PathFinder Module - Sensitive Path Discovery
Scans web servers for common sensitive paths, admin panels, and hidden endpoints
"""

import time
import json
import datetime
import requests
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

from helpers.utils import Colors, clear_screen


class PathFinder:
    """Core path finding functionality with comprehensive wordlists."""

    # Login and Admin paths
    ADMIN_PATHS = [
        '/admin', '/admin/', '/administrator', '/administrator/',
        '/admin/login', '/admin/login.php', '/admin/index.php',
        '/admin.php', '/adminpanel', '/admincp', '/admin_area',
        '/panel', '/panel/', '/cpanel', '/controlpanel',
        '/login', '/login/', '/login.php', '/login.html', '/signin',
        '/user/login', '/users/login', '/auth/login', '/account/login',
        '/wp-login.php', '/wp-admin', '/wp-admin/',
        '/manager', '/manager/', '/management', '/dashboard',
        '/admin/dashboard', '/secure', '/secure/', '/private',
        '/backend', '/backend/', '/adminarea', '/siteadmin',
        '/moderator', '/webadmin', '/admincontrol', '/admin_login',
        '/admin/admin', '/admin/account', '/admin/home',
        '/phpmyadmin', '/phpmyadmin/', '/pma', '/myadmin',
        '/mysql', '/mysqladmin', '/db', '/database',
        '/adminer', '/adminer.php',
    ]

    # CMS-specific paths (WordPress, Joomla, Drupal, etc.)
    CMS_PATHS = [
        # WordPress
        '/wp-content/', '/wp-includes/', '/wp-json/', '/wp-json/wp/v2/',
        '/wp-config.php', '/wp-config.php.bak', '/wp-config.txt',
        '/xmlrpc.php', '/wp-cron.php', '/wp-settings.php',
        '/wp-content/uploads/', '/wp-content/plugins/', '/wp-content/themes/',
        '/wp-content/debug.log', '/wp-content/backup-db/',
        '/readme.html', '/license.txt',
        # Joomla
        '/administrator/', '/administrator/index.php',
        '/configuration.php', '/configuration.php.bak',
        '/components/', '/modules/', '/plugins/', '/templates/',
        '/cache/', '/tmp/', '/logs/',
        '/htaccess.txt', '/web.config.txt',
        # Drupal
        '/user/', '/user/login', '/node/', '/admin/content',
        '/sites/default/', '/sites/default/files/',
        '/sites/default/settings.php', '/CHANGELOG.txt',
        '/core/', '/profiles/', '/themes/',
        # Magento
        '/downloader/', '/app/etc/local.xml', '/var/log/',
        '/skin/', '/media/', '/js/',
        # Laravel
        '/.env', '/storage/', '/storage/logs/', '/storage/logs/laravel.log',
        '/vendor/', '/artisan', '/bootstrap/',
    ]

    # API and hidden endpoints
    API_PATHS = [
        '/api', '/api/', '/api/v1', '/api/v1/', '/api/v2', '/api/v2/',
        '/api/v3', '/api/users', '/api/user', '/api/admin',
        '/api/login', '/api/auth', '/api/token', '/api/config',
        '/api/status', '/api/health', '/api/info', '/api/version',
        '/rest', '/rest/', '/rest/api', '/v1', '/v2', '/v3',
        '/graphql', '/graphiql', '/graphql/console',
        '/swagger', '/swagger/', '/swagger-ui', '/swagger-ui/',
        '/swagger-ui.html', '/swagger.json', '/swagger.yaml',
        '/api-docs', '/api-docs/', '/docs', '/docs/', '/redoc',
        '/openapi', '/openapi.json', '/openapi.yaml',
        '/.well-known/', '/.well-known/security.txt',
        '/health', '/healthz', '/healthcheck', '/status', '/ping',
        '/metrics', '/prometheus', '/actuator', '/actuator/health',
        '/debug', '/debug/', '/trace', '/console',
        '/internal', '/internal/', '/private-api',
    ]

    # Sensitive files and backup paths
    SENSITIVE_PATHS = [
        # Config files
        '/.env', '/.env.local', '/.env.production', '/.env.backup',
        '/config.php', '/config.inc.php', '/config.yml', '/config.yaml',
        '/config.json', '/settings.php', '/settings.py', '/settings.json',
        '/database.yml', '/secrets.yml', '/credentials.json',
        '/application.properties', '/application.yml',
        # Backup files
        '/backup', '/backup/', '/backups', '/backups/', '/bak',
        '/backup.sql', '/backup.zip', '/backup.tar.gz', '/db.sql',
        '/database.sql', '/dump.sql', '/data.sql', '/mysql.sql',
        '/site.zip', '/www.zip', '/html.zip', '/web.zip',
        '/.backup', '/old', '/old/', '/archive', '/archive/',
        # Git/Version control
        '/.git', '/.git/', '/.git/config', '/.git/HEAD',
        '/.gitignore', '/.gitattributes',
        '/.svn', '/.svn/', '/.svn/entries',
        '/.hg', '/.hg/', '/.bzr', '/.bzr/',
        # Server files
        '/.htaccess', '/.htpasswd', '/web.config', '/server-status',
        '/server-info', '/nginx.conf', '/httpd.conf',
        '/robots.txt', '/sitemap.xml', '/sitemap_index.xml',
        '/crossdomain.xml', '/clientaccesspolicy.xml',
        # IDE/Editor files
        '/.idea/', '/.vscode/', '/.project', '/.settings/',
        '/nbproject/', '/.DS_Store', '/Thumbs.db',
        # Log files
        '/logs', '/logs/', '/log', '/log/', '/error.log', '/access.log',
        '/debug.log', '/app.log', '/application.log',
        '/error_log', '/errors.log', '/php_errors.log',
        # Common directories
        '/temp', '/temp/', '/tmp', '/tmp/', '/cache', '/cache/',
        '/uploads', '/uploads/', '/files', '/files/',
        '/assets', '/assets/', '/static', '/static/',
        '/media', '/media/', '/images', '/img/',
        '/includes', '/include', '/inc', '/lib', '/libs',
        '/src', '/source', '/test', '/tests', '/spec',
    ]

    # Status codes that indicate found paths
    FOUND_CODES = [200, 201, 204, 301, 302, 303, 307, 308, 401, 403]

    def __init__(self, url, timeout=10, threads=10, proxies=None):
        """Initialize path finder."""
        self.url = self._normalize_url(url)
        self.timeout = timeout
        self.threads = threads
        self.proxies = proxies
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        if proxies:
            self.session.proxies.update(proxies)
        self.results = []

    def _normalize_url(self, url):
        """Normalize URL to ensure proper format."""
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
        return url.rstrip('/')

    def _check_path(self, path):
        """Check if a path exists on the target."""
        full_url = urljoin(self.url + '/', path.lstrip('/'))
        try:
            response = self.session.get(
                full_url,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False
            )
            return {
                'path': path,
                'url': full_url,
                'status_code': response.status_code,
                'content_length': len(response.content),
                'content_type': response.headers.get('Content-Type', 'Unknown'),
                'found': response.status_code in self.FOUND_CODES
            }
        except requests.exceptions.Timeout:
            return {'path': path, 'url': full_url, 'status_code': 'TIMEOUT', 'found': False}
        except requests.exceptions.ConnectionError:
            return {'path': path, 'url': full_url, 'status_code': 'CONN_ERR', 'found': False}
        except Exception as e:
            return {'path': path, 'url': full_url, 'status_code': 'ERROR', 'error': str(e), 'found': False}

    def _scan_paths(self, paths, callback=None):
        """Scan a list of paths using thread pool."""
        results = []
        found = []
        total = len(paths)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._check_path, path): path for path in paths}
            for i, future in enumerate(as_completed(futures), 1):
                result = future.result()
                results.append(result)
                if result['found']:
                    found.append(result)
                if callback:
                    callback(i, total, result)

        return {'all_results': results, 'found': found, 'total_checked': total}

    def scan_admin_paths(self, callback=None):
        """Scan for admin and login paths."""
        return self._scan_paths(self.ADMIN_PATHS, callback)

    def scan_cms_paths(self, callback=None):
        """Scan for CMS-specific paths."""
        return self._scan_paths(self.CMS_PATHS, callback)

    def scan_api_paths(self, callback=None):
        """Scan for API and hidden endpoints."""
        return self._scan_paths(self.API_PATHS, callback)

    def scan_sensitive_paths(self, callback=None):
        """Scan for sensitive files and directories."""
        return self._scan_paths(self.SENSITIVE_PATHS, callback)

    def scan_all_paths(self, callback=None):
        """Scan all path categories."""
        all_paths = list(set(
            self.ADMIN_PATHS +
            self.CMS_PATHS +
            self.API_PATHS +
            self.SENSITIVE_PATHS
        ))
        return self._scan_paths(all_paths, callback)

    def scan_custom_wordlist(self, wordlist_path, callback=None):
        """Scan using a custom wordlist file."""
        try:
            with open(wordlist_path, 'r') as f:
                paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            return self._scan_paths(paths, callback)
        except FileNotFoundError:
            raise Exception(f"Wordlist not found: {wordlist_path}")
        except Exception as e:
            raise Exception(f"Error reading wordlist: {str(e)}")


class PathFinderModule:
    """Module interface for path finding - handles all presentation."""

    def __init__(self):
        self.name = "Sensitive Path Finder"
        self.version = "1.0.0"
        self.description = "Discovers sensitive paths, admin panels, and hidden endpoints"
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
                self._scan_admin_paths(config, target_manager)
            elif choice == "2":
                self._scan_cms_paths(config, target_manager)
            elif choice == "3":
                self._scan_api_paths(config, target_manager)
            elif choice == "4":
                self._scan_sensitive_paths(config, target_manager)
            elif choice == "5":
                self._scan_all_paths(config, target_manager)
            elif choice == "6":
                self._scan_custom_wordlist(config, target_manager)
            elif choice == "7":
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
              SENSITIVE PATH FINDER v{self.version}
            Discover Hidden Paths & Admin Panels
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
{Colors.OKBLUE}Scan Options:{Colors.ENDC}
+-------------------------------------------------------------+
|  1. Admin/Login Paths      ({len(PathFinder.ADMIN_PATHS)} paths)                   |
|  2. CMS Paths (WP/Joomla)  ({len(PathFinder.CMS_PATHS)} paths)                   |
|  3. API/Hidden Endpoints   ({len(PathFinder.API_PATHS)} paths)                   |
|  4. Sensitive Files        ({len(PathFinder.SENSITIVE_PATHS)} paths)                   |
|  5. All Paths Combined     ({len(set(PathFinder.ADMIN_PATHS + PathFinder.CMS_PATHS + PathFinder.API_PATHS + PathFinder.SENSITIVE_PATHS))} paths)                  |
|  6. Custom Wordlist                                         |
|  7. Batch Scan (All Targets)                                |
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
            print(f"{Colors.WARNING}[!] Use 'Batch Scan' (option 7) to scan all.{Colors.ENDC}")

            choice = input(
                f"{Colors.OKCYAN}Enter target number (or 'N' for new): {Colors.ENDC}"
            ).strip().upper()

            if choice == "N":
                target = input(
                    f"{Colors.OKCYAN}Enter target URL: {Colors.ENDC}"
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
                f"{Colors.OKCYAN}Enter a target now? (Y/n): {Colors.ENDC}"
            ).strip()
            if choice.lower() != "n":
                target = input(
                    f"{Colors.OKCYAN}Enter target URL: {Colors.ENDC}"
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
        if result['found']:
            status = f"{Colors.OKGREEN}[{result['status_code']}]{Colors.ENDC}"
        elif result.get('status_code') == 404:
            status = ""
        else:
            status = f"[{result.get('status_code', '?')}]"

        print(
            f"\r{Colors.OKCYAN}[{bar}] {percentage:.0f}% ({current}/{total}) {status} {Colors.ENDC}",
            end="",
            flush=True,
        )

    def _display_results(self, results, scan_type):
        """Display scan results in a formatted table."""
        found = results.get('found', [])
        total = results.get('total_checked', 0)

        print(f"\n\n{Colors.HEADER}{'=' * 60}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Scan Complete: {scan_type}{Colors.ENDC}")
        print(f"{Colors.HEADER}{'=' * 60}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}Paths Checked: {total}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}Paths Found:   {len(found)}{Colors.ENDC}")

        if found:
            print(f"\n{Colors.OKGREEN}Found Paths:{Colors.ENDC}")
            print(f"{Colors.OKCYAN}{'Status':<8} {'Size':<10} {'Path':<45}{Colors.ENDC}")
            print("-" * 65)

            # Sort by status code
            found.sort(key=lambda x: (x['status_code'] if isinstance(x['status_code'], int) else 999))

            for item in found:
                status = item['status_code']
                size = item.get('content_length', 0)
                path = item['path']

                # Color based on status
                if status == 200:
                    color = Colors.OKGREEN
                elif status in [301, 302, 303, 307, 308]:
                    color = Colors.WARNING
                elif status in [401, 403]:
                    color = Colors.FAIL
                else:
                    color = Colors.OKCYAN

                size_str = f"{size}B" if size < 1024 else f"{size/1024:.1f}KB"
                print(f"{color}{status:<8} {size_str:<10} {path:<45}{Colors.ENDC}")
        else:
            print(f"\n{Colors.WARNING}[!] No paths found{Colors.ENDC}")

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

    def _scan_admin_paths(self, config, target_manager):
        """Scan for admin and login paths."""
        print(f"\n{Colors.HEADER}=== Admin/Login Path Scan ==={Colors.ENDC}")

        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return

        print(f"{Colors.WARNING}[*] Scanning {target} for admin paths...{Colors.ENDC}")
        print(f"{Colors.OKCYAN}[*] Checking {len(PathFinder.ADMIN_PATHS)} paths...{Colors.ENDC}\n")

        try:
            finder = PathFinder(target, timeout=config['timeout'], proxies=self._get_proxy())
            results = finder.scan_admin_paths(callback=self._print_progress)
            found = self._display_results(results, "Admin/Login Paths")

            if config.get("auto_save") and found:
                scan_data = {
                    "target": target,
                    "scan_type": "admin_paths",
                    "timestamp": datetime.datetime.now().isoformat(),
                    "paths_checked": results['total_checked'],
                    "paths_found": len(found),
                    "found_paths": found
                }
                self._save_results(scan_data, config["output_file"])

        except Exception as e:
            print(f"\n{Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _scan_cms_paths(self, config, target_manager):
        """Scan for CMS-specific paths."""
        print(f"\n{Colors.HEADER}=== CMS Path Scan ==={Colors.ENDC}")

        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return

        print(f"{Colors.WARNING}[*] Scanning {target} for CMS paths...{Colors.ENDC}")
        print(f"{Colors.OKCYAN}[*] Checking {len(PathFinder.CMS_PATHS)} paths (WP, Joomla, Drupal, etc.)...{Colors.ENDC}\n")

        try:
            finder = PathFinder(target, timeout=config['timeout'], proxies=self._get_proxy())
            results = finder.scan_cms_paths(callback=self._print_progress)
            found = self._display_results(results, "CMS Paths")

            if config.get("auto_save") and found:
                scan_data = {
                    "target": target,
                    "scan_type": "cms_paths",
                    "timestamp": datetime.datetime.now().isoformat(),
                    "paths_checked": results['total_checked'],
                    "paths_found": len(found),
                    "found_paths": found
                }
                self._save_results(scan_data, config["output_file"])

        except Exception as e:
            print(f"\n{Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _scan_api_paths(self, config, target_manager):
        """Scan for API and hidden endpoints."""
        print(f"\n{Colors.HEADER}=== API/Hidden Endpoint Scan ==={Colors.ENDC}")

        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return

        print(f"{Colors.WARNING}[*] Scanning {target} for API endpoints...{Colors.ENDC}")
        print(f"{Colors.OKCYAN}[*] Checking {len(PathFinder.API_PATHS)} paths...{Colors.ENDC}\n")

        try:
            finder = PathFinder(target, timeout=config['timeout'], proxies=self._get_proxy())
            results = finder.scan_api_paths(callback=self._print_progress)
            found = self._display_results(results, "API/Hidden Endpoints")

            if config.get("auto_save") and found:
                scan_data = {
                    "target": target,
                    "scan_type": "api_paths",
                    "timestamp": datetime.datetime.now().isoformat(),
                    "paths_checked": results['total_checked'],
                    "paths_found": len(found),
                    "found_paths": found
                }
                self._save_results(scan_data, config["output_file"])

        except Exception as e:
            print(f"\n{Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _scan_sensitive_paths(self, config, target_manager):
        """Scan for sensitive files and directories."""
        print(f"\n{Colors.HEADER}=== Sensitive Files Scan ==={Colors.ENDC}")

        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return

        print(f"{Colors.WARNING}[*] Scanning {target} for sensitive files...{Colors.ENDC}")
        print(f"{Colors.OKCYAN}[*] Checking {len(PathFinder.SENSITIVE_PATHS)} paths...{Colors.ENDC}\n")

        try:
            finder = PathFinder(target, timeout=config['timeout'], proxies=self._get_proxy())
            results = finder.scan_sensitive_paths(callback=self._print_progress)
            found = self._display_results(results, "Sensitive Files")

            if config.get("auto_save") and found:
                scan_data = {
                    "target": target,
                    "scan_type": "sensitive_paths",
                    "timestamp": datetime.datetime.now().isoformat(),
                    "paths_checked": results['total_checked'],
                    "paths_found": len(found),
                    "found_paths": found
                }
                self._save_results(scan_data, config["output_file"])

        except Exception as e:
            print(f"\n{Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _scan_all_paths(self, config, target_manager):
        """Scan all path categories."""
        print(f"\n{Colors.HEADER}=== Full Path Scan ==={Colors.ENDC}")

        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return

        all_paths = list(set(
            PathFinder.ADMIN_PATHS +
            PathFinder.CMS_PATHS +
            PathFinder.API_PATHS +
            PathFinder.SENSITIVE_PATHS
        ))

        print(f"{Colors.WARNING}[*] Full scan on {target}...{Colors.ENDC}")
        print(f"{Colors.OKCYAN}[*] Checking {len(all_paths)} unique paths...{Colors.ENDC}\n")

        try:
            finder = PathFinder(target, timeout=config['timeout'], proxies=self._get_proxy())
            results = finder.scan_all_paths(callback=self._print_progress)
            found = self._display_results(results, "All Paths")

            if config.get("auto_save") and found:
                scan_data = {
                    "target": target,
                    "scan_type": "all_paths",
                    "timestamp": datetime.datetime.now().isoformat(),
                    "paths_checked": results['total_checked'],
                    "paths_found": len(found),
                    "found_paths": found
                }
                self._save_results(scan_data, config["output_file"])

        except Exception as e:
            print(f"\n{Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _scan_custom_wordlist(self, config, target_manager):
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
            finder = PathFinder(target, timeout=config['timeout'], proxies=self._get_proxy())
            print(f"{Colors.WARNING}[*] Loading wordlist: {wordlist_path}...{Colors.ENDC}")

            results = finder.scan_custom_wordlist(wordlist_path, callback=self._print_progress)
            found = self._display_results(results, f"Custom Wordlist ({wordlist_path})")

            if config.get("auto_save") and found:
                scan_data = {
                    "target": target,
                    "scan_type": "custom_wordlist",
                    "wordlist": wordlist_path,
                    "timestamp": datetime.datetime.now().isoformat(),
                    "paths_checked": results['total_checked'],
                    "paths_found": len(found),
                    "found_paths": found
                }
                self._save_results(scan_data, config["output_file"])

        except Exception as e:
            print(f"\n{Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _batch_operation(self, config, target_manager):
        """Batch scan on all loaded targets."""
        print(f"\n{Colors.HEADER}=== Batch Path Scan ==={Colors.ENDC}")

        targets = target_manager.get_target_list()

        if not targets:
            print(f"{Colors.WARNING}[!] No targets loaded for batch operation{Colors.ENDC}")
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return

        print(f"{Colors.OKGREEN}[+] Found {len(targets)} targets{Colors.ENDC}")

        # Select scan type
        print(f"\n{Colors.OKCYAN}Select scan type for batch:{Colors.ENDC}")
        print("  1. Admin/Login Paths")
        print("  2. CMS Paths")
        print("  3. API Endpoints")
        print("  4. Sensitive Files")
        print("  5. All Paths")

        scan_choice = input(f"{Colors.OKCYAN}Choice [1-5]: {Colors.ENDC}").strip()

        scan_map = {
            '1': ('admin_paths', 'scan_admin_paths'),
            '2': ('cms_paths', 'scan_cms_paths'),
            '3': ('api_paths', 'scan_api_paths'),
            '4': ('sensitive_paths', 'scan_sensitive_paths'),
            '5': ('all_paths', 'scan_all_paths'),
        }

        if scan_choice not in scan_map:
            print(f"{Colors.FAIL}[!] Invalid choice{Colors.ENDC}")
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return

        scan_type, scan_method = scan_map[scan_choice]

        confirm = input(
            f"{Colors.OKCYAN}Scan {len(targets)} targets? (Y/n): {Colors.ENDC}"
        ).strip()
        if confirm.lower() == "n":
            return

        try:
            all_results = []
            for i, target in enumerate(targets, 1):
                print(f"\n{Colors.HEADER}[{i}/{len(targets)}] Scanning {target}...{Colors.ENDC}")

                try:
                    finder = PathFinder(target, timeout=config['timeout'], proxies=self._get_proxy())
                    method = getattr(finder, scan_method)
                    results = method(callback=self._print_progress)

                    found = results.get('found', [])
                    print(f"\n{Colors.OKGREEN}[+] Found {len(found)} paths{Colors.ENDC}")

                    all_results.append({
                        "target": target,
                        "scan_type": scan_type,
                        "timestamp": datetime.datetime.now().isoformat(),
                        "paths_checked": results['total_checked'],
                        "paths_found": len(found),
                        "found_paths": found
                    })

                except Exception as e:
                    print(f"{Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")
                    all_results.append({
                        "target": target,
                        "error": str(e)
                    })

            # Save batch results
            batch_file = f"batch_pathfinder_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(batch_file, "w") as f:
                json.dump(all_results, f, indent=2)

            # Summary
            print(f"\n{Colors.HEADER}{'=' * 60}{Colors.ENDC}")
            print(f"{Colors.OKGREEN}[+] Batch Scan Complete!{Colors.ENDC}")
            print(f"{Colors.HEADER}{'=' * 60}{Colors.ENDC}")
            print(f"{Colors.OKCYAN}Targets Scanned: {len(targets)}{Colors.ENDC}")

            total_found = sum(r.get('paths_found', 0) for r in all_results if 'paths_found' in r)
            print(f"{Colors.OKCYAN}Total Paths Found: {total_found}{Colors.ENDC}")
            print(f"{Colors.OKCYAN}Results Saved: {batch_file}{Colors.ENDC}")

        except Exception as e:
            print(f"{Colors.FAIL}[!] Batch error: {str(e)}{Colors.ENDC}")

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
