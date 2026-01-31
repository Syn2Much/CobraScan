#!/usr/bin/env python3
"""
Cobra Scan - Main Application
Interactive GUI framework and module loader
"""

import sys
import argparse
import signal
import importlib
import time
from pathlib import Path

# Suppress urllib3 warnings for clean logs
import urllib3

urllib3.disable_warnings()

from helpers.target_manager import TargetManager
from helpers.proxy_manager import ProxyManager
from helpers.utils import Colors, clear_screen
from helpers.report_builder import generate_html_report
from helpers.report_server import serve_reports


class CobraScanner:
    """Interactive GUI Application - Module Loader Framework."""

    def __init__(self):
        self.app_name = "CobraScan"
        self.version = "2.5"
        self.config = {
            "timeout": 10,
            "output_file": "cobra_scan_results.json",
            "auto_save": True,
            "verbose": True,
        }
        self.target_manager = TargetManager()
        self.proxy_manager = ProxyManager()
        self.modules = {}
        self.module_errors = []

        # Set up signal handler for Ctrl+C
        signal.signal(signal.SIGINT, self.signal_handler)

        # Load modules with loading animation
        self._load_modules()

    def _load_modules(self):
        """Automatically discover and load all available modules."""
        modules_path = Path("modules")
        if not modules_path.exists():
            print(f"{Colors.FAIL}[✗] Modules directory not found{Colors.ENDC}")
            return

        # Show loading animation
        print(f"{Colors.OKCYAN}Loading modules{Colors.ENDC}", end="", flush=True)

        loaded = 0
        for module_file in modules_path.glob("*.py"):
            if module_file.stem == "__init__":
                continue

            print(".", end="", flush=True)
            time.sleep(0.1)

            try:
                # Dynamic import
                module_name = f"modules.{module_file.stem}"
                module = importlib.import_module(module_name)

                # Look for Module classes (convention: *Module)
                for attr_name in dir(module):
                    if attr_name.endswith("Module") and not attr_name.startswith("_"):
                        module_class = getattr(module, attr_name)
                        if hasattr(module_class, "__init__"):
                            try:
                                instance = module_class()
                                if hasattr(instance, "name") and hasattr(
                                    instance, "run"
                                ):
                                    self.modules[module_file.stem] = instance
                                    loaded += 1
                                    break
                            except Exception as e:
                                self.module_errors.append(
                                    f"{module_file.stem}: {str(e)}"
                                )
            except Exception as e:
                self.module_errors.append(f"{module_file.stem}: {str(e)}")

        print(f" {Colors.OKGREEN}✓{Colors.ENDC}")
        if self.config.get("verbose"):
            print(f"{Colors.OKGREEN}[✓] Loaded {loaded} module(s){Colors.ENDC}")
            if self.module_errors and loaded == 0:
                print(
                    f"{Colors.WARNING}[!] Errors: {len(self.module_errors)}{Colors.ENDC}"
                )
            time.sleep(0.5)

    def signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully."""
        print(f"\n{Colors.WARNING}[!] Exiting gracefully...{Colors.ENDC}")
        sys.exit(0)

    def print_banner(self):
        """Print the application banner."""
        banner = f"""{Colors.HEADER}               
    ⠀⠀⠀⠀⠀⠀⠀⣀⡠⠤⡒⠂⢀⡈⠉⢉⣉⠉⠉⠓⠲⠦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠐⣶⣉⡥⢤⡖⠚⠉⠙⡿⣈⣀⠩⠝⠛⠓⢦⣄⡀⠙⠳⣤⡀⠀⠀⠀⠀⠀
⠀⠀⠀⠈⠣⠑⠀⢱⠀⠀⡾⣽⣷⠒⢒⣋⣉⣉⣩⣿⣿⣶⣄⠈⠻⣆⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠴⠥⠤⠞⠁⣿⣿⣯⣭⣭⣿⣿⣿⣿⣿⣿⣿⠆⠀⢻⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⢀⡟⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⡠⠋⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⣿⣿⣿⣿⠟⠁⠀⣠⠞⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⣿⣿⠟⠁⠀⡠⠚⠁⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⣿⣿⣿⣿⡿⠃⠀⢠⠞⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⣿⡿⠋⠀⢀⠔⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⣿⡿⠁⠀⢠⠊⠀⠀⠀⢀⣠⠤⠴⢶⡶⠤⢄⡀⠀⠀
⠀⢀⡠⠔⠒⢻⣿⣿⣿⣿⣿⠃⠀⠀⢼⣀⡤⠖⠋⣁⣠⠴⠚⠉⠀⠀⠀⠈⣳⡄
⡞⠉⠑⠒⠒⠚⢿⣿⣿⣿⣿⡄⠀⠀⠘⢿⣉⣉⣉⣁⣀⣀⠠⠤⠄⣒⠾⠟⠛⣇
⠈⠁⠒⠒⠂⠠⠤⠾⠿⠿⠿⠿⣦⣤⣀⣀⣀⣀⣀⡀⠤⠤⠶⠾⠿⠶⠒⠛⠉⠁⠀⠀⠀⠀

             {self.app_name} Version {self.version}    
=====================================================================
{Colors.ENDC}"""
        print(banner)

    def print_status(self):
        """Print current configuration status with enhanced visuals."""
        # Get target info
        target_count = self.target_manager.get_target_count()
        if target_count == 0:
            target_display = f"{Colors.FAIL}No targets loaded{Colors.ENDC}"
        elif target_count == 1:
            target = self.target_manager.get_current_target()
            target_display = f"{Colors.OKGREEN}{target[:40]}{'...' if len(target) > 40 else ''}{Colors.ENDC}"
        else:
            target_display = (
                f"{Colors.OKGREEN}{target_count} targets loaded{Colors.ENDC}"
            )

        # Module count with status indicator
        module_status = f"{Colors.OKGREEN}● {len(self.modules)} active{Colors.ENDC}"
        if self.module_errors:
            module_status += (
                f" {Colors.WARNING}({len(self.module_errors)} errors){Colors.ENDC}"
            )

        # Proxy status
        proxy_count = self.proxy_manager.get_count()
        if proxy_count > 0:
            proxy_display = f"{Colors.OKGREEN}{proxy_count} loaded{Colors.ENDC}"
        else:
            proxy_display = f"{Colors.WARNING}None{Colors.ENDC}"

        status = f"""{Colors.OKCYAN}╔═══════════════════════════════════════════════════════════╗
║                      SYSTEM STATUS                        ║
╠═══════════════════════════════════════════════════════════╣{Colors.ENDC}
{Colors.OKCYAN}║{Colors.ENDC} Target:       {target_display: <62} {Colors.OKCYAN}║{Colors.ENDC}
{Colors.OKCYAN}║{Colors.ENDC} Proxies:      {proxy_display: <62} {Colors.OKCYAN}║{Colors.ENDC}
{Colors.OKCYAN}║{Colors.ENDC} Modules:      {module_status: <77} {Colors.OKCYAN}║{Colors.ENDC}
{Colors.OKCYAN}║{Colors.ENDC} Timeout:      {Colors.OKGREEN}{self.config['timeout']}s{Colors.ENDC}{' ' * 51} {Colors.OKCYAN}║{Colors.ENDC}
{Colors.OKCYAN}║{Colors.ENDC} Output:       {Colors.OKGREEN}{self.config['output_file'][:40]}{Colors.ENDC}{' ' * (51 - len(self.config['output_file'][:40]))} {Colors.OKCYAN}║{Colors.ENDC}
{Colors.OKCYAN}╚═══════════════════════════════════════════════════════════╝{Colors.ENDC}"""

    def print_menu(self):
        """Print the main menu with loaded modules."""
        menu = f"""
{Colors.OKBLUE}Available Modules:{Colors.ENDC}
┌─────────────────────────────────────────────────────────────┐"""

        # Dynamically list loaded modules
        module_num = 1
        for module_key, module in self.modules.items():
            menu += f"\n│ {module_num}. {module.name:<57}│"
            module_num += 1

        # Pad if needed
        while module_num <= 3:
            menu += f"\n│ {' ' * 59}│"
            module_num += 1

        menu += f"""
└─────────────────────────────────────────────────────────────┘

{Colors.OKBLUE}Options:{Colors.ENDC}
┌─────────────────────────────────────────────────────────────┐
│ T.  Load Target (URL/IP or File)                            │
│ P.  Load Proxies (HTTP/HTTPS from File)                     │
│ R.  Results (View / Clear)                                  │
│ C. Configuration & Settings                                 │
│ H. Help & Information                                       │
│ Q. Exit                                                     │
└─────────────────────────────────────────────────────────────┘
        """
        print(menu)

    def get_input(self, prompt, required=True):
        """Get user input with optional validation."""
        while True:
            try:
                value = input(f"{Colors.OKCYAN}{prompt}{Colors.ENDC}")
                if value.strip() or not required:
                    return value.strip()
                if required:
                    print(f"{Colors. FAIL}[!] This field is required. {Colors.ENDC}")
            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}[! ] Operation cancelled.{Colors.ENDC}")
                return None

    def load_target_menu(self):
        """Interactive menu to load single target or file."""
        while True:
            clear_screen()
            self.print_banner()

            print(f"\n{Colors.HEADER}═══ Load Target ═══{Colors.ENDC}\n")

            # Show current target status
            target_count = self.target_manager.get_target_count()
            if target_count > 0:
                if target_count == 1:
                    target = self.target_manager.get_current_target()
                    print(
                        f"{Colors.OKGREEN}[✓] Current target: {target}{Colors.ENDC}\n"
                    )
                else:
                    print(
                        f"{Colors.OKGREEN}[✓] Currently loaded: {target_count} targets{Colors.ENDC}\n"
                    )

            print(f"{Colors.OKBLUE}Options:{Colors.ENDC}")
            print("┌────────────────────────────────────────────────────────────┐")
            print("│ 1. Load Single URL/IP Address                              │")
            print("│ 2. Load Multiple Targets from File                         │")
            print("│ 0. Back to Main Menu                                       │")
            print("└────────────────────────────────────────────────────────────┘\n")

            choice = self.get_input("Select option: ", False)

            if choice == "0":
                break
            elif choice == "1":
                self.load_single_target()
            elif choice == "2":
                self.load_targets_from_file()

    def load_single_target(self):
        """Load a single URL or IP address."""
        print(f"\n{Colors.HEADER}═══ Load Single Target ═══{Colors.ENDC}\n")

        target = self.get_input("Enter URL or IP address: ")
        if not target:
            return

        self.target_manager.load_single_target(target)
        print(f"\n{Colors.OKGREEN}[✓] Target loaded successfully! {Colors.ENDC}")
        print(f"{Colors.OKCYAN}Target:{Colors.ENDC} {target}")

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors. ENDC}")

    def load_targets_from_file(self):
        """Load multiple targets from a text file."""
        print(f"\n{Colors.HEADER}═══ Load Targets from File ═══{Colors.ENDC}\n")

        filename = self.get_input("Enter filename (one URL/IP per line): ")
        if not filename:
            return

        success, message = self.target_manager.load_targets_from_file(filename)

        if success:
            targets = self.target_manager.get_target_list()
            print(f"\n{Colors.OKGREEN}[✓] {message}{Colors.ENDC}")

            # Show preview
            print(f"\n{Colors.OKCYAN}Preview (first 10):{Colors.ENDC}")
            for i, target in enumerate(targets[:10], 1):
                print(f"  {i}. {target}")

            if len(targets) > 10:
                print(f"  ... and {len(targets) - 10} more")
        else:
            print(f"{Colors.FAIL}[✗] {message}{Colors.ENDC}")

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def load_proxy_menu(self):
        """Interactive menu to load proxies from file."""
        while True:
            clear_screen()
            self.print_banner()

            print(f"\n{Colors.HEADER}═══ Load Proxies ═══{Colors.ENDC}\n")

            # Show current proxy status
            proxy_count = self.proxy_manager.get_count()
            if proxy_count > 0:
                print(
                    f"{Colors.OKGREEN}[✓] Currently loaded: {proxy_count} proxies{Colors.ENDC}\n"
                )

            print(f"{Colors.OKBLUE}Options:{Colors.ENDC}")
            print("┌────────────────────────────────────────────────────────────┐")
            print("│ 1. Load Proxies from File                                  │")
            print("│ 2. View Loaded Proxies                                     │")
            print("│ 3. Clear All Proxies                                       │")
            print("│ 0. Back to Main Menu                                       │")
            print("└────────────────────────────────────────────────────────────┘\n")

            choice = self.get_input("Select option: ", False)

            if choice == "0":
                break
            elif choice == "1":
                self.load_proxies_from_file()
            elif choice == "2":
                self.view_loaded_proxies()
            elif choice == "3":
                self.clear_proxies()

    def load_proxies_from_file(self):
        """Load proxies from a text file."""
        print(f"\n{Colors.HEADER}═══ Load Proxies from File ═══{Colors.ENDC}\n")
        print(f"{Colors.OKCYAN}Expected format (one per line):{Colors.ENDC}")
        print("  - ip:port")
        print("  - http://ip:port")
        print("  - https://ip:port")
        print("  - user:pass@ip:port\n")

        filename = self.get_input("Enter proxy file path: ")
        if not filename:
            return

        success, message = self.proxy_manager.load_from_file(filename)

        if success:
            print(f"\n{Colors.OKGREEN}[✓] {message}{Colors.ENDC}")

            # Show preview
            proxies = self.proxy_manager.get_proxy_list()
            print(f"\n{Colors.OKCYAN}Preview (first 5):{Colors.ENDC}")
            for i, proxy in enumerate(proxies[:5], 1):
                print(f"  {i}. {proxy}")

            if len(proxies) > 5:
                print(f"  ... and {len(proxies) - 5} more")
        else:
            print(f"{Colors.FAIL}[✗] {message}{Colors.ENDC}")

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def view_loaded_proxies(self):
        """View all loaded proxies."""
        print(f"\n{Colors.HEADER}═══ Loaded Proxies ═══{Colors.ENDC}\n")

        proxies = self.proxy_manager.get_proxy_list()
        if not proxies:
            print(f"{Colors.WARNING}[!] No proxies loaded{Colors.ENDC}")
        else:
            print(f"{Colors.OKGREEN}Total: {len(proxies)} proxies{Colors.ENDC}\n")
            for i, proxy in enumerate(proxies, 1):
                print(f"  {i}. {proxy}")

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def clear_proxies(self):
        """Clear all loaded proxies."""
        if self.proxy_manager.get_count() == 0:
            print(f"\n{Colors.WARNING}[!] No proxies to clear{Colors.ENDC}")
        else:
            confirm = self.get_input("Clear all proxies? (y/N): ", False)
            if confirm.lower() == "y":
                self.proxy_manager.clear()
                print(f"{Colors.OKGREEN}[✓] All proxies cleared{Colors.ENDC}")

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def configuration_menu(self):
        """Configuration settings menu."""
        import json
        import time

        while True:
            clear_screen()
            self.print_banner()

            print(f"\n{Colors. HEADER}═══ Configuration Settings ═══{Colors.ENDC}")
            print(
                f"""
{Colors.OKCYAN}Current Settings:{Colors.ENDC}
┌────────────────────────────────────────────────────────────┐
│ Timeout:          {self.config['timeout']} seconds{' ' * 36}
│ Output File:      {self.config['output_file']:<44}
│ Auto-Save:        {str(self.config['auto_save']):<44}
│ Verbose:          {str(self.config['verbose']):<44}
└─────────────────────────────────────────────────────────────┘

{Colors.OKBLUE}Configuration Menu:{Colors.ENDC}
┌─────────────────────────────────────────────────────────────┐
│ 1. Change Timeout                                           │
│ 2. Change Output File                                       │
│ 3. Toggle Auto-Save                                         │
│ 4. Toggle Verbose Mode                                      │
│ 5. Save Configuration                                       │
│ 6. Load Configuration                                       │
│ 7. Reset to Defaults                                        │
│ 0. Back to Main Menu                                        │
└─────────────────────────────────────────────────────────────┘
            """
            )

            choice = self.get_input("Select option: ", False)

            if choice == "1":
                new_value = self.get_input(
                    f"Enter timeout in seconds (current: {self.config['timeout']}): ",
                    False,
                )
                if new_value and new_value.isdigit():
                    self.config["timeout"] = int(new_value)
                    print(f"{Colors.OKGREEN}[✓] Timeout updated{Colors.ENDC}")
                    time.sleep(1)
            elif choice == "2":
                new_value = self.get_input(
                    f"Enter output filename (current: {self.config['output_file']}): ",
                    False,
                )
                if new_value:
                    self.config["output_file"] = new_value
                    print(f"{Colors. OKGREEN}[✓] Output file updated{Colors.ENDC}")
                    time.sleep(1)
            elif choice == "3":
                self.config["auto_save"] = not self.config["auto_save"]
                print(
                    f"{Colors.OKGREEN}[✓] Auto-save {'enabled' if self.config['auto_save'] else 'disabled'}{Colors.ENDC}"
                )
                time.sleep(1)
            elif choice == "4":
                self.config["verbose"] = not self.config["verbose"]
                print(
                    f"{Colors. OKGREEN}[✓] Verbose mode {'enabled' if self.config['verbose'] else 'disabled'}{Colors.ENDC}"
                )
                time.sleep(1)
            elif choice == "5":
                self._save_config()
                time.sleep(1)
            elif choice == "6":
                self._load_config()
                time.sleep(1)
            elif choice == "7":
                confirm = self.get_input(
                    "Reset all settings to defaults? (y/N): ", False
                )
                if confirm.lower() == "y":
                    self.config = {
                        "timeout": 10,
                        "output_file": "recon_results.json",
                        "auto_save": True,
                        "verbose": True,
                    }
                    print(
                        f"{Colors.OKGREEN}[✓] Settings reset to defaults{Colors.ENDC}"
                    )
                    time.sleep(1)
            elif choice == "0":
                break
            else:
                print(f"{Colors.FAIL}[✗] Invalid option{Colors.ENDC}")
                time.sleep(1)

    def _save_config(self):
        """Save configuration to file."""
        import json

        try:
            with open("cobra_config.json", "w") as f:
                json.dump(self.config, f, indent=2)
            print(f"{Colors.OKGREEN}[✓] Configuration saved{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error saving config: {str(e)}{Colors.ENDC}")

    def _load_config(self):
        """Load configuration from file."""
        import json
        import os

        try:
            if os.path.exists("cobra_config.json"):
                with open("cobra_config.json", "r") as f:
                    self.config = json.load(f)
                print(f"{Colors. OKGREEN}[✓] Configuration loaded{Colors.ENDC}")
            else:
                print(f"{Colors.WARNING}[! ] No config file found{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors. FAIL}[✗] Error loading config: {str(e)}{Colors.ENDC}")

    def show_help(self):
        """Show help information."""
        help_text = f"""
{Colors.HEADER}═══ Help Information ═══{Colors.ENDC}

{Colors.OKBLUE}About Cobra Scanner:{Colors.ENDC}
Advanced reconnaissance tool for analyzing websites and web applications.

{Colors.OKBLUE}Module Structure:{Colors.ENDC}
• web_analyzer.py    - Core scanning functionality
• target_manager.py  - Target loading and management
• utils.py           - Helper functions and utilities
• main.py            - Interactive GUI application

{Colors.OKBLUE}Loading Targets:{Colors.ENDC}
Option T - Load Target
  • Load Single URL/IP:   Enter one target to scan
  • Load from File:  Multiple targets (one per line)

{Colors.OKBLUE}Using Modules:{Colors.ENDC}
Select a module number from the main menu to load it. 
Each module has its own menu with specific scan options.

{Colors.OKBLUE}Keyboard Shortcuts:{Colors.ENDC}
• Ctrl+C:  Exit gracefully
• T: Load targets
• C: Configuration
• H: Help
• Q:  Quit

{Colors.WARNING}⚠️  Use responsibly and ethically{Colors.ENDC}
        """

        print(help_text)
        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def results_menu(self):
        """View or clear persistent JSON results."""
        import json, os

        while True:
            clear_screen()
            self.print_banner()

            print(f"\n{Colors.HEADER}═══ Results Manager ═══{Colors.ENDC}\n")
            output_file = self.config.get("output_file", "cobra_scan_results.json")
            print(f"{Colors.OKCYAN}Current results file:{Colors.ENDC} {output_file}\n")

            # Load current results
            results = []
            try:
                if os.path.exists(output_file):
                    with open(output_file, "r") as f:
                        results = json.load(f)
                if not isinstance(results, list):
                    results = [results]
            except Exception:
                results = []

            print(f"{Colors.OKGREEN}Entries:{Colors.ENDC} {len(results)}\n")
            print(f"{Colors.OKBLUE}Options:{Colors.ENDC}")
            print("┌────────────────────────────────────────────────────────────┐")
            print("│ 1. View Summary                                            │")
            print("│ 2. Clear All Results                                       │")
            print("│ 3. Generate HTML Security Report                           │")
            print("│ 4. Host Reports via Flask (static server)                  │")
            print("│ 0. Back to Main Menu                                       │")
            print("└────────────────────────────────────────────────────────────┘\n")

            choice = self.get_input("Select option: ", False)
            if choice == "0":
                break
            elif choice == "1":
                self._view_results_summary(results)
            elif choice == "2":
                self._clear_results_file(output_file)
            elif choice == "3":
                self._generate_html_report(results)
            elif choice == "4":
                self._host_reports_server()

    def _view_results_summary(self, results):
        """Show a concise summary of saved results."""
        import pprint

        if not results:
            print(f"\n{Colors.WARNING}[!] No results saved yet{Colors.ENDC}")
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return
        print(f"\n{Colors.OKCYAN}Showing up to 5 recent entries:{Colors.ENDC}\n")
        for i, entry in enumerate(results[-5:], 1):
            # Print minimal info
            if isinstance(entry, dict):
                scan_info = entry.get("scan_info") or {}
                if scan_info:
                    print(
                        f"[{i}] {scan_info.get('hostname', scan_info.get('url', 'N/A'))} - {scan_info.get('proxy_mode', 'N/A')} ({scan_info.get('proxy_used', 'N/A')})"
                    )
                else:
                    label = entry.get("target", entry.get("domain", "N/A"))
                    stype = entry.get("scan_type", "N/A")
                    proxies = entry.get("proxies_used") or entry.get("proxy_used")
                    if isinstance(proxies, list):
                        proxies = ",".join(proxies[:3]) + (
                            "..." if len(proxies) > 3 else ""
                        )
                    print(
                        f"[{i}] {label} - {stype} {('[' + str(proxies) + ']') if proxies else ''}"
                    )
            else:
                pprint.pprint(entry)
        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _clear_results_file(self, output_file):
        """Clear the results JSON file (reset to empty list)."""
        import json

        confirm = self.get_input(
            "This will delete all saved results. Confirm? (y/N): ", False
        )
        if confirm and confirm.lower() == "y":
            try:
                with open(output_file, "w") as f:
                    json.dump([], f, indent=2)
                print(
                    f"{Colors.OKGREEN}[✓] Results cleared: {output_file}{Colors.ENDC}"
                )
            except Exception as e:
                print(f"{Colors.FAIL}[✗] Failed to clear: {str(e)}{Colors.ENDC}")
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
        else:
            print(f"{Colors.OKCYAN}Cancelled{Colors.ENDC}")
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _generate_html_report(self, results):
        """Generate stylized HTML reports grouped by target."""
        if not results:
            print(f"\n{Colors.WARNING}[!] No results to include in report{Colors.ENDC}")
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return

        try:
            output = generate_html_report(results)
            print(f"\n{Colors.OKGREEN}[✓] Reports generated in: reports/{Colors.ENDC}")
            print(f"{Colors.OKCYAN}    Index: {output}{Colors.ENDC}")

            # Count unique targets
            targets = set()
            for entry in results:
                si = entry.get("scan_info") or {}
                t = (
                    si.get("hostname")
                    or si.get("url")
                    or entry.get("target")
                    or entry.get("domain")
                )
                if t:
                    targets.add(t)
            print(
                f"{Colors.OKCYAN}    Generated {len(targets)} target report(s){Colors.ENDC}"
            )
        except Exception as e:
            print(
                f"\n{Colors.FAIL}[✗] Failed to generate report: {str(e)}{Colors.ENDC}"
            )

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _host_reports_server(self):
        """Run a lightweight Flask server to host generated reports."""
        from pathlib import Path

        report_dir = Path("reports")
        report_dir.mkdir(parents=True, exist_ok=True)

        port_input = self.get_input("Enter port to serve on [5000]: ", False)
        try:
            port = int(port_input) if port_input else 5000
        except ValueError:
            port = 5000

        host = self.get_input("Enter bind address [0.0.0.0]: ", False) or "0.0.0.0"

        print(f"\n{Colors.OKBLUE}Starting report server...{Colors.ENDC}")

        try:
            serve_reports(str(report_dir), host=host, port=port)
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}Server stopped.{Colors.ENDC}")
        except Exception as e:
            print(f"\n{Colors.FAIL}[✗] Server error: {str(e)}{Colors.ENDC}")

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def run(self):
        """Main interactive loop."""
        try:
            self._load_config()

            while True:
                clear_screen()
                self.print_banner()
                self.print_status()
                self.print_menu()

                choice = self.get_input("Select option: ", False).upper()

                if choice == "T":
                    self.load_target_menu()
                elif choice == "P":
                    self.load_proxy_menu()
                elif choice == "R":
                    self.results_menu()
                elif choice.isdigit():
                    # Load module by number
                    module_num = int(choice)
                    module_list = list(self.modules.values())
                    if 1 <= module_num <= len(module_list):
                        selected_module = module_list[module_num - 1]
                        selected_module.run(
                            self.config, self.target_manager, self.proxy_manager
                        )
                    else:
                        print(f"{Colors.FAIL}[✗] Invalid module number{Colors. ENDC}")
                        import time

                        time.sleep(1)
                elif choice == "C":
                    self.configuration_menu()
                elif choice == "H":
                    self.show_help()
                elif choice == "Q":
                    print(f"{Colors.OKCYAN}Goodbye!{Colors.ENDC}")
                    break
                else:
                    print(f"{Colors.FAIL}[✗] Invalid option{Colors.ENDC}")
                    import time

                    time.sleep(1)

        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Exiting... {Colors.ENDC}")
            sys.exit(0)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Cobra Scanner - Advanced Web Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Launch interactive mode (default)",
    )

    args = parser.parse_args()

    app = CobraScanner()
    app.run()


if __name__ == "__main__":
    main()
