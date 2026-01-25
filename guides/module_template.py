#!/usr/bin/env python3
"""
[MODULE NAME] Module
[Brief description of what this module does]
"""

import time
import json
import datetime

from helpers.utils import Colors, clear_screen


class ModuleTemplate:
    """
    Template for creating new modules.

    To create a new module:
    1. Copy this file and rename it (e.g., port_scanner.py)
    2. Update the class name (e.g., PortScannerModule)
    3. Update self.name and self.description
    4. Implement your scan functions
    5. Update the menu options
    6. Add to main. py _load_modules()
    """

    def __init__(self):
        self.name = "Cobra Module Template"  # Change this to your module name
        self.version = "1.0.0"
        self.description = "Demo module template for creating new modules"

    def run(self, config, target_manager, proxy_manager=None):
        """
        Main entry point for the module.
        This is called from main.py when user selects this module.

        Args:
            config: Configuration dict with timeout, output_file, etc.
            target_manager: TargetManager instance for target handling
            proxy_manager: ProxyManager instance for HTTP proxy rotation (optional)
        """
        self.proxy_manager = proxy_manager
        while True:
            clear_screen()
            self._print_module_banner()
            self._print_module_status(config, target_manager)
            self._print_module_menu()

            choice = input(f"{Colors.OKCYAN}Select option:  {Colors.ENDC}").strip()

            # Map choices to functions
            if choice == "1":
                self._demo_scan_1(config, target_manager)
            elif choice == "2":
                self._demo_scan_2(config, target_manager)
            elif choice == "3":
                self._demo_scan_3(config, target_manager)
            elif choice == "4":
                self._demo_scan_4(config, target_manager)
            elif choice == "5":
                self._batch_operation(config, target_manager)
            elif choice.upper() == "B" or choice == "0":
                break  # Return to main menu
            else:
                print(f"{Colors. FAIL}[✗] Invalid option{Colors.ENDC}")
                time.sleep(1)

    # ==================== UI/DISPLAY FUNCTIONS ====================

    def _print_module_banner(self):
        """Print the module banner with ASCII art or title."""
        banner = f"""
{Colors.HEADER}═══════════════════════════════════════════════════════════════
                    {self.name. upper()}
                         v{self.version}
═══════════════════════════════════════════════════════════════{Colors.ENDC}
        """
        print(banner)

    def _print_module_status(self, config, target_manager):
        """Print current module status and configuration."""
        target_display = target_manager.get_status_string()
        target_count = len(target_manager.get_target_list())

        status = f"""{Colors.OKCYAN}Module Status:{Colors. ENDC}
┌─────────────────────────────────────────────────────────────┐
│ Current Target:      {target_display: <45}│
│ Loaded Targets:   {target_count: <47}│
│ Timeout:          {config['timeout']} seconds{' ' * 36}│
│ Output File:      {config['output_file']: <44}│
└─────────────────────────────────────────────────────────────┘"""
        print(status)

    def _print_module_menu(self):
        """Print the module menu options."""
        menu = f"""
{Colors. OKBLUE}Available Operations:{Colors.ENDC}
┌─────────────────────────────────────────────────────────────┐
│ 1.  Demo Scan Option 1                                       │
│ 2. Demo Scan Option 2                                       │
│ 3. Demo Scan Option 3                                       │
│ 4. Demo Scan Option 4                                       │
│ 5. Batch Operation (All Targets)                            │
│                                                             │
│ B. Back to Main Menu                                        │
└─────────────────────────────────────────────────────────────┘
        """
        print(menu)

    # ==================== HELPER FUNCTIONS ====================

    def _get_target(self, target_manager):
        """
        Get target for scanning with intelligent selection.
        Handles single target, target list, or new input.
        """
        current = target_manager.get_current_target()
        target_list = target_manager.get_target_list()

        if current:
            return current
        elif target_list:
            print(
                f"{Colors.WARNING}[!] You have {len(target_list)} targets loaded from file. {Colors.ENDC}"
            )
            print(
                f"{Colors.WARNING}[!] Use 'Batch Operation' (option 5) to scan all targets.{Colors.ENDC}"
            )

            choice = (
                input(
                    f"{Colors. OKCYAN}Enter target number to scan (or 'N' for new): {Colors.ENDC}"
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
            print(
                f"{Colors.WARNING}[! ] No target loaded.  Please load a target first.{Colors. ENDC}"
            )
            choice = input(
                f"{Colors. OKCYAN}Enter a target now?  (Y/n): {Colors.ENDC}"
            ).strip()
            if choice.lower() != "n":
                target = input(
                    f"{Colors. OKCYAN}Enter target URL or hostname: {Colors.ENDC}"
                ).strip()
                if target:
                    target_manager.load_single_target(target)
                return target
            return None

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

            print(f"{Colors.OKGREEN}[✓] Results saved to {output_file}{Colors.ENDC}")

        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error saving to JSON: {str(e)}{Colors.ENDC}")

    def _print_progress(self, current, total, message=""):
        """Print progress bar or status."""
        percentage = (current / total) * 100
        bar_length = 40
        filled = int(bar_length * current / total)
        bar = "█" * filled + "░" * (bar_length - filled)

        print(
            f"\r{Colors.OKCYAN}[{bar}] {percentage:.1f}% {message}{Colors.ENDC}",
            end="",
            flush=True,
        )

        if current == total:
            print()  # New line when complete

    # ==================== SCAN FUNCTIONS ====================

    def _demo_scan_1(self, config, target_manager):
        """
        Demo Scan Option 1
        Replace this with your actual scan functionality.
        """
        print(f"\n{Colors.HEADER}═══ Demo Scan 1 ═══{Colors.ENDC}")

        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors. ENDC}")
            return

        print(f"{Colors. WARNING}[*] Running Demo Scan 1 on {target}...{Colors.ENDC}")

        try:
            # Simulate scanning with progress
            steps = 5
            for i in range(1, steps + 1):
                time.sleep(0.5)
                self._print_progress(i, steps, f"Processing step {i}/{steps}")

            # Demo results
            result = {
                "target": target,
                "scan_type": "Demo Scan 1",
                "timestamp": datetime.datetime.now().isoformat(),
                "status": "success",
                "data": {
                    "demo_field_1": "Demo Value 1",
                    "demo_field_2": "Demo Value 2",
                    "demo_metric": 42,
                },
            }

            print(f"\n{Colors. OKGREEN}[✓] Scan Complete!{Colors.ENDC}\n")
            print(json.dumps(result, indent=2))

            # Optionally save results
            if config.get("auto_save"):
                self._save_results(result, config["output_file"])

        except Exception as e:
            print(f"{Colors. FAIL}[✗] Error:  {str(e)}{Colors.ENDC}")

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _demo_scan_2(self, config, target_manager):
        """Demo Scan Option 2"""
        print(f"\n{Colors. HEADER}═══ Demo Scan 2 ═══{Colors.ENDC}")

        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors. ENDC}")
            return

        print(f"{Colors.WARNING}[*] Running Demo Scan 2 on {target}...{Colors.ENDC}")

        try:
            # Simulate different output format
            print(f"\n{Colors.OKGREEN}[✓] Scan Complete! {Colors.ENDC}\n")

            print(f"{Colors. OKCYAN}Demo Result 1:{Colors.ENDC} ✓ Pass")
            print(f"{Colors.OKCYAN}Demo Result 2:{Colors.ENDC} ✗ Fail")
            print(f"{Colors.OKCYAN}Demo Result 3:{Colors. ENDC} ⚠ Warning")
            print(f"{Colors.OKCYAN}Demo Metric:{Colors.ENDC} 99.9%")

        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error: {str(e)}{Colors.ENDC}")

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors. ENDC}")

    def _demo_scan_3(self, config, target_manager):
        """Demo Scan Option 3"""
        print(f"\n{Colors.HEADER}═══ Demo Scan 3 ═══{Colors.ENDC}")

        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return

        print(f"{Colors.WARNING}[*] Running Demo Scan 3 on {target}...{Colors.ENDC}")

        try:
            # Simulate table output
            print(f"\n{Colors.OKGREEN}[✓] Scan Complete!{Colors.ENDC}\n")

            print(
                f"{Colors.OKCYAN}{'Item':<20} {'Status':<15} {'Value':<20}{Colors.ENDC}"
            )
            print("─" * 60)
            print(
                f"{'Demo Item 1':<20} {Colors.OKGREEN}{'Active':<15}{Colors.ENDC} {'100':<20}"
            )
            print(
                f"{'Demo Item 2': <20} {Colors.FAIL}{'Inactive':<15}{Colors.ENDC} {'0':<20}"
            )
            print(
                f"{'Demo Item 3':<20} {Colors.WARNING}{'Pending':<15}{Colors. ENDC} {'50':<20}"
            )

        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error: {str(e)}{Colors.ENDC}")

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors. ENDC}")

    def _demo_scan_4(self, config, target_manager):
        """Demo Scan Option 4 - Interactive scan with user input"""
        print(f"\n{Colors.HEADER}═══ Demo Scan 4 - Interactive ═══{Colors. ENDC}")

        target = self._get_target(target_manager)
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return

        # Get additional user input
        print(f"\n{Colors.OKCYAN}Additional Options:{Colors.ENDC}")
        depth = (
            input(f"{Colors. OKCYAN}Enter scan depth (1-10) [5]: {Colors.ENDC}").strip()
            or "5"
        )
        verbose = (
            input(f"{Colors. OKCYAN}Verbose output?  (y/N): {Colors.ENDC}")
            .strip()
            .lower()
            == "y"
        )

        print(
            f"\n{Colors.WARNING}[*] Running interactive scan on {target}...{Colors. ENDC}"
        )
        print(f"{Colors.WARNING}[*] Depth: {depth}, Verbose: {verbose}{Colors.ENDC}")

        try:
            # Simulate scan
            time.sleep(1)

            print(f"\n{Colors. OKGREEN}[✓] Scan Complete!{Colors.ENDC}\n")
            print(f"{Colors.OKCYAN}Scan depth:{Colors.ENDC} {depth}")
            print(f"{Colors. OKCYAN}Results found:{Colors.ENDC} {int(depth) * 3}")

            if verbose:
                print(f"\n{Colors.OKCYAN}Verbose Details:{Colors.ENDC}")
                print("  - Detail 1: Some information")
                print("  - Detail 2: More information")
                print("  - Detail 3: Additional data")

        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error: {str(e)}{Colors.ENDC}")

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")

    def _batch_operation(self, config, target_manager):
        """
        Batch operation on all loaded targets.
        Useful for scanning multiple targets at once.
        """
        print(f"\n{Colors.HEADER}═══ Batch Operation ═══{Colors.ENDC}")

        targets = target_manager.get_target_list()

        if not targets:
            print(
                f"{Colors.WARNING}[!] No targets available for batch operation{Colors.ENDC}"
            )
            input(f"\n{Colors.WARNING}Press Enter to continue... {Colors.ENDC}")
            return

        print(f"{Colors. OKGREEN}[✓] Found {len(targets)} targets{Colors.ENDC}")
        print(f"{Colors.WARNING}[*] Starting batch operation... {Colors.ENDC}\n")

        confirm = input(
            f"{Colors. OKCYAN}Process all {len(targets)} targets? (Y/n): {Colors.ENDC}"
        ).strip()
        if confirm.lower() == "n":
            return

        try:
            results = []
            for i, target in enumerate(targets, 1):
                print(f"\n[{i}/{len(targets)}] Processing {target}...")

                try:
                    # Simulate operation
                    time.sleep(0.5)

                    result = {
                        "target": target,
                        "scan_type": "Batch Demo",
                        "timestamp": datetime.datetime.now().isoformat(),
                        "status": "success",
                        "data": {"demo": "value"},
                    }

                    results.append(result)
                    print(f"{Colors.OKGREEN}[✓] Complete{Colors.ENDC}")

                except Exception as e:
                    print(f"{Colors.FAIL}[✗] Failed: {str(e)}{Colors.ENDC}")
                    results.append({"target": target, "error": str(e)})

            # Save all results
            batch_file = f"batch_{self.name. lower().replace(' ', '_')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(batch_file, "w") as f:
                json.dump(results, f, indent=2)

            print(f"\n{Colors.OKGREEN}[✓] Batch operation complete!{Colors.ENDC}")
            print(f"{Colors. OKCYAN}Results saved to: {batch_file}{Colors. ENDC}")
            print(
                f"{Colors.OKCYAN}Successful:  {len([r for r in results if 'error' not in r])}/{len(results)}{Colors.ENDC}"
            )

        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error: {str(e)}{Colors.ENDC}")

        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors. ENDC}")


# ==================== CORE FUNCTIONALITY CLASS ====================


class DemoCore:
    """
    Separate class for core functionality.
    Keep scanning logic separate from UI/presentation.
    """

    def __init__(self, target, timeout=10):
        self.target = target
        self.timeout = timeout

    def perform_scan(self):
        """Your actual scan logic here."""
        # Implement actual scanning functionality
        time.sleep(1)  # Simulate work

        return {
            "target": self.target,
            "result": "Demo result",
            "timestamp": datetime.datetime.now().isoformat(),
        }

    def analyze_data(self, data):
        """Analyze collected data."""
        # Implement analysis logic
        pass

    def generate_report(self, data):
        """Generate formatted report."""
        # Implement report generation
        pass
