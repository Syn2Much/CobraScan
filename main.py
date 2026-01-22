#!/usr/bin/env python3
"""
Web Analyzer Pro - Main Application
Interactive GUI for web reconnaissance
"""

import sys
import argparse
import time
import json
import datetime
import signal

from web_analyzer import WebAnalyzer
from target_manager import TargetManager
from utils import Colors, clear_screen


class WebAnalyzerApp: 
    """Interactive GUI Application for Web Analysis."""
    
    def __init__(self):
        self.app_name = "Web Analyzer Pro"
        self.version = "2.0.0"
        self.config = {
            'timeout': 10,
            'output_file': 'recon_results.json',
            'auto_save': True,
            'verbose': True
        }
        self.target_manager = TargetManager()
        
        # Set up signal handler for Ctrl+C
        signal.signal(signal.SIGINT, self.signal_handler)
        
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully."""
        print(f"\n{Colors. WARNING}[!] Exiting gracefully...{Colors.ENDC}")
        sys.exit(0)
    
    def print_banner(self):
        """Print the application banner."""
        banner = f"""{Colors.HEADER}               

    ███████                                ███   █████████                               
  ███░░░░░███                             ░░░   ███░░░░░███                              
 ███     ░░███ █████████████   ████████   ████ ░███    ░░░   ██████   ██████   ████████  
░███      ░███░░███░░███░░███ ░░███░░███ ░░███ ░░█████████  ███░░███ ░░░░░███ ░░███░░███ 
░███      ░███ ░███ ░███ ░███  ░███ ░███  ░███  ░░░░░░░░███░███ ░░░   ███████  ░███ ░███ 
░░███     ███  ░███ ░███ ░███  ░███ ░███  ░███  ███    ░███░███  ███ ███░░███  ░███ ░███ 
 ░░░███████░   █████░███ █████ ████ █████ █████░░█████████ ░░██████ ░░████████ ████ █████
   ░░░░░░░    ░░░░░ ░░░ ░░░░░ ░░░░ ░░░░░ ░░░░░  ░░░░░░░░░   ░░░░░░   ░░░░░░░░ ░░░░ ░░░░░    Version {self.version}     
   ════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
                                                                                      
              {Colors.ENDC}                                                                                                                                                              
        """
        print(banner)
        
    def print_status(self):
        """Print current configuration status."""
        target_display = self.target_manager.get_status_string()
            
        status = f"""
{Colors.OKCYAN}Current Status:{Colors.ENDC}
┌─────────────────────────────────────────────────────────────┐
│ Current Target:    {target_display: <45} │
│ Timeout:          {self.config['timeout']} seconds{' ' * 36} │
│ Output File:      {self.config['output_file']: <44} │
│ Auto-Save:        {str(self.config['auto_save']):<44} │
└─────────────────────────────────────────────────────────────┘
        """
        print(status)
    
    def print_menu(self):
        """Print the main menu."""
        menu = f"""
{Colors.OKBLUE}Main Menu:{Colors.ENDC}
┌─────────────────────────────────────────────────────────────┐
│ T.  Load Target (URL/IP or File)                             │
│                                                             │
│ 1. Quick Scan (Basic HTTP Info)                            │
│ 2. DNS Reconnaissance                                       │
│ 3. IP & Geolocation Info                                    │
│ 4. SSL/TLS Certificate Analysis                            │
│ 5. Security Headers Analysis                               │
│ 6. Port Scanning                                           │
│ 7. Technology Detection                                     │
│ 8. Full Reconnaissance Scan (Save to JSON)                 │
│ 9. Batch Scan from Loaded Targets                          │
│                                                             │
│ C. Configuration & Settings                                │
│ H. Help & Information                                      │
│ Q. Exit                                                     │
└─────────────────────────────────────────────────────────────┘
        """
        print(menu)
    
    def get_input(self, prompt, required=True):
        """Get user input with optional validation."""
        while True:
            try:
                value = input(f"{Colors.OKCYAN}{prompt}{Colors.ENDC}")
                if value. strip() or not required:
                    return value. strip()
                if required: 
                    print(f"{Colors. FAIL}[!] This field is required. {Colors.ENDC}")
            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}[! ] Operation cancelled.{Colors.ENDC}")
                return None
    
    def load_target_menu(self):
        """Interactive menu to load single target or file."""
        clear_screen()
        self.print_banner()
        
        print(f"\n{Colors.HEADER}═══ Load Target ═══{Colors. ENDC}\n")
        print(f"{Colors.OKBLUE}Options:{Colors.ENDC}")
        print("┌─────────────────────────────────────────────────────────────┐")
        print("│ 1. Load Single URL/IP Address                              │")
        print("│ 2. Load Multiple Targets from File                         │")
        print("│ 0. Back to Main Menu                                        │")
        print("└─────────────────────────────────────────────────────────────┘\n")
        
        choice = self.get_input("Select option:  ", False)
        
        if choice == '1':
            self.load_single_target()
        elif choice == '2': 
            self.load_targets_from_file()
        elif choice == '0':
            return
        else:
            print(f"{Colors.FAIL}[✗] Invalid option{Colors.ENDC}")
            time.sleep(1)
    
    def load_single_target(self):
        """Load a single URL or IP address."""
        print(f"\n{Colors.HEADER}═══ Load Single Target ═══{Colors. ENDC}\n")
        
        target = self.get_input("Enter URL or IP address: ")
        if not target:
            return
        
        try:
            # Test if it's a valid URL/hostname
            analyzer = WebAnalyzer(target, timeout=self.config['timeout'])
            self.target_manager.load_single_target(target)
            
            print(f"\n{Colors.OKGREEN}[✓] Target loaded successfully! {Colors.ENDC}")
            print(f"{Colors. OKCYAN}Target:{Colors.ENDC} {target}")
            print(f"{Colors.OKCYAN}Hostname:{Colors.ENDC} {analyzer.hostname}")
            
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Invalid target: {str(e)}{Colors.ENDC}")
        
        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors. ENDC}")
    
    def load_targets_from_file(self):
        """Load multiple targets from a text file."""
        print(f"\n{Colors. HEADER}═══ Load Targets from File ═══{Colors.ENDC}\n")
        
        filename = self.get_input("Enter filename (one URL/IP per line): ")
        if not filename:
            return
        
        success, message = self.target_manager. load_targets_from_file(filename)
        
        if success:
            targets = self.target_manager.get_target_list()
            print(f"\n{Colors. OKGREEN}[✓] {message}{Colors.ENDC}")
            
            # Show preview
            print(f"\n{Colors.OKCYAN}Preview (first 10):{Colors.ENDC}")
            for i, target in enumerate(targets[:10], 1):
                print(f"  {i}. {target}")
            
            if len(targets) > 10:
                print(f"  ... and {len(targets) - 10} more")
        else:
            print(f"{Colors.FAIL}[✗] {message}{Colors.ENDC}")
        
        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
    
    def get_target(self):
        """Get target for scanning."""
        current = self.target_manager.get_current_target()
        target_list = self.target_manager.get_target_list()
        
        if current:
            return current
        elif target_list: 
            print(f"{Colors.WARNING}[!] You have {len(target_list)} targets loaded from file. {Colors.ENDC}")
            print(f"{Colors.WARNING}[!] Use 'Batch Scan' (option 9) to scan all targets.{Colors.ENDC}")
            
            choice = self.get_input("Enter target number to scan (or 'N' for new): ", False).upper()
            
            if choice == 'N':
                target = self.get_input("Enter target URL or hostname: ")
                return target
            elif choice. isdigit():
                idx = int(choice) - 1
                target = self.target_manager.get_target_by_index(idx)
                if target:
                    return target
                else:
                    print(f"{Colors.FAIL}[✗] Invalid target number{Colors.ENDC}")
                    time.sleep(1)
                    return None
            else:
                return None
        else:
            print(f"{Colors.WARNING}[!] No target loaded.  Please load a target first (option T).{Colors.ENDC}")
            choice = self.get_input("Enter a target now?  (Y/n): ", False)
            if choice.lower() != 'n':
                target = self.get_input("Enter target URL or hostname: ")
                if target:
                    self.target_manager.load_single_target(target)
                return target
            return None
    
    def print_result(self, title, data):
        """Pretty print results."""
        print(f"\n{Colors.HEADER}═══ {title} ═══{Colors.ENDC}\n")
        print(json.dumps(data, indent=2))
        print()
    
    def quick_scan(self):
        """Perform quick scan."""
        print(f"\n{Colors.HEADER}═══ Quick Scan ═══{Colors.ENDC}")
        
        target = self.get_target()
        if not target: 
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors. ENDC}")
            return
        
        try:
            print(f"{Colors.WARNING}[*] Scanning {target}...{Colors.ENDC}")
            analyzer = WebAnalyzer(target, timeout=self.config['timeout'])
            result = analyzer.quick_scan()
            
            print(f"\n{Colors.OKGREEN}[✓] Scan Complete!{Colors.ENDC}\n")
            print(f"{Colors.OKCYAN}URL:{Colors.ENDC} {result['url']}")
            print(f"{Colors.OKCYAN}Hostname:{Colors.ENDC} {result['hostname']}")
            print(f"{Colors.OKCYAN}Status:{Colors. ENDC} {result['status_code']} {result['reason']}")
            print(f"{Colors.OKCYAN}Response Time:{Colors.ENDC} {result['elapsed_seconds']:.3f}s")
            print(f"{Colors.OKCYAN}Content Length:{Colors.ENDC} {result['content_length']} bytes")
            print(f"{Colors.OKCYAN}Encoding:{Colors.ENDC} {result['encoding']}")
            print(f"{Colors.OKCYAN}Server:{Colors.ENDC} {result['server']}")
            
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error:  {str(e)}{Colors.ENDC}")
        
        input(f"\n{Colors. WARNING}Press Enter to continue...{Colors.ENDC}")
    
    def dns_recon(self):
        """Perform DNS reconnaissance."""
        print(f"\n{Colors.HEADER}═══ DNS Reconnaissance ═══{Colors.ENDC}")
        
        target = self. get_target()
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return
        
        try:
            print(f"{Colors.WARNING}[*] Performing DNS lookup for {target}...{Colors. ENDC}")
            analyzer = WebAnalyzer(target, timeout=self.config['timeout'])
            result = analyzer.get_dns_info()
            
            print(f"\n{Colors.OKGREEN}[✓] DNS Lookup Complete!{Colors.ENDC}\n")
            self.print_result("DNS Information", result)
            
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error: {str(e)}{Colors.ENDC}")
        
        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors. ENDC}")
    
    def ip_info(self):
        """Get IP and geolocation info."""
        print(f"\n{Colors.HEADER}═══ IP & Geolocation Info ═══{Colors.ENDC}")
        
        target = self.get_target()
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors. ENDC}")
            return
        
        try:
            print(f"{Colors.WARNING}[*] Resolving IP and geolocation for {target}... {Colors.ENDC}")
            analyzer = WebAnalyzer(target, timeout=self.config['timeout'])
            result = analyzer. get_ip_info()
            
            print(f"\n{Colors.OKGREEN}[✓] IP Lookup Complete!{Colors.ENDC}\n")
            self.print_result("IP Information", result)
            
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error: {str(e)}{Colors.ENDC}")
        
        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
    
    def ssl_analysis(self):
        """Analyze SSL/TLS certificate."""
        print(f"\n{Colors.HEADER}═══ SSL/TLS Certificate Analysis ═══{Colors. ENDC}")
        
        target = self.get_target()
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return
        
        try:
            print(f"{Colors.WARNING}[*] Analyzing SSL certificate for {target}...{Colors. ENDC}")
            analyzer = WebAnalyzer(target, timeout=self.config['timeout'])
            result = analyzer.get_ssl_info()
            
            print(f"\n{Colors.OKGREEN}[✓] SSL Analysis Complete!{Colors. ENDC}\n")
            self.print_result("SSL/TLS Information", result)
            
            if 'days_until_expiry' in result:
                days = result['days_until_expiry']
                if days < 30:
                    print(f"{Colors.FAIL}[! ] WARNING: Certificate expires in {days} days! {Colors.ENDC}")
                elif days < 90:
                    print(f"{Colors.WARNING}[! ] Certificate expires in {days} days{Colors.ENDC}")
                else:
                    print(f"{Colors.OKGREEN}[✓] Certificate valid for {days} days{Colors. ENDC}")
            
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error: {str(e)}{Colors.ENDC}")
        
        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors. ENDC}")
    
    def headers_analysis(self):
        """Analyze security headers."""
        print(f"\n{Colors.HEADER}═══ Security Headers Analysis ═══{Colors.ENDC}")
        
        target = self.get_target()
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return
        
        try:
            print(f"{Colors.WARNING}[*] Analyzing security headers for {target}... {Colors.ENDC}")
            analyzer = WebAnalyzer(target, timeout=self.config['timeout'])
            result = analyzer. analyze_headers()
            
            print(f"\n{Colors. OKGREEN}[✓] Headers Analysis Complete!{Colors.ENDC}\n")
            
            for header, info in result.items():
                status = f"{Colors.OKGREEN}✓ Present" if info['present'] else f"{Colors.FAIL}✗ Missing"
                print(f"{Colors.OKCYAN}{header}:{Colors.ENDC} {status}{Colors.ENDC}")
                if info['present'] and info['value']:
                    print(f"  Value: {info['value'][: 80]}...")
            
        except Exception as e: 
            print(f"{Colors. FAIL}[✗] Error:  {str(e)}{Colors.ENDC}")
        
        input(f"\n{Colors. WARNING}Press Enter to continue...{Colors.ENDC}")
    
    def port_scan(self):
        """Scan common ports."""
        print(f"\n{Colors.HEADER}═══ Port Scanning ═══{Colors.ENDC}")
        
        target = self.get_target()
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors. ENDC}")
            return
        
        try:
            print(f"{Colors.WARNING}[*] Scanning common ports for {target}...{Colors.ENDC}")
            print(f"{Colors.WARNING}[*] This may take a moment... {Colors.ENDC}")
            analyzer = WebAnalyzer(target, timeout=self.config['timeout'])
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
    
    def tech_detection(self):
        """Detect technologies."""
        print(f"\n{Colors.HEADER}═══ Technology Detection ═══{Colors.ENDC}")
        
        target = self.get_target()
        if not target: 
            input(f"\n{Colors.WARNING}Press Enter to continue... {Colors.ENDC}")
            return
        
        try: 
            print(f"{Colors. WARNING}[*] Detecting technologies for {target}...{Colors. ENDC}")
            analyzer = WebAnalyzer(target, timeout=self.config['timeout'])
            result = analyzer.detect_technologies()
            
            print(f"\n{Colors.OKGREEN}[✓] Technology Detection Complete!{Colors.ENDC}\n")
            
            if result:
                for tech_type, tech_name in result.items():
                    print(f"{Colors.OKCYAN}{tech_type. replace('_', ' ').title()}:{Colors.ENDC} {tech_name}")
            else:
                print(f"{Colors. WARNING}No technologies detected{Colors.ENDC}")
            
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error: {str(e)}{Colors.ENDC}")
        
        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
    
    def full_recon(self):
        """Perform full reconnaissance and save to JSON."""
        print(f"\n{Colors.HEADER}═══ Full Reconnaissance Scan ═══{Colors. ENDC}")
        
        target = self.get_target()
        if not target:
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return
        
        try:
            print(f"{Colors.WARNING}[*] Performing comprehensive scan of {target}...{Colors. ENDC}")
            print(f"{Colors.WARNING}[*] This will take several seconds...{Colors.ENDC}\n")
            
            analyzer = WebAnalyzer(target, timeout=self.config['timeout'])
            
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
            self.save_to_json(result)
            
            # Show summary
            print(f"\n{Colors.OKCYAN}═══ Scan Summary ═══{Colors. ENDC}")
            print(f"URL: {result['url']}")
            print(f"Hostname: {result['hostname']}")
            print(f"Status:  {result['status_code']} {result['reason']}")
            print(f"IP:  {result['ip_info']. get('ip_address', 'N/A')}")
            print(f"Open Ports: {len([p for p in result['open_ports'] if 'port' in p])}")
            print(f"Technologies: {len(result['technologies'])}")
            
        except Exception as e: 
            print(f"{Colors. FAIL}[✗] Error:  {str(e)}{Colors.ENDC}")
        
        input(f"\n{Colors. WARNING}Press Enter to continue...{Colors.ENDC}")
    
    def batch_scan(self):
        """Scan multiple targets from loaded list."""
        print(f"\n{Colors.HEADER}═══ Batch Scan ═══{Colors.ENDC}")
        
        targets = self.target_manager.get_target_list()
        
        if not targets:
            print(f"{Colors.WARNING}[!] No targets loaded from file.{Colors.ENDC}")
            print(f"{Colors.WARNING}[!] Please use option T to load targets from a file first.{Colors.ENDC}")
            input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
            return
        
        print(f"{Colors. OKGREEN}[✓] Found {len(targets)} targets{Colors.ENDC}")
        print(f"{Colors.WARNING}[*] Starting batch scan...{Colors.ENDC}\n")
        
        confirm = self.get_input(f"Scan all {len(targets)} targets? (Y/n): ", False)
        if confirm.lower() == 'n':
            return
        
        try:
            results = []
            for i, target in enumerate(targets, 1):
                print(f"[{i}/{len(targets)}] Scanning {target}...")
                try:
                    analyzer = WebAnalyzer(target, timeout=self.config['timeout'])
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
    
    def save_to_json(self, data):
        """Save data to JSON file."""
        try:
            try:
                with open(self. config['output_file'], 'r') as f:
                    existing_data = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                existing_data = []
            
            if not isinstance(existing_data, list):
                existing_data = [existing_data]
            
            existing_data. append(data)
            
            with open(self.config['output_file'], 'w') as f:
                json.dump(existing_data, f, indent=2)
            
            print(f"{Colors.OKGREEN}[✓] Results saved to {self.config['output_file']}{Colors.ENDC}")
            
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error saving to JSON: {str(e)}{Colors.ENDC}")
    
    def configuration_menu(self):
        """Configuration settings menu."""
        while True:
            clear_screen()
            self.print_banner()
            
            print(f"\n{Colors.HEADER}═══ Configuration Settings ═══{Colors.ENDC}")
            print(f"""
{Colors.OKCYAN}Current Settings:{Colors.ENDC}
┌─────────────────────────────────────────────────────────────┐
│ Timeout:          {self.config['timeout']} seconds
│ Output File:     {self.config['output_file']}
│ Auto-Save:       {self.config['auto_save']}
│ Verbose:         {self.config['verbose']}
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
            """)
            
            choice = self.get_input("Select option: ", False)
            
            if choice == '1': 
                new_value = self.get_input(f"Enter timeout in seconds (current: {self.config['timeout']}): ", False)
                if new_value and new_value. isdigit():
                    self. config['timeout'] = int(new_value)
                    print(f"{Colors.OKGREEN}[✓] Timeout updated{Colors.ENDC}")
                    time.sleep(1)
            elif choice == '2':
                new_value = self.get_input(f"Enter output filename (current: {self.config['output_file']}): ", False)
                if new_value: 
                    self.config['output_file'] = new_value
                    print(f"{Colors. OKGREEN}[✓] Output file updated{Colors.ENDC}")
                    time.sleep(1)
            elif choice == '3':
                self.config['auto_save'] = not self.config['auto_save']
                print(f"{Colors. OKGREEN}[✓] Auto-save {'enabled' if self.config['auto_save'] else 'disabled'}{Colors.ENDC}")
                time.sleep(1)
            elif choice == '4': 
                self.config['verbose'] = not self.config['verbose']
                print(f"{Colors. OKGREEN}[✓] Verbose mode {'enabled' if self.config['verbose'] else 'disabled'}{Colors.ENDC}")
                time.sleep(1)
            elif choice == '5':
                self.save_config()
            elif choice == '6':
                self.load_config()
            elif choice == '7':
                confirm = self.get_input("Reset all settings to defaults? (y/N): ", False)
                if confirm.lower() == 'y':
                    self.config = {'timeout': 10, 'output_file': 'recon_results.json', 'auto_save': True, 'verbose': True}
                    print(f"{Colors.OKGREEN}[✓] Settings reset to defaults{Colors.ENDC}")
                    time.sleep(1)
            elif choice == '0':
                break
            else:
                print(f"{Colors.FAIL}[✗] Invalid option{Colors. ENDC}")
                time.sleep(1)
    
    def save_config(self):
        """Save configuration to file."""
        try:
            with open('omni_config.json', 'w') as f:
                json.dump(self.config, f, indent=2)
            print(f"{Colors.OKGREEN}[✓] Configuration saved{Colors. ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error saving config: {str(e)}{Colors.ENDC}")
        time.sleep(1)
    
    def load_config(self):
        """Load configuration from file."""
        try:
            import os
            if os.path. exists('omni_config. json'):
                with open('omni_config.json', 'r') as f:
                    self.config = json.load(f)
                print(f"{Colors.OKGREEN}[✓] Configuration loaded{Colors. ENDC}")
            else:
                print(f"{Colors. WARNING}[!] No config file found{Colors.ENDC}")
        except Exception as e: 
            print(f"{Colors. FAIL}[✗] Error loading config: {str(e)}{Colors.ENDC}")
        time.sleep(1)
    
    def show_help(self):
        """Show help information."""
        help_text = f"""
{Colors.HEADER}═══ Help Information ═══{Colors.ENDC}

{Colors.OKBLUE}About Web Analyzer Pro:{Colors.ENDC}
Advanced reconnaissance tool for analyzing websites and web applications.

{Colors.OKBLUE}Module Structure:{Colors.ENDC}
• web_analyzer.py    - Core scanning functionality
• target_manager.py  - Target loading and management
• utils.py           - Helper functions and utilities
• main.py            - Interactive GUI application

{Colors.OKBLUE}Loading Targets:{Colors.ENDC}
Option T - Load Target
  • Load Single URL/IP:  Enter one target to scan
  • Load from File: Multiple targets (one per line)

{Colors.OKBLUE}Available Scans:{Colors.ENDC}
1-7:  Individual scan types (printed to screen)
8:   Full Reconnaissance (saved to JSON)
9:   Batch Scan all loaded targets (saved to JSON)

{Colors.OKBLUE}Keyboard Shortcuts:{Colors.ENDC}
• Ctrl+C:  Exit gracefully
• T: Load targets
• Q: Quit

{Colors.WARNING}⚠️  Use responsibly and ethically{Colors.ENDC}
        """
        
        print(help_text)
        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
    
    def run(self):
        """Main interactive loop."""
        try:
            self.load_config()
            
            while True:
                clear_screen()
                self.print_banner()
                self.print_status()
                self.print_menu()
                
                choice = self.get_input("Select option: ", False).upper()
                
                if choice == 'T':
                    self.load_target_menu()
                elif choice == '1':
                    self.quick_scan()
                elif choice == '2':
                    self. dns_recon()
                elif choice == '3':
                    self.ip_info()
                elif choice == '4':
                    self. ssl_analysis()
                elif choice == '5':
                    self.headers_analysis()
                elif choice == '6':
                    self.port_scan()
                elif choice == '7':
                    self.tech_detection()
                elif choice == '8': 
                    self.full_recon()
                elif choice == '9': 
                    self.batch_scan()
                elif choice == 'C' or choice == '0':
                    self.configuration_menu()
                elif choice == 'H': 
                    self.show_help()
                elif choice == 'Q':
                    print(f"{Colors.OKCYAN}Goodbye!{Colors.ENDC}")
                    break
                else:
                    print(f"{Colors.FAIL}[✗] Invalid option{Colors.ENDC}")
                    time.sleep(1)
                    
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Exiting... {Colors.ENDC}")
            sys.exit(0)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Web Analyzer Pro - Advanced Web Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-i', '--interactive', action='store_true', help='Launch interactive mode (default)')
    
    args = parser.parse_args()
    
    app = WebAnalyzerApp()
    app.run()


if __name__ == '__main__':
    main()
