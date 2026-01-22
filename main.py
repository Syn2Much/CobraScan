#!/usr/bin/env python3
"""
Cobra Scan - Main Application
Interactive GUI framework and module loader
"""

import sys
import argparse
import signal

from target_manager import TargetManager
from utils import Colors, clear_screen


class CobraScanner:  
    """Interactive GUI Application - Module Loader Framework."""
    
    def __init__(self):
        self.app_name = "Cobra"
        self.version = "1.2.5"
        self.config = {
            'timeout': 10,
            'output_file': 'cobra_scan_results.json',
            'auto_save': True,
            'verbose': True
        }
        self.target_manager = TargetManager()
        self.modules = {}
        
        # Load modules
        self._load_modules()
        
        # Set up signal handler for Ctrl+C
        signal.signal(signal.SIGINT, self. signal_handler)
        
    def _load_modules(self):
        """Load all available modules."""
        try:
            from modules.web_analyzer import WebAnalyzerModule
            self.modules['web_analyzer'] = WebAnalyzerModule()
        except ImportError as e:
            print(f"Error loading web_analyzer module: {e}")
    
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully."""
        print(f"\n{Colors. WARNING}[!] Exiting gracefully...{Colors.ENDC}")
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

             Cobra Version {self.version}    
=====================================================================
{Colors.ENDC}"""
        print(banner)
        
    def print_status(self):
        """Print current configuration status."""
        target_display = self.target_manager.get_status_string()
            
        status = f"""{Colors.OKCYAN}Current Status:{Colors.ENDC}
┌─────────────────────────────────────────────────────────────┐
│ Current Target:     {target_display: <45}
│ Timeout:          {self.config['timeout']} seconds{' ' * 36}
│ Output File:      {self.config['output_file']: <44}
│ Auto-Save:        {str(self.config['auto_save']):<44}
└─────────────────────────────────────────────────────────────┘"""
        print(status)
    
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
        print("┌────────────────────────────────────────────────────────────┐")
        print("│ 1. Load Single URL/IP Address                              │")
        print(" 2. Load Multiple Targets from File                          │")
        print("│ 0. Back to Main Menu                                       │")
        print("└────────────────────────────────────────────────────────────┘\n")
        
        choice = self.get_input("Select option:  ", False)
        
        if choice == '1':
            self.load_single_target()
        elif choice == '2':  
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
    
    def configuration_menu(self):
        """Configuration settings menu."""
        import json
        import time
        
        while True:
            clear_screen()
            self.print_banner()
            
            print(f"\n{Colors. HEADER}═══ Configuration Settings ═══{Colors.ENDC}")
            print(f"""
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
            """)
            
            choice = self.get_input("Select option: ", False)
            
            if choice == '1':  
                new_value = self.get_input(f"Enter timeout in seconds (current: {self.config['timeout']}): ", False)
                if new_value and new_value.isdigit():
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
                print(f"{Colors.OKGREEN}[✓] Auto-save {'enabled' if self.config['auto_save'] else 'disabled'}{Colors.ENDC}")
                time.sleep(1)
            elif choice == '4':  
                self.config['verbose'] = not self.config['verbose']
                print(f"{Colors. OKGREEN}[✓] Verbose mode {'enabled' if self.config['verbose'] else 'disabled'}{Colors.ENDC}")
                time.sleep(1)
            elif choice == '5':
                self._save_config()
                time.sleep(1)
            elif choice == '6':
                self._load_config()
                time.sleep(1)
            elif choice == '7':
                confirm = self.get_input("Reset all settings to defaults? (y/N): ", False)
                if confirm.lower() == 'y':
                    self. config = {'timeout': 10, 'output_file': 'recon_results.json', 'auto_save': True, 'verbose':  True}
                    print(f"{Colors.OKGREEN}[✓] Settings reset to defaults{Colors.ENDC}")
                    time.sleep(1)
            elif choice == '0':
                break
            else:
                print(f"{Colors.FAIL}[✗] Invalid option{Colors.ENDC}")
                time.sleep(1)
    
    def _save_config(self):
        """Save configuration to file."""
        import json
        try:
            with open('cobra_config.json', 'w') as f:
                json.dump(self.config, f, indent=2)
            print(f"{Colors.OKGREEN}[✓] Configuration saved{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error saving config: {str(e)}{Colors.ENDC}")
    
    def _load_config(self):
        """Load configuration from file."""
        import json
        import os
        try:
            if os.path. exists('cobra_config.json'):
                with open('cobra_config.json', 'r') as f:
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
                
                if choice == 'T':
                    self.load_target_menu()
                elif choice. isdigit():
                    # Load module by number
                    module_num = int(choice)
                    module_list = list(self.modules.values())
                    if 1 <= module_num <= len(module_list):
                        selected_module = module_list[module_num - 1]
                        selected_module.run(self. config, self.target_manager)
                    else:
                        print(f"{Colors.FAIL}[✗] Invalid module number{Colors. ENDC}")
                        import time
                        time.sleep(1)
                elif choice == 'C':
                    self.configuration_menu()
                elif choice == 'H':   
                    self.show_help()
                elif choice == 'Q':
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
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-i', '--interactive', action='store_true', help='Launch interactive mode (default)')
    
    args = parser.parse_args()
    
    app = CobraScanner()
    app.run()


if __name__ == '__main__':
    main()