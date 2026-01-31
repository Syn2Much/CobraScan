#!/usr/bin/env python3
"""
Utility Module
Helper functions and classes
"""

import os
import datetime
import signal
import json


class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class ScanInterrupt(Exception):
    """Exception raised when user presses Ctrl+C during a scan."""
    pass


class ScanContext:
    """
    Context manager for handling Ctrl+C during scans.
    
    Usage:
        with ScanContext(config, partial_results) as ctx:
            # Do scan work
            if ctx.interrupted:
                break  # Skip to next scan
    """
    
    def __init__(self, config: dict = None, partial_results: dict = None, output_file: str = None):
        self.config = config or {}
        self.partial_results = partial_results
        self.output_file = output_file or self.config.get("output_file", "cobra_scan_results.json")
        self.interrupted = False
        self.skip_current = False
        self._original_handler = None
    
    def _handler(self, sig, frame):
        """Handle Ctrl+C - set interrupted flag instead of exiting."""
        self.interrupted = True
        self.skip_current = True
        print(f"\n{Colors.WARNING}[!] Ctrl+C detected - skipping current scan...{Colors.ENDC}")
    
    def __enter__(self):
        self._original_handler = signal.signal(signal.SIGINT, self._handler)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Restore original handler
        signal.signal(signal.SIGINT, self._original_handler)
        
        # If interrupted and we have partial results, save them
        if self.interrupted and self.partial_results:
            self._save_partial_results()
        
        # Suppress the ScanInterrupt exception so execution continues
        return exc_type is ScanInterrupt
    
    def _save_partial_results(self):
        """Save partial scan results to JSON."""
        try:
            self.partial_results["interrupted"] = True
            self.partial_results["interrupt_timestamp"] = datetime.datetime.now().isoformat()
            
            # Load existing results
            try:
                with open(self.output_file, "r") as f:
                    existing = json.load(f)
            except:
                existing = []
            
            if not isinstance(existing, list):
                existing = [existing]
            existing.append(self.partial_results)
            
            with open(self.output_file, "w") as f:
                json.dump(existing, f, indent=2)
            
            print(f"{Colors.OKGREEN}[✓] Partial results saved to {self.output_file}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Failed to save partial results: {e}{Colors.ENDC}")
    
    def check(self):
        """Check if interrupted and should skip current scan."""
        if self.skip_current:
            self.skip_current = False  # Reset for next scan
            return True
        return False
    
    def reset(self):
        """Reset skip flag for next scan phase."""
        self.skip_current = False


class Logger:
    """Pretty logging utility with verbose toggle support."""
    
    def __init__(self, verbose: bool = True, module_name: str = ""):
        self.verbose = verbose
        self.module_name = module_name
    
    def _timestamp(self) -> str:
        """Get current timestamp."""
        return datetime.datetime.now().strftime("%H:%M:%S")
    
    def log(self, message: str, level: str = "info", end: str = "\n", force: bool = False):
        """
        Print formatted log message.
        
        Args:
            message: The message to print
            level: Log level (info, success, warning, error, vuln, test, progress, phase)
            end: Line ending character
            force: If True, print even when verbose is False
        """
        if not self.verbose and not force:
            return
            
        ts = self._timestamp()
        prefix = f"    {Colors.OKCYAN}[{ts}]{Colors.ENDC}"
        
        if level == "info":
            print(f"{prefix} {message}", end=end, flush=True)
        elif level == "success":
            print(f"{prefix} {Colors.OKGREEN}✓{Colors.ENDC} {message}", end=end, flush=True)
        elif level == "warning":
            print(f"{prefix} {Colors.WARNING}⚠{Colors.ENDC} {message}", end=end, flush=True)
        elif level == "error":
            print(f"{prefix} {Colors.FAIL}✗{Colors.ENDC} {message}", end=end, flush=True)
        elif level == "vuln":
            print(f"{prefix} {Colors.FAIL}🔓 VULN:{Colors.ENDC} {message}", end=end, flush=True)
        elif level == "found":
            print(f"{prefix} {Colors.OKGREEN}🎯 FOUND:{Colors.ENDC} {message}", end=end, flush=True)
        elif level == "test":
            print(f"{prefix} {Colors.HEADER}▶{Colors.ENDC} {message}", end=end, flush=True)
        elif level == "progress":
            print(f"\r{prefix} {message}", end="", flush=True)
        elif level == "phase":
            print(f"\n{Colors.OKBLUE}[{ts}] ═══ {message} ═══{Colors.ENDC}", end=end, flush=True)
        elif level == "header":
            print(f"\n{Colors.HEADER}{'═' * 60}", flush=True)
            print(f"  {message}")
            print(f"{'═' * 60}{Colors.ENDC}", flush=True)
        elif level == "subheader":
            print(f"{Colors.OKCYAN}{'─' * 50}{Colors.ENDC}", flush=True)
            print(f"{Colors.OKCYAN}  {message}{Colors.ENDC}", flush=True)
            print(f"{Colors.OKCYAN}{'─' * 50}{Colors.ENDC}", flush=True)
    
    def phase(self, phase_num: int, title: str, icon: str = "🔍"):
        """Print a phase header."""
        print(f"\n{Colors.OKBLUE}[PHASE {phase_num}] {icon} {title}{Colors.ENDC}")
        print(f"{'─' * 45}")
    
    def result(self, label: str, value: str, status: str = "neutral"):
        """Print a result line with status coloring."""
        if not self.verbose:
            return
        if status == "good":
            color = Colors.OKGREEN
            icon = "✓"
        elif status == "bad":
            color = Colors.FAIL
            icon = "✗"
        elif status == "warn":
            color = Colors.WARNING
            icon = "⚠"
        else:
            color = Colors.OKCYAN
            icon = "•"
        print(f"    {color}{icon} {label}:{Colors.ENDC} {value}")
    
    def progress_bar(self, current: int, total: int, prefix: str = "", suffix: str = ""):
        """Print a progress bar."""
        if not self.verbose:
            return
        percentage = (current / total) * 100 if total > 0 else 0
        bar_length = 30
        filled = int(bar_length * current / total) if total > 0 else 0
        bar = "█" * filled + "░" * (bar_length - filled)
        print(f"\r    {Colors.OKCYAN}[{bar}]{Colors.ENDC} {percentage:5.1f}% {prefix} {suffix}", end="", flush=True)
    
    def newline(self):
        """Print a newline."""
        print()


def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def format_file_size(size_bytes:  int) -> str:
    """
    Format bytes to human-readable size.
    
    Args:
        size_bytes: Size in bytes
        
    Returns: 
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"


def validate_url(url: str) -> bool:
    """
    Basic URL validation.
    
    Args:
        url: URL to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not url or not url.strip():
        return False
    
    # Basic validation - can be enhanced
    url = url.strip().lower()
    return any([
        url.startswith('http://'),
        url.startswith('https://'),
        '.' in url  # At least contains a dot (domain)
    ])