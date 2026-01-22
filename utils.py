#!/usr/bin/env python3
"""
Utility Module
Helper functions and classes
"""

import os


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