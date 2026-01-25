#!/usr/bin/env python3
"""
Proxy Manager Module
Handles loading, rotating, and validating HTTP/HTTPS proxies
"""

import random
from typing import List, Dict, Optional, Tuple
from pathlib import Path


class ProxyManager:
    """Manages HTTP/HTTPS proxy list with rotation support."""

    def __init__(self):
        self.proxies: List[str] = []
        self.current_index = 0
        self.failed_proxies: List[str] = []

    def load_from_file(self, filepath: str) -> Tuple[bool, str]:
        """
        Load proxies from a text file (one proxy per line).

        Expected formats:
            - ip:port
            - http://ip:port
            - https://ip:port
            - user:pass@ip:port

        Args:
            filepath: Path to the proxy list file

        Returns:
            Tuple of (success, message)
        """
        try:
            path = Path(filepath)
            if not path.exists():
                return False, f"File not found: {filepath}"

            with open(path, 'r') as f:
                lines = f.readlines()

            loaded = 0
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                proxy = self._normalize_proxy(line)
                if proxy and proxy not in self.proxies:
                    self.proxies.append(proxy)
                    loaded += 1

            if loaded == 0:
                return False, "No valid proxies found in file"

            return True, f"Loaded {loaded} proxies"

        except Exception as e:
            return False, f"Error loading proxies: {str(e)}"

    def _normalize_proxy(self, proxy: str) -> Optional[str]:
        """
        Normalize proxy string to standard format.

        Args:
            proxy: Raw proxy string

        Returns:
            Normalized proxy string or None if invalid
        """
        proxy = proxy.strip()
        if not proxy:
            return None

        # Already has protocol
        if proxy.startswith(('http://', 'https://')):
            return proxy

        # Add http:// prefix if missing
        # Format: ip:port or user:pass@ip:port
        if ':' in proxy:
            return f"http://{proxy}"

        return None

    def get_proxy(self) -> Optional[Dict[str, str]]:
        """
        Get the current proxy in requests-compatible format.

        Returns:
            Dict with 'http' and 'https' keys, or None if no proxies
        """
        if not self.proxies:
            return None

        proxy = self.proxies[self.current_index]
        return {
            'http': proxy,
            'https': proxy
        }

    def get_next_proxy(self) -> Optional[Dict[str, str]]:
        """
        Rotate to the next proxy and return it.

        Returns:
            Dict with 'http' and 'https' keys, or None if no proxies
        """
        if not self.proxies:
            return None

        self.current_index = (self.current_index + 1) % len(self.proxies)
        return self.get_proxy()

    def get_random_proxy(self) -> Optional[Dict[str, str]]:
        """
        Get a random proxy from the list.

        Returns:
            Dict with 'http' and 'https' keys, or None if no proxies
        """
        if not self.proxies:
            return None

        proxy = random.choice(self.proxies)
        return {
            'http': proxy,
            'https': proxy
        }

    def mark_failed(self, proxy_dict: Optional[Dict[str, str]]):
        """
        Mark a proxy as failed (for tracking purposes).

        Args:
            proxy_dict: Proxy dict returned by get_proxy methods
        """
        if proxy_dict and 'http' in proxy_dict:
            proxy = proxy_dict['http']
            if proxy not in self.failed_proxies:
                self.failed_proxies.append(proxy)

    def remove_failed(self):
        """Remove all failed proxies from the active list."""
        for proxy in self.failed_proxies:
            if proxy in self.proxies:
                self.proxies.remove(proxy)
        removed = len(self.failed_proxies)
        self.failed_proxies.clear()
        self.current_index = 0
        return removed

    def clear(self):
        """Clear all loaded proxies."""
        self.proxies.clear()
        self.failed_proxies.clear()
        self.current_index = 0

    def get_count(self) -> int:
        """Get the number of loaded proxies."""
        return len(self.proxies)

    def get_proxy_list(self) -> List[str]:
        """Get the list of all loaded proxies."""
        return self.proxies.copy()

    def is_loaded(self) -> bool:
        """Check if any proxies are loaded."""
        return len(self.proxies) > 0
