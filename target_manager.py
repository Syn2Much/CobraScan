#!/usr/bin/env python3
"""
Target Manager Module
Handles loading and managing scan targets
"""

import pathlib
from typing import List, Optional


class TargetManager:
    """Manage scan targets from single input or file."""
    
    def __init__(self):
        """Initialize target manager."""
        self. current_target = None
        self. target_list = []
        self.target_source = None
    
    def load_single_target(self, target:  str) -> bool:
        """
        Load a single target URL or IP. 
        
        Args:
            target: URL or IP address
            
        Returns:
            True if successful, False otherwise
        """
        if not target or not target.strip():
            return False
        
        self.current_target = target.strip()
        self.target_list = []
        self.target_source = None
        return True
    
    def load_targets_from_file(self, filename: str) -> tuple[bool, str]:
        """
        Load multiple targets from a text file.
        
        Args:
            filename: Path to file containing targets (one per line)
            
        Returns: 
            Tuple of (success:  bool, message: str)
        """
        try:
            file_path = pathlib.Path(filename)
            if not file_path.exists():
                return False, f"File not found: {filename}"
            
            # Read and parse file
            contents = file_path.read_text()
            targets = [
                line.strip() 
                for line in contents.split('\n') 
                if line.strip() and not line.strip().startswith('#')
            ]
            
            if not targets:
                return False, "No valid targets found in file"
            
            # Store targets
            self.target_list = targets
            self.target_source = filename
            self.current_target = None
            
            return True, f"Loaded {len(targets)} targets from {filename}"
            
        except Exception as e:
            return False, f"Error loading file: {str(e)}"
    
    def get_current_target(self) -> Optional[str]:
        """Get the current single target."""
        return self.current_target
    
    def get_target_list(self) -> List[str]:
        """Get the list of targets loaded from file."""
        return self.target_list
    
    def get_target_count(self) -> int:
        """Get total number of loaded targets."""
        if self.target_list:
            return len(self.target_list)
        elif self.current_target:
            return 1
        return 0
    
    def has_targets(self) -> bool:
        """Check if any targets are loaded."""
        return bool(self.current_target or self.target_list)
    
    def get_target_by_index(self, index: int) -> Optional[str]:
        """
        Get target from list by index.
        
        Args:
            index: Zero-based index
            
        Returns:
            Target string or None if invalid index
        """
        if 0 <= index < len(self.target_list):
            return self.target_list[index]
        return None
    
    def get_status_string(self) -> str:
        """Get a formatted status string for display."""
        if self.target_list:
            return f"{len(self.target_list)} targets loaded from {self.target_source}"
        elif self.current_target:
            return self.current_target
        else:
            return "None"
    
    def clear_targets(self):
        """Clear all loaded targets."""
        self.current_target = None
        self. target_list = []
        self.target_source = None
