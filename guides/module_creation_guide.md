
# Module Creation Guide

## Quick Start:  Creating a New Module

### Step 1: Copy the Template
```bash
cp module_template.py your_module_name. py
```

### Step 2: Update Module Information
In your new file, update:
- Class name:  `ModuleTemplate` → `YourModuleName`
- `self.name` → Your module's display name
- `self.description` → Brief description

### Step 3: Customize the Menu
Update `_print_module_menu()` with your scan options:
```python
menu = f"""
{Colors. OKBLUE}Available Operations:{Colors.ENDC}
┌─────────────────────────────────────────────────────────────┐
│ 1. Your Scan Type 1                                         │
│ 2. Your Scan Type 2                                         │
│ 3. Your Scan Type 3                                         │
│ B. Back to Main Menu                                        │
└─────────────────────────────────────────────────────────────┘
```

### Step 4: Implement Scan Functions
Replace the demo functions with your actual scans: 
- `_demo_scan_1` → `_your_scan_name`
- Update the choice mapping in `run()`

### Step 5: Add to Main Menu
In `main.py`, add to `_load_modules()`:
```python
def _load_modules(self):
    try:
        from web_analyzer import WebAnalyzerModule
        self.modules['web_analyzer'] = WebAnalyzerModule()
        
        from your_module_name import YourModuleName
        self.modules['your_module'] = YourModuleName()
    except ImportError as e:
        print(f"Error loading modules: {e}")
```

## Module Structure

### Required Methods:
- `__init__()` - Initialize module
- `run(config, target_manager)` - Main entry point
- `_print_module_banner()` - Display banner
- `_print_module_status()` - Display status
- `_print_module_menu()` - Display menu

### Recommended Helper Methods:
- `_get_target(target_manager)` - Get target for scanning
- `_save_results(data, output_file)` - Save results to JSON
- `_print_progress(current, total, message)` - Progress indicator

### Scan Function Template:
```python
def _your_scan(self, config, target_manager):
    """Your scan description."""
    print(f"\n{Colors.HEADER}═══ Your Scan Name ═══{Colors.ENDC}")
    
    target = self._get_target(target_manager)
    if not target:
        input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
        return
    
    print(f"{Colors.WARNING}[*] Scanning {target}...{Colors. ENDC}")
    
    try:
        # Your scan logic here
        result = self._perform_your_scan(target, config)
        
        print(f"\n{Colors.OKGREEN}[✓] Scan Complete! {Colors.ENDC}\n")
        # Display results
        
        if config.get('auto_save'):
            self._save_results(result, config['output_file'])
        
    except Exception as e:
        print(f"{Colors.FAIL}[✗] Error: {str(e)}{Colors.ENDC}")
    
    input(f"\n{Colors.WARNING}Press Enter to continue...{Colors.ENDC}")
```

## Best Practices

1. **Separation of Concerns**
   - Keep UI/display logic in the Module class
   - Keep scan logic in a separate Core class

2. **Error Handling**
   - Always use try/except blocks
   - Provide meaningful error messages
   - Allow graceful continuation

3. **User Experience**
   - Always end scans with "Press Enter to continue"
   - Use color coding consistently
   - Provide progress indicators for long operations

4. **Data Management**
   - Save results in JSON format
   - Include timestamps
   - Support batch operations

5. **Configuration**
   - Respect the global config settings
   - Use timeout from config
   - Check auto_save setting

## Color Usage Guide

```python
Colors.HEADER    # Cyan - Headers and titles
Colors.OKBLUE    # Blue - Section labels
Colors.OKCYAN    # Cyan - Field names
Colors.OKGREEN   # Green - Success messages
Colors. WARNING   # Yellow - Warnings and prompts
Colors.FAIL      # Red - Errors and failures
Colors.ENDC      # Reset color
```

## Example Module Ideas

- **Port Scanner Module** - Scan ports with different techniques
- **Subdomain Finder Module** - Discover subdomains
- **Vulnerability Scanner Module** - Check for common vulnerabilities
- **API Tester Module** - Test API endpoints
- **Content Discovery Module** - Find hidden files/directories
- **Network Mapper Module** - Map network topology
- **Exploit Module** - Testing exploits (ethical use only)
```

This template gives you everything you need to quickly create new modules!  Just copy, customize, and add to main.py.  🐍