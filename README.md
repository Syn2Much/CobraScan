# CobraScan 🐍

*a powerful, modular reconnaissance tool designed for security professionals, ethical hackers, and system administrators. It provides a unified interface for multiple security scanning and analysis techniques through an extensible plugin architecture*

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/Syn2Much/CobraScan/graphs/commit-activity)

---


## ✨ Features

### Core Features
- **🔌 Modular Architecture**: Plugin-based system for easy extension
- **📊 Multiple Scan Types**: DNS, SSL, ports, headers, and more
- **🎯 Target Management**: Single or batch target scanning
- **💾 Persistent Configuration**: Save preferences between sessions
- **📈 JSON Export**: Structured data for automation and reporting

---
### Main Menu
```
┌─────────────────────────────────────────────┐
│ Available Modules:                          │
│ 1. Web Analyzer (v2.0.0)                    │
│                                             │
│ T. Load Target (URL/IP or File)             │
│ C. Configuration & Settings                 │
│ H. Help & Information                       │
│ Q. Exit                                     │
└─────────────────────────────────────────────┘
```

### Web Analyzer Scan Menu
```
┌─────────────────────────────────────────────┐
│  1. Quick Scan                              │
│  2. DNS Reconnaissance                      │
│  3. IP & Geolocation Info                   │
│  4. SSL/TLS Certificate Analysis            │
│  5. Security Headers Analysis               │
│  6. HTTP Methods Scan                       │
│  7. Content Analysis                        │
│  8. Performance Metrics                     │
│  9. Port Scanning                           │
│ 10. Technology Detection                    │
│ 11. Full Reconnaissance Scan                │
│ 12. Batch Scan from Loaded Targets          │
│  B. Back to Main Menu                       │
└─────────────────────────────────────────────┘
```
## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Installation Steps

```bash
# Clone the repository
git clone https://github.com/Syn2Much/CobraScan.git
cd CobraScan

# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

---

## 🚀 Quick Start

1. **Start CobraScan**:
   ```bash
   python main.py
   ```

2. **Load Targets**:
   - Press `T` from main menu
   - Choose single target or load from file

3. **Run Scans**:
   - Select a module (e.g., `1` for Web Analyzer)
   - Choose scan type
   - View results or export to JSON

4. **Configure Settings**:
   - Press `C` from main menu
   - Adjust timeout, output file, etc.

---

## 🔌 Module Development

### Creating a New Module

1. **Copy the Template**:
   ```bash
   cp dev/module_template.py modules/your_module.py
   ```

2. **Customize Your Module**:
   ```python
   # modules/your_module.py
   class YourModuleName:
       def __init__(self):
           self.name = "Your Module Name"
           self.version = "1.0.0"
       
       def run(self, config, target_manager):
           """Main entry point for your module."""
           # Your module logic here
           pass
   ```

3. **Register the Module** in `main.py`:
   ```python
   # Add to _load_modules() method
   from modules.your_module import YourModuleName
   self.modules['your_module'] = YourModuleName()
   ```

### Module Template Features
- Pre-built menu system
- Configuration management
- Target handling
- Error handling
- JSON export utilities

### Best Practices
1. Follow the template structure
2. Include comprehensive docstrings
3. Add error handling for network issues
4. Test with various target types
5. Document your module in README

---


## 📝 Changelog

### Version 1.3.0 (Current)
- **Web Analyzer v2.0.0**: Major expansion with 12 scan types
-  New: HTTP Methods vulnerability scanning (TRACE, PUT, DELETE detection)
-  New: Content analysis (emails, meta tags, sensitive paths)
-  New: Performance metrics (response time, compression, caching analysis)
-  New: Enhanced SSL analysis with certificate warnings and expiry tracking
-  New: Security headers with vulnerability recommendations
-  New: IPv6 DNS records support (AAAA records)
-  New: Expanded port scanning (21 ports including PostgreSQL, Redis, Elasticsearch)
-  Refactored: Structured JSON output with logical sections
-  Refactored: Enhanced Modular Plugin Loader
-  Fixed: All spacing and formatting issues
-  Improved: Better error handling and user feedback

### Version 1.2.5
- Modular Architecture: Complete refactor to plugin system
- Dynamic Module Loading: Automatic menu generation
- Module Template: Easy module creation
- Improved Structure: Better code organization
- Bug Fixes: Banner spacing and error handling

### Version 1.2.0
- Rebranded to CobraScan
- Target Manager: Single and batch scanning
- Configuration System: Persistent settings
- Enhanced UI: Improved user interface

### Version 1.0.0
- Initial Release
- Basic Scanning: Core functionality
- JSON Export: Structured output

[View full changelog](CHANGELOG.md)

---

## 📁 Project Structure

```
CobraScan/
│
├── main.py                 # Main application entry point
├── README.md               # Documentation
├── requirements.txt        # Python dependencies
│
├── helpers/                # Helper modules
│   ├── __init__.py
│   ├── target_manager.py   # Target loading and management
│   └── utils.py            # Utility functions
│
├── modules/                # Scan modules
│   ├── __init__.py
│   ├── web_analyzer.py     # Web analysis module
│   └── (additional modules)
│
├── dev/                    # Development resources
│   ├── module_creation_guide.md
│   └── module_template.py  # New module template
│
├── targets.txt             # Target list (user-created)
├── cobra_config.json       # Configuration (auto-generated)
└── cobra_scan_results.json # Scan results (auto-generated)
```
---
## ⚖️ Legal Disclaimer

**CobraScan is for authorized security testing only.**

### ❌ Prohibited Use
- Scanning systems without explicit permission
- Malicious or disruptive activities
- Violating laws or terms of service
- Unauthorized access attempts

**Users are responsible for compliance with all applicable laws.**

---

## 📞 Support

### Documentation
- [Module Creation Guide](guides/module_creation_guide.md)

### Contact
- **Email**: dev@sinners.city
- **GitHub**: [@Syn2Much](https://github.com/Syn2Much)
- **Website**: [sinners.city](https://sinners.city)

---

<div align="center">
s
## 🐍 CobraScan - The All-Seeing Reconnaissance Tool

*In the realm of security, visibility is power. CobraScan grants you omniscience.*

**⭐ If you find this useful, please give it a star! ⭐**

[Report Bug](https://github.com/Syn2Much/CobraScan/issues) · 
[Request Feature](https://github.com/Syn2Much/CobraScan/issues) · 
[View Source](https://github.com/Syn2Much/CobraScan)

---

**Made with 🐍 by [Syn2Much](https://github.com/Syn2Much)**

</div>
