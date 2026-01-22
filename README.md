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

### Web Analyzer Module
- **🌐 Quick Scan**: Basic HTTP information
- **🔍 DNS Reconnaissance**: A, MX, TXT record analysis
- **📍 IP Geolocation**: IP address location and ISP info
- **🔒 SSL/TLS Analysis**: Certificate validation and expiration
- **🛡️ Security Headers**: Security header presence and configuration
- **🔌 Port Scanning**: Common port detection
- **🛠️ Technology Detection**: Web server and framework identification
- **📋 Full Reconnaissance**: Complete all-in-one scan
- **📦 Batch Processing**: Scan multiple targets from file

---

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


## 🛠️ Usage Guide

### Main Menu
```
┌─────────────────────────────────────────────┐
│ Available Modules:                          │
│ 1. Web Analyzer                             │
│ 2. [Future Module]                          │
│                                             │
│ T. Load Target (URL/IP or File)             │
│ C. Configuration & Settings                 │
│ H. Help & Information                       │
│ Q. Exit                                     │
└─────────────────────────────────────────────┘
```


### Target Management

**Single Target:**
```
T -> 1 -> Enter URL/IP
```

**Batch from File:**
Create `targets.txt`:
```txt
https://example.com
https://test-site.com
192.168.1.1
```

Then:
```
T -> 2 -> targets.txt
```

### Configuration
Access via `C` from main menu:
- Timeout settings
- Output file naming
- Auto-save preferences
- Verbose mode toggle

---

## 📊 Examples

### Example 1: Single Target Full Scan
```bash
# Run CobraScan
python main.py

# Load target
Press T -> 1 -> https://example.com

# Run Web Analyzer
Press 1 -> 8 (Full Reconnaissance)

# Results saved to cobra_scan_results.json
```

### Example 2: Batch Security Check
```bash
# Create target list
echo "https://site1.com" > targets.txt
echo "https://site2.com" >> targets.txt

# Run batch scan
python main.py
Press T -> 2 -> targets.txt
Press 1 -> 9 (Batch Scan)

# Results in batch_YYYYMMDD_HHMMSS.json
```

### Example 3: Quick SSL Check
```bash
python main.py
Press T -> 1 -> https://bank.example.com
Press 1 -> 4 (SSL/TLS Analysis)
```

### Sample JSON Output
```json
{
  "scan_type": "full_recon",
  "timestamp": "2024-01-15T10:30:00Z",
  "target": "https://example.com",
  "results": {
    "http_info": {
      "status_code": 200,
      "headers": {...}
    },
    "dns_info": {
      "a_records": ["93.184.216.34"],
      "mx_records": ["10 mail.example.com."]
    },
    "ssl_info": {
      "valid": true,
      "expires_in": 89,
      "issuer": "Let's Encrypt"
    },
    "security_headers": {
      "hsts": true,
      "csp": false,
      "x_frame_options": true
    },
    "open_ports": [
      {"port": 443, "service": "HTTPS", "status": "open"}
    ]
  }
}
```

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

---

## 🛣️ Roadmap

### Current Modules
- ✅ **Web Analyzer** - Comprehensive web target analysis

### Planned Modules
- 🔄 **Subdomain Scanner** - Automated subdomain discovery
- 📋 **Vulnerability Scanner** - CVE and OWASP Top 10 checks
- 🔌 **API Security Tester** - REST/GraphQL endpoint testing
- 📁 **Directory Brute Forcer** - Hidden file discovery
- 🗺️ **Network Mapper** - Network topology visualization
- 🔍 **OSINT Collector** - Open-source intelligence gathering
- 📝 **Report Generator** - Professional HTML/PDF reports

### Core Enhancements
- ⚡ Multi-threading support
- 🔄 Proxy and Tor integration
- 📊 API integrations (Shodan, VirusTotal)
- 🛡️ WAF detection and evasion
- 📈 Advanced reporting and visualization

---

## 📝 Changelog

### Version 1.2.5 (Current)
-  Modular Architecture: Complete refactor to plugin system
-  Dynamic Module Loading: Automatic menu generation
-  Module Template: Easy module creation
-  Improved Structure: Better code organization
-  Bug Fixes: Banner spacing and error handling

### Version 1.2.0
-  Rebranded to CobraScan
- Target Manager: Single and batch scanning
-  Configuration System: Persistent settings
-  Enhanced UI: Improved user interface

### Version 1.0.0
-  Initial Release
-  Basic Scanning: Core functionality
-  JSON Export: Structured output

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
- [Module Creation Guide](dev/module_creation_guide.md)

### Contact
- **Email**: dev@sinners.city
- **GitHub**: [@Syn2Much](https://github.com/Syn2Much)
- **Website**: [sinners.city](https://sinners.city)

---

<div align="center">

## 🐍 CobraScan - The All-Seeing Reconnaissance Tool

*In the realm of security, visibility is power. CobraScan grants you omniscience.*

**⭐ If you find this useful, please give it a star! ⭐**

[Report Bug](https://github.com/Syn2Much/CobraScan/issues) · 
[Request Feature](https://github.com/Syn2Much/CobraScan/issues) · 
[View Source](https://github.com/Syn2Much/CobraScan)

---

**Made with 🐍 by [Syn2Much](https://github.com/Syn2Much)**

</div>
