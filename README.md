
# CobraScan 🐍

A modular, all-in-one comprehensive reconnaissance tool that performs multiple security scans and analyses through an unified interactive interface with extensible module architecture.

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/Syn2Much/CobraScan/graphs/commit-activity)

---

## 🎯 Key Features

- **🔌 Modular Architecture** - Easy to extend with custom modules
- **📊 Multiple Scan Types** - DNS, SSL, ports, headers, and more
- **🎨 Interactive CLI** - Beautiful, user-friendly interface
- **📦 Batch Processing** - Scan multiple targets simultaneously
- **💾 JSON Export** - Structured data for further analysis
- **⚙️ Persistent Config** - Save your preferences
- **🚀 Template System** - Create new modules in minutes

---

## 📚 Main Menu

```
┌─────────────────────────────────────────────────────────────┐
│ Available Modules:                                          │
│ 1. Web Analyzer                                             │
│ 2. [Future Module]                                          │
│ 3. [Future Module]                                          │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ T.   Load Target (URL/IP or File)                           │
│ C.  Configuration & Settings                                │
│ H. Help & Information                                       │
│ Q. Exit                                                     │
└─────────────────────────────────────────────────────────────┘
```

### Web Analyzer Module

| Option | Function | Output |
|--------|----------|--------|
| **1** | Quick Scan (Basic HTTP Info) | Screen |
| **2** | DNS Reconnaissance | Screen |
| **3** | IP & Geolocation Info | Screen |
| **4** | SSL/TLS Certificate Analysis | Screen |
| **5** | Security Headers Analysis | Screen |
| **6** | Port Scanning | Screen |
| **7** | Technology Detection | Screen |
| **8** | Full Reconnaissance Scan | **JSON File** |
| **9** | Batch Scan from Loaded Targets | **JSON File** |
| **B** | Back to Main Menu | - |

---

## 📦 Installation

### Prerequisites
- Python 3.8+
- pip package manager

### Quick Start

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

## 🚀 Usage

### Interactive Mode (Recommended)

```bash
python main.py
```

1. Select a module from the main menu (e.g., `1` for Web Analyzer)
2. Choose your scan type from the module menu
3. Enter target URL or load from file
4. Review results on screen or in JSON output

### Target File Format

Create a text file (e.g., `targets.txt`) with one URL/IP per line:

```text
# Production servers
https://example.com
https://subdomain.example.com

# Testing
http://192.168.1.1
test-site.com

# Client sites
https://client1.com
https://client2.net
```

---

## 🔧 Configuration

Access the configuration menu by pressing **C** from the main menu.

### Configurable Options

| Setting | Description | Default |
|---------|-------------|---------|
| **Timeout** | Request timeout in seconds | 10 |
| **Output File** | JSON output filename | `cobra_scan_results.json` |
| **Auto-Save** | Automatically save detailed scans | True |
| **Verbose** | Enable verbose output | True |

### Saving/Loading Configuration

Configuration is saved to `cobra_config.json` and persists between sessions.

---

## 📁 Project Structure

```
CobraScan/
│
├── main.py                 # Main GUI framework & module loader
├── target_manager.py       # Target loading and management
├── utils. py                # Helper functions and utilities
├── requirements.txt        # Python dependencies
├── README.md               # This file
│
├── modules/                # Module directory
│   ├── __init__.py         # Package initializer
│   ├── web_analyzer.py     # Web analysis module
│   └── module_template.py  # Template for new modules
│
├── targets. txt             # Sample target list (user-created)
├── cobra_config. json       # Configuration file (auto-generated)
└── cobra_scan_results.json # Scan results (auto-generated)
```

---

## 🔌 Creating Custom Modules

CobraScan's modular architecture makes it easy to extend functionality. 

### Quick Start:  Copy the Template

```bash
# Copy the module template
cp dev/module_template.py modules/your_module. py
```

### Customize Your Module

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
    
    def _print_module_banner(self):
        """Display your module banner."""
        pass
    
    def _your_scan_function(self, config, target_manager):
        """Your custom scan logic."""
        pass
```

### Register Your Module

Add to `main.py` in the `_load_modules()` method:

```python
def _load_modules(self):
    """Load all available modules."""
    try:
        from modules.web_analyzer import WebAnalyzerModule
        self.modules['web_analyzer'] = WebAnalyzerModule()
        
        # Add your module
        from modules.your_module import YourModuleName
        self.modules['your_module'] = YourModuleName()
        
    except ImportError as e:
        print(f"Error loading modules: {e}")
```

### Module Contribution Guidelines

- Follow the module template structure
- Include docstrings for all functions
- Add error handling
- Test with multiple targets
- Update README with new module info

---


## 🎓 Examples

### Example 1: Single Target Scan

```
1. Run:  python main.py
2. Press '1' to load Web Analyzer module
3. Press 'T' (from main menu) to load target
4. Select option '1' (Load Single URL/IP)
5. Enter: https://example.com
6. Press '8' for Full Reconnaissance Scan
7. Results saved to cobra_scan_results. json
```

### Example 2:  Batch Scanning

```
1. Create targets.txt with multiple URLs
2. Run: python main.py
3. Press 'T' to load target
4. Select option '2' (Load from File)
5. Enter: targets.txt
6. Press '1' to open Web Analyzer
7. Press '9' for Batch Scan
8. Results saved to batch_YYYYMMDD_HHMMSS.json
```

### Example 3: Quick Security Check

```
1. Load target (option T)
2. Press '1' to open Web Analyzer
3. Press '5' for Security Headers Analysis
4. Review security header presence
5. Press '4' for SSL Certificate check
6. Verify certificate expiration
```

---

## 📊 Sample Output

### JSON Output Example
```json
{
  "url": "https://example.com/",
  "hostname": "example.com",
  "status_code": 200,
  "dns_info": {
    "a_records": ["93.184.216.34"],
    "mx_records": ["10 mail.example.com. "]
  },
  "ip_info": {
    "ip_address": "93.184.216.34",
    "geolocation": {
      "country": "United States",
      "city": "Norwell"
    }
  },
  "ssl_info": {
    "days_until_expiry": 365,
    "tls_version": "TLSv1.3"
  },
  "open_ports": [
    {"port": 80, "service": "HTTP", "status": "open"},
    {"port": 443, "service": "HTTPS", "status": "open"}
  ],
  "technologies": {
    "web_server": "nginx",
    "cms": "WordPress"
  }
}
```


## 📋 Roadmap

### Current Modules
- [x] **Web Analyzer** - HTTP, DNS, SSL, ports, headers, tech detection

### Planned Modules

- [ ] **Subdomain Enumerator** - Automated subdomain discovery
- [ ] **Vulnerability Scanner** - CVE detection and OWASP Top 10
- [ ] **API Tester** - REST/GraphQL endpoint testing
- [ ] **Content Discovery** - Hidden files and directory enumeration
- [ ] **Network Mapper** - Network topology visualization
- [ ] **OSINT Collector** - Open-source intelligence gathering
- [ ] **WordPress Scanner** - WP-specific vulnerability detection
- [ ] **SQL Injection Tester** - Automated SQLi detection
- [ ] **XSS Detector** - Cross-site scripting vulnerability finder
- [ ] **Report Generator** - HTML/PDF professional reports

### Core Features

- [ ] **Multi-threading** - Concurrent scanning for speed
- [ ] **Proxy Support** - SOCKS/HTTP proxy configuration
- [ ] **API Integration** - Shodan, VirusTotal, SecurityTrails
- [ ] **WAF Detection** - Web Application Firewall identification
- [ ] **Rate Limiting** - Respectful scanning controls
- [ ] **Custom User Agents** - Configurable request headers
- [ ] **Export Formats** - CSV, XML, HTML reports
- [ ] **Scheduled Scans** - Automated periodic scanning
- [ ] **Diff Mode** - Compare scan results over time
- [ ] **Notification System** - Email/Slack/Discord alerts

---

## 📝 Changelog

### Version 1.2.5 (Current)
- 🎉 **Modular Architecture** - Complete refactor to plugin system
- ✨ Dynamic module loading and menu generation
- ✨ Module template for easy extension
- ✨ Improved code organization and maintainability
- ✨ Separated GUI framework from business logic
- 🐛 Fixed banner spacing issues
- 📚 Added module creation guide

### Version 1.2.0
- 🎉 Rebranded to CobraScan
- ✨ Modular architecture with separate files
- ✨ Target manager for single/batch scanning
- ✨ Enhanced error handling
- ✨ Configuration persistence
- ✨ Improved user interface

### Version 1.0.0
- 🎉 Initial release
- ✅ Basic scanning functionality
- ✅ Interactive CLI interface
- ✅ JSON export capability

---

## ⚠️ Legal Disclaimer

**IMPORTANT:** This tool is designed for **authorized security testing and research purposes only**. 

### Ethical Use Guidelines

✅ **DO:**
- Use on systems you own or have explicit permission to test
- Respect robots.txt and terms of service
- Use for educational and security research
- Report vulnerabilities responsibly

❌ **DON'T:**
- Scan systems without authorization
- Use for malicious purposes
- Violate computer fraud laws
- Cause service disruption

**Users are solely responsible for compliance with all applicable laws and regulations.**

---

## 📄 License

This project is licensed under the MIT License - see below for details: 

```
MIT License

Copyright (c) 2024 CobraScan

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. 
```

---

## 👥 Authors

- **Syn2Much** - *Creator & Lead Developer* - [@Syn2Much](https://github.com/Syn2Much)

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/AmazingModule`)
3. **Create your module** using the template
4. **Commit your changes** (`git commit -m 'Add:  Amazing new module'`)
5. **Push to branch** (`git push origin feature/AmazingModule`)
6. **Open a Pull Request**


## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/Syn2Much/CobraScan/issues)
- **Discussions:** [GitHub Discussions](https://github.com/Syn2Much/CobraScan/discussions)
- **Email:** dev@sinners. city

---

## 📱 Connect

- **GitHub:** [@Syn2Much](https://github.com/Syn2Much)
- **Website:** [sinners.city](https://sinners.city)
- **Email:** dev@sinners.city

---

<div align="center">

### 🕵️ CobraScan - The All Knowing Recon Tool 🕵️

*"In the world of reconnaissance, knowledge is power. CobraScan gives you all-seeing eyes."*

⭐ **Star this repo if you find it useful!** ⭐

[Report Bug](https://github.com/Syn2Much/CobraScan/issues) · [Request Feature](https://github.com/Syn2Much/CobraScan/issues) · [Documentation](https://github.com/Syn2Much/CobraScan/wiki)

---

**Made with 🐍 by Syn2Much**

</div>
```
