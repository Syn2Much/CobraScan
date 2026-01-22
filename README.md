
# CobraScan 🐍

A all in one comprehensive reconnaissance tool that performs multiple security scans and analyses in one unified interactive user interface.


[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/Syn2Much/CobraScan/graphs/commit-activity)


---

## 📚 Menu Options

| Option | Function | Output |
|--------|----------|--------|
| **T** | Load Target (URL/IP or File) | - |
| **1** | Quick Scan (Basic HTTP Info) | Screen |
| **2** | DNS Reconnaissance | Screen |
| **3** | IP & Geolocation Info | Screen |
| **4** | SSL/TLS Certificate Analysis | Screen |
| **5** | Security Headers Analysis | Screen |
| **6** | Port Scanning | Screen |
| **7** | Technology Detection | Screen |
| **8** | Full Reconnaissance Scan | **JSON File** |
| **9** | Batch Scan from Loaded Targets | **JSON File** |
| **C** | Configuration & Settings | - |
| **H** | Help & Information | - |
| **Q** | Exit | - |

---
## 📦 Installation

### Prerequisites
- Python 3
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

Navigate through the menu using the numbered options and keyboard shortcuts. 

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
| **Output File** | JSON output filename | `CobraScan_results.json` |
| **Auto-Save** | Automatically save detailed scans | True |
| **Verbose** | Enable verbose output | True |

### Saving/Loading Configuration

Configuration is saved to `CobraScan_config.json` and persists between sessions.

---


## 📁 Project Structure

```
CobraScan/
│
├── main.py                 # Main GUI application
├── web_analyzer.py         # Core scanning engine
├── target_manager.py       # Target loading and management
├── utils. py                # Helper functions and utilities
├── requirements.txt        # Python dependencies
├── README. md               # This file
│
├── targets.txt             # Sample target list (user-created)
├── CobraScan_config.json    # Configuration file (auto-generated)
└── CobraScan_results.json   # Scan results (auto-generated)
```

---

## 🎓 Examples

### Example 1: Single Target Scan

```
1. Press 'T' to load target
2. Select option '1' (Load Single URL/IP)
3. Enter: https://example.com
4. Press '8' for Full Reconnaissance Scan
5. Results saved to CobraScan_results. json
```

### Example 2: Batch Scanning

```
1. Create targets. txt with multiple URLs
2. Press 'T' to load target
3. Select option '2' (Load from File)
4. Enter: targets.txt
5. Press '9' for Batch Scan
6. Results saved to batch_YYYYMMDD_HHMMSS.json
```

### Example 3: Quick Security Check

```
1. Load target (option T)
2. Press '5' for Security Headers Analysis
3. Review security header presence
4. Press '4' for SSL Certificate check
5. Verify certificate expiration
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

---

## 🛠️ Advanced Usage

### Adding Custom Modules

The modular architecture makes it easy to extend functionality:

```python
# Example: Create custom_scanner.py
class CustomScanner:
    def __init__(self, url):
        self.url = url
    
    def custom_scan(self):
        # Your custom scanning logic
        return {"result": "data"}

# Import in main.py
from custom_scanner import CustomScanner

# Add to menu and integrate
```

### Automation with Scripts

```python
from web_analyzer import WebAnalyzer

# Automated scanning
targets = ["https://site1.com", "https://site2.com"]
for target in targets:
    analyzer = WebAnalyzer(target)
    result = analyzer.full_recon_scan()
    # Process results
```


---

## 📋 Roadmap

### Planned Features

- [ ] **Subdomain Enumeration** - Automated subdomain discovery
- [ ] **Vulnerability Scanning** - CVE detection and analysis
- [ ] **HTML/PDF Reports** - Professional report generation
- [ ] **API Integration** - Shodan, VirusTotal, SecurityTrails
- [ ] **WHOIS Lookup** - Domain registration information
- [ ] **Screenshot Capture** - Automated visual documentation
- [ ] **Custom User Agents** - Configurable request headers
- [ ] **Proxy Support** - SOCKS/HTTP proxy configuration
- [ ] **Plugin System** - Extensible module architecture
- [ ] **Multi-threading** - Concurrent scanning for speed
- [ ] **WAF Detection** - Web Application Firewall identification
- [ ] **API Endpoint Discovery** - REST/GraphQL endpoint enumeration

---

## 📝 Changelog

### Version 2.0.0 (Current)
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

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/Syn2Much/CobraScan/issues)
- **Discussions:** [GitHub Discussions](https://github.com/Syn2Much/CobraScan/discussions)
- **Email:** dev@sinners.city

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


</div>


