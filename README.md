
# OmniScan 🔍

> **Omni** (Latin:  "all", "every") - A comprehensive scanning solution that sees all aspects of your target.

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/Syn2Much/OmniScan/graphs/commit-activity)


---

##  Features

### 🎯 Core Scanning Capabilities
- **Quick Scan** - Fast HTTP reconnaissance with response time analysis
- **DNS Reconnaissance** - A, MX, TXT, and NS record enumeration
- **IP & Geolocation** - IP resolution with geographic location data
- **SSL/TLS Analysis** - Certificate validation and expiration monitoring
- **Security Headers** - Comprehensive security header analysis
- **Port Scanning** - Common port detection with service identification
- **Technology Detection** - CMS, frameworks, and web server fingerprinting
- **Full Reconnaissance** - Complete scan with JSON export

### 🎨 User Interface
- Beautiful color-coded terminal interface
- Interactive menu-driven navigation
- Real-time progress indicators
- Graceful error handling
- Cross-platform support (Windows, Linux, macOS)

### 📋 Target Management
- **Single Target** - Scan individual URLs or IP addresses
- **Batch Scanning** - Load and scan multiple targets from file
- **File Format Support** - Simple text file with one target per line
- **Comment Support** - Use `#` for comments in target files

### 💾 Data Export
- JSON format for detailed scans
- Timestamped batch scan results
- Automatic result logging
- Configurable output files

---

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Quick Start

```bash
# Clone the repository
git clone https://github.com/Syn2Much/OmniScan.git
cd OmniScan

# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

### Manual Installation

```bash
# Install required packages
pip install requests dnspython
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

## 🔧 Configuration

Access the configuration menu by pressing **C** from the main menu.

### Configurable Options

| Setting | Description | Default |
|---------|-------------|---------|
| **Timeout** | Request timeout in seconds | 10 |
| **Output File** | JSON output filename | `OmniScan_results.json` |
| **Auto-Save** | Automatically save detailed scans | True |
| **Verbose** | Enable verbose output | True |

### Saving/Loading Configuration

Configuration is saved to `OmniScan_config.json` and persists between sessions.

---

## 📁 Project Structure

```
OmniScan/
│
├── main.py                 # Main GUI application
├── web_analyzer.py         # Core scanning engine
├── target_manager.py       # Target loading and management
├── utils. py                # Helper functions and utilities
├── requirements.txt        # Python dependencies
├── README. md               # This file
│
├── targets.txt             # Sample target list (user-created)
├── OmniScan_config.json    # Configuration file (auto-generated)
└── OmniScan_results.json   # Scan results (auto-generated)
```

---

## 🎓 Examples

### Example 1: Single Target Scan

```
1. Press 'T' to load target
2. Select option '1' (Load Single URL/IP)
3. Enter: https://example.com
4. Press '8' for Full Reconnaissance Scan
5. Results saved to OmniScan_results. json
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

## 🔒 Security Considerations

### Rate Limiting
- Default timeout: 10 seconds
- Port scanning may trigger IDS/IPS alerts
- Consider rate limiting for batch scans

### Data Privacy
- Scan results may contain sensitive information
- Store results securely
- Comply with data protection regulations (GDPR, etc.)

### Operational Security
- Use VPN when testing remote systems
- Obtain written authorization before testing
- Maintain audit logs of scanning activities

---

## 🐛 Troubleshooting

### Common Issues

**Issue:** DNS resolution errors
```
Solution: Check internet connectivity and DNS settings
Verify target hostname is correct
```

**Issue:** SSL certificate errors
```
Solution: Target may not support HTTPS
Check firewall/proxy settings
```

**Issue:** Port scanning fails
```
Solution: Firewall may be blocking connections
Increase timeout in configuration
Some ports may require elevated privileges
```

**Issue:** Permission denied errors
```
Solution: Run with appropriate permissions
Some operations (port < 1024) may require sudo/admin
```

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Commit your changes**
   ```bash
   git commit -m 'Add amazing feature'
   ```
4. **Push to the branch**
   ```bash
   git push origin feature/amazing-feature
   ```
5. **Open a Pull Request**

### Development Guidelines
- Follow PEP 8 style guide
- Add docstrings to all functions
- Include type hints where appropriate
- Test on multiple platforms
- Update documentation

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
- 🎉 Rebranded to OmniScan
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

## 📄 License

This project is licensed under the MIT License - see below for details: 

```
MIT License

Copyright (c) 2024 OmniScan

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

## 🙏 Acknowledgments

- **Requests Library** - HTTP for Humans
- **dnspython** - DNS toolkit for Python
- **Open Source Community** - For inspiration and support
---

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/Syn2Much/OmniScan/issues)
- **Discussions:** [GitHub Discussions](https://github.com/Syn2Much/OmniScan/discussions)
- **Email:** dev@sinners.city

---

## 📱 Connect

- **GitHub:** [@Syn2Much](https://github.com/Syn2Much)
- **Website:** [sinners.city](https://sinners.city)
- **Email:** dev@sinners.city

---

<div align="center">

**Made with ❤️ by Syn2Much**

### 🌟 OmniScan - See Everything 🌟

*Omnipotent · Omniscient · Omnipresent Reconnaissance*

⭐ **Star this repo if you find it useful!** ⭐

[Report Bug](https://github.com/Syn2Much/OmniScan/issues) · [Request Feature](https://github.com/Syn2Much/OmniScan/issues) · [Documentation](https://github.com/Syn2Much/OmniScan/wiki)

---

**"In the world of reconnaissance, knowledge is power. OmniScan gives you all-seeing eyes."**

</div>
```

