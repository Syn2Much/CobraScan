
# Cobra Scan 🐍

*A powerful, modular reconnaissance tool for security professionals, ethical hackers, and system administrators. Perform deep scans and generate detailed pentest reports on the fly*

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/Syn2Much/CobraScan/graphs/commit-activity)

---
![Animation](https://github.com/user-attachments/assets/24c352a3-f529-468d-b253-28a01961f133)

## ✨ Features

### Core Capabilities

- **🔌 Modular Architecture**: Plugin-based system for easy extension
- **🎯 Target Management**: Single or batch target scanning
- **🌐 Proxy Support**: HTTP/HTTPS proxy rotation from file lists
- **💾 Persistent Configuration**: Save preferences between sessions
- **📈 Export Options**: JSON data export and HTML/PDF reports with optional Flask web panel
- **📝 Verbose Logging**: Real-time colored terminal output with toggle support

### Modules

**Vulnerability Scanner (v1.0.0)**

- OWASP Top 10 coverage, CVE detection, injection testing (XSS, SQLi, command injection, path traversal)
- SSL/TLS analysis, security headers check, sensitive file detection, open redirect testing
- Risk scoring with severity-based findings
- Verbose mode with real-time test progress and vulnerability alerts

**Sensitive Path Finder (v1.0.0)**

- Admin/login paths, CMS detection (WordPress, Joomla, Drupal, etc.)
- API endpoints (REST, GraphQL, Swagger), sensitive files (.git, .env, configs)
- Multi-threaded scanning with custom wordlist support
- Live progress bar and instant path discovery alerts

**Subdomain Enumeration (v1.0.0)**

- DNS bruteforce (quick & deep wordlists), certificate transparency (crt.sh)
- Zone transfer testing, reverse DNS, custom wordlists
- Verbose logging for DNS lookups, CT queries, and zone transfers

**Web Analyzer (v2.0.0)**

- HTTP info, DNS reconnaissance, IP geolocation, SSL/TLS analysis
- Security headers, HTTP methods scan, content analysis, performance metrics
- Port scanning (21 common ports), technology detection
- Real-time verbose logging with 9-phase progress tracking

---

## 📦 Installation

```bash
git clone https://github.com/Syn2Much/CobraScan.git
cd CobraScan
pip install -r requirements.txt
python main.py
```

**Requirements**: Python 3.8+

---

## 🚀 Quick Start

1. **Start**: `python main.py`
2. **Load Targets**: Press `T` → Single target or file (one per line)
3. **Load Proxies** (Optional): Press `P` → Load from file
4. **Run Scans**: Select module → Choose scan type → View/export results
5. **Configure**: Press `C` → Adjust timeout, output settings

### Main Menu

```
Available Modules:
1. Web Analyzer (v2.0.0)
2. Sensitive Path Finder (v1.0.0)
3. Subdomain Enumeration (v1.0.0)
4. Vulnerability Scanner (v1.0.0)

T. Load Target    P. Load Proxies
R. Results        C. Configuration
H. Help           Q. Exit
```

### Target File Example (`targets.txt`)

```txt
https://example.com
https://test-site.com
192.168.1.1
```

### Proxy File Example (`proxies.txt`)

```txt
192.168.1.100:8080
http://10.0.0.1:3128
https://proxy.example.com:8443
user:password@proxy.corp.com:8080
```

---

## 🔌 Module Development

1. **Copy Template**: `cp dev/module_template.py modules/your_module.py`
2. **Customize**: Define `name`, `version`, and `run()` method
3. **Register**: Add import to `main.py`

```python
class YourModule:
    def __init__(self):
        self.name = "Your Module"
        self.version = "1.0.0"
    
    def run(self, config, target_manager, proxy_manager=None):
        # Your logic here
        pass
```

---

## 🛣️ Roadmap

**Current**: Web Analyzer, Path Finder, Subdomain Enum, Vuln Scanner, HTML Reports

**Planned**: API Security Tester, Network Mapper, OSINT Collector, Multi-threading, Tor integration, WAF detection

---

## 📁 Project Structure

```
CobraScan/
├── main.py                 # Entry point
├── helpers/                # Core utilities
│   ├── target_manager.py
│   ├── proxy_manager.py
│   ├── http_client.py
│   └── report_builder.py
├── modules/                # Scan modules (auto-loaded)
│   ├── web_analyzer.py
│   ├── path_finder.py
│   ├── sub_domain.py
│   └── vuln_scanner.py
├── reports/                # Generated reports
└── guides/                 # Documentation
```

---

## ⚖️ Legal Disclaimer

**For authorized security testing only.** Users are responsible for compliance with all applicable laws. Prohibited: unauthorized scanning, malicious activities, violating terms of service.

---

## 📞 Support

**Email**: <dev@sinners.city>  
**GitHub**: [@Syn2Much](https://github.com/Syn2Much)  
**Website**: [sinners.city](https://sinners.city)

[Report Bug](https://github.com/Syn2Much/CobraScan/issues) · [Request Feature](https://github.com/Syn2Much/CobraScan/issues)

---

<div align="center">

**⭐ Star this repo if you find it useful! ⭐**

**Made with 🐍 by [Syn2Much](https://github.com/Syn2Much)**

</div>
