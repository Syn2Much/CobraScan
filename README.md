
# Cobra - a penetration testing framework for security professionals and ethical hackers
 

Cobra performs deep web reconnaissance, vulnerability discovery, and pentest report generation through a clean, plugin-based architecture.

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/Syn2Much/CobraScan/graphs/commit-activity)
![Animation](https://github.com/user-attachments/assets/5975113d-16ce-4056-881e-bd42e5235690)

---

## 📌 Overview

**Cobra Scan** is designed to be:

* 🔧 **Extensible** – drop-in modules
* ⚡ **Fast** – multi-threaded where possible
* 📊 **Insightful** – real-time output + structured reports
* 🧩 **Modular** – scan only what you need

Perfect for:

* Web app security testing
* Reconnaissance & attack surface mapping
* Automated pentest report generation

---

## ✨ Key Features

* 🔌 **Modular plugin system**
* 🎯 **Single or batch target scanning**
* 🌐 **HTTP / HTTPS proxy support**
* 💾 **Persistent configuration**
* 📈 **JSON, HTML & PDF reporting**
* 🖥️ **Optional Flask-based web panel**
* 📝 **Verbose, colorized logging**


---

## 🧩 Available Modules

### 🔍 Web Analyzer (v2.0.0)

* HTTP & DNS reconnaissance
* IP geolocation & SSL/TLS analysis
* Security headers & HTTP methods
* Technology fingerprinting
* Performance metrics
* Port scanning (21 common ports)
* 9-phase real-time progress tracking

---

### 🗂️ Sensitive Path Finder (v2.0.0)

* Admin & login panels
* CMS detection (WordPress, Joomla, Drupal, etc.)
* API endpoints (REST, GraphQL, Swagger)
* Sensitive files (`.git`, `.env`, configs)
* Custom wordlists
* Multi-threaded scanning with live alerts

---

### 🌐 Subdomain Enumeration (v2.0.0)

* DNS brute force (quick & deep wordlists)
* Certificate Transparency (`crt.sh`)
* Zone transfer testing
* Reverse DNS lookups
* Custom wordlist support
* Verbose DNS and CT logging

---

### 🚨 Vulnerability Scanner (v2.0.0)

* OWASP Top 10 coverage
* CVE detection
* Injection testing:

  * XSS
  * SQLi
  * Command injection
  * Path traversal
* SSL/TLS misconfigurations
* Security header analysis
* Open redirect testing
* Sensitive file exposure
* Severity-based risk scoring

---

## 📦 Installation

```bash
git clone https://github.com/Syn2Much/CobraScan.git
cd CobraScan
pip install -r requirements.txt
python main.py
```

**Requirements**

* Python **3.8+**
* Linux / macOS / Windows

---

## 🚀 Quick Start

1. **Launch**

   ```bash
   python main.py
   ```

2. **Load Targets**

   * Press `T`
   * Single target or file input (one per line)

3. **(Optional) Load Proxies**

   * Press `P`
   * Load proxy list from file

4. **Run Scans**

   * Select a module
   * Choose scan type
   * View results or export reports

5. **Configure Settings**

   * Press `C`
   * Adjust timeouts, verbosity, output formats

---

## 🧭 Main Menu

```
Available Modules:
1. Web Analyzer
2. Sensitive Path Finder
3. Subdomain Enumeration
4. Vulnerability Scanner

T. Load Targets
P. Load Proxies
R. Results
C. Configuration
H. Help
Q. Exit
```

---

## 📄 Input File Examples

### Targets (`targets.txt`)

```txt
https://example.com
https://test-site.com
192.168.1.1
```

### Proxies (`proxies.txt`)

```txt
192.168.1.100:8080
http://10.0.0.1:3128
https://proxy.example.com:8443
user:password@proxy.corp.com:8080
```

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
├── modules/                # Scan modules
│   ├── web_analyzer.py
│   ├── path_finder.py
│   ├── sub_domain.py
│   └── vuln_scanner.py
├── reports/                # Generated reports
└── guides/                 # Documentation
```

---

## 🛣️ Roadmap

**Current**

* Web Analyzer
* Path Finder
* Subdomain Enumeration
* Vulnerability Scanner
* HTML / PDF Reports

**Planned**

* API Security Tester
* Network Mapper
* OSINT Collector
* Expanded multi-threading
* Tor integration
* WAF detection

---

## ⚖️ Legal Disclaimer

⚠️ **Authorized testing only**

Cobra is intended for legal security testing and educational use.
Unauthorized scanning, abuse, or violations of terms of service are strictly prohibited.

---

## 📞 Support & Contact

* **Email**: [dev@sinners.city](mailto:dev@sinners.city)
* **GitHub**: [@Syn2Much](https://github.com/Syn2Much)
* **Website**: [https://sinners.city](https://sinners.city)

👉 [Report a Bug](https://github.com/Syn2Much/CobraScan/issues)
👉 [Request a Feature](https://github.com/Syn2Much/CobraScan/issues)

---

<div align="center">

⭐ **Star the repo if you find it useful!** ⭐

</div>


