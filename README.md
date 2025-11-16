# EOL Security Scanner

A comprehensive penetration testing toolkit for detecting end-of-life (EOL) frameworks and libraries in web applications. This tool helps security professionals identify outdated software components that may pose security risks.

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Features

### 🔍 EOL Scanner (`eol_scanner.py`)
- **Automated Detection**: Scans target URLs and automatically detects frameworks/libraries
- **SSL Bypass**: Support for self-signed certificates and internal testing (`--no-verify-ssl`)
- **Comprehensive Coverage**: Detects Angular, React, Vue, Django, Rails, Laravel, WordPress, Drupal, PHP, Nginx, Apache, and more
- **Security Reporting**: Color-coded severity levels (Critical/Warning/Info)
- **EOL Status**: Checks against endoflife.date API for support status

### ⚡ EOL Quick Checker (`eol_checker.py`)
- **Interactive Mode**: User-friendly prompts for framework and version
- **Quick Check**: Command-line arguments for fast lookups
- **Smart Search**: Fuzzy matching and suggestions for products
- **Detailed Reports**: Release dates, LTS status, days until EOL, security recommendations
- **200+ Products**: Supports all products from endoflife.date database

## Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Setup

1. Clone the repository:
```bash
git clone https://github.com/YOUR_USERNAME/eol-security-scanner.git
cd eol-security-scanner
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### EOL Scanner - Automated Web Scanning

**Basic scan:**
```bash
python eol_scanner.py https://example.com
```

**Scan with SSL bypass** (for internal testing):
```bash
python eol_scanner.py https://internal.corp --no-verify-ssl
# or use short flag
python eol_scanner.py https://192.168.1.100 -k
```

**Example output:**
```
[*] Scanning https://example.com...
[*] Detecting frameworks and libraries...
[*] Checking EOL status...

================================================================================
EOL SECURITY SCAN REPORT
================================================================================
Target URL: https://example.com
Scan Time: 2025-11-16 14:30:45
================================================================================

[+] Detected 3 frameworks/libraries:

[CRITICAL] DJANGO v3.2
        Status: ✗ END OF LIFE
        EOL Date: 2024-04-01
        Support Until: 2024-04-01

[WARNING] JQUERY v2.2.4
        Status: ⚠ NO SECURITY SUPPORT
        EOL Date: 2023-08-15

[INFO] NGINX v1.24.0
        Status: ✓ SUPPORTED
        EOL Date: 2025-04-15

================================================================================
SUMMARY:
  Critical Issues: 1
  Warnings: 1
  Total Detected: 3
================================================================================

[!] RECOMMENDATION: Upgrade end-of-life components immediately!
```

### EOL Quick Checker - Interactive Lookup

**Interactive mode** (recommended for beginners):
```bash
python eol_checker.py
```

Then follow the prompts:
```
Enter framework/product name (e.g., django, dotnet, php): django
[*] Found: django
Enter version for django (e.g., 3.2, 4.0): 3.2
```

**Quick check mode:**
```bash
python eol_checker.py django 3.2
python eol_checker.py dotnet 6.0
python eol_checker.py php 7.4
python eol_checker.py nodejs 16
python eol_checker.py python 3.8
```

**Example output:**
```
======================================================================
PRODUCT: DJANGO
VERSION: 3.2 (Cycle: 3.2)
======================================================================

📦 Release Information:
   Release Date: 2021-04-06
   Latest in Cycle: 3.2.23
   LTS: Yes (Long Term Support)

🛡️  Support Status:
   ✗ Security Support: ENDED on 2024-04-01

⏰ End of Life Status:
   ✗ STATUS: END OF LIFE (ended 229 days ago)
   EOL Date: 2024-04-01

   ⚠️  CRITICAL: This version is no longer maintained!

💡 Security Recommendation:
   🔴 URGENT: Upgrade immediately to a supported version!
======================================================================
```

## Detected Technologies

### Frontend Frameworks
- Angular
- React
- Vue.js
- jQuery
- Bootstrap

### Backend Frameworks
- Django (Python)
- Rails (Ruby)
- Laravel (PHP)
- WordPress
- Drupal

### Servers & Languages
- Nginx
- Apache
- PHP
- Node.js
- Python
- .NET

*And 200+ more products via the Quick Checker!*

## Use Cases

### For Penetration Testers
- **Pre-engagement reconnaissance**: Identify vulnerable components before testing
- **Report generation**: Document EOL software in security assessments
- **Internal testing**: Use SSL bypass for corporate environments
- **Compliance checks**: Verify software is within support lifecycle

### For Security Teams
- **Continuous monitoring**: Regular scans of production systems
- **Patch management**: Prioritize upgrades based on EOL status
- **Vendor assessment**: Check third-party applications
- **Security audits**: Quick verification of software versions

### For Developers
- **Dependency checks**: Ensure your stack is up-to-date
- **Migration planning**: Know when to plan framework upgrades
- **Security awareness**: Understand support timelines

## Legal & Ethical Use

⚠️ **IMPORTANT**: This tool is designed for authorized security testing only.

- ✅ Only scan systems you own or have written permission to test
- ✅ Respect rate limits and server resources
- ✅ Follow responsible disclosure practices
- ❌ Do not use for unauthorized access or malicious purposes
- ❌ Do not perform aggressive scanning without permission

## API Credits

This tool uses the [endoflife.date](https://endoflife.date) API to check EOL status. Please respect their rate limits and consider supporting their project.

## Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Ideas for contributions:
- Additional framework detection patterns
- Export formats (JSON, CSV, XML, HTML)
- Integration with other security tools
- Batch scanning from file
- CVE lookup for EOL versions
- Burp Suite/ZAP proxy integration

## Roadmap

- [ ] Batch URL scanning from file
- [ ] JSON/CSV/HTML report export
- [ ] CVE database integration
- [ ] Proxy support (Burp Suite/ZAP)
- [ ] JavaScript library detection from loaded scripts
- [ ] Recursive crawling mode
- [ ] Docker container support
- [ ] CI/CD integration examples

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Created for the security community by a penetration tester.

## Disclaimer

This tool is provided "as is" without warranty of any kind. The authors are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before testing any systems.

## Acknowledgments

- [endoflife.date](https://endoflife.date) - For providing the comprehensive EOL database
- The security community - For feedback and contributions

---

**Star ⭐ this repository if you find it useful!**

For issues, questions, or suggestions, please open an issue on GitHub.
