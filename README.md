# 🛡️ WebSafeScan

**Advanced Bash-based Web Security Scanner for Security Headers, SSL/TLS Validation, Cookie Analysis, and Server Security Assessment**

---

## Overview

WebSafeScan is a lightweight Bash-based security assessment tool that automates common web security checks without performing exploitation or intrusive testing.

It helps security professionals, students, and system administrators quickly identify common security misconfigurations on websites.

> ⚠️ **This tool is intended for authorized security testing only.**

---

## Features

✔ Security Header Analysis

✔ Cookie Security Analysis

✔ HTTP Method Enumeration

✔ Server & X-Powered-By Disclosure Detection

✔ SSL/TLS Validation (SSLYze or OpenSSL)

✔ Compliance Warnings

✔ Simple Terminal Reports

---

## Requirements

### Minimum

* Bash
* curl
* OpenSSL

### Recommended

* Python
* pipx
* SSLYze

---

## Installation

### Full Installation

```bash
sudo apt update
sudo apt install -y curl openssl python3 python3-pip pipx
python3 -m pipx ensurepath
pipx install sslyze
chmod +x detailed_webscan.sh
```

### Minimal Installation

```bash
sudo apt install -y curl openssl
chmod +x detailed_webscan.sh
```

---

## Usage

Run a scan

```bash
./detailed_webscan.sh https://example.com
```

Save results

```bash
./detailed_webscan.sh https://example.com > report.txt
```

---

## Security Checks

* HTTP Security Headers
* Secure & HttpOnly Cookie Flags
* Allowed HTTP Methods
* Server Banner Disclosure
* X-Powered-By Detection
* TLS/SSL Certificate Validation
* Cipher Information
* Basic Security Recommendations

---

## Example Output

```text
Target: https://example.com

Checking Security Headers...
✔ HSTS Found
✘ Content-Security-Policy Missing

Checking Cookies...
✔ Secure Cookie
✔ HttpOnly Cookie

Checking TLS...
✔ TLS 1.3 Supported

Scan Completed
```

---

## Project Structure

```text
websafe-scan/
├── README.md
├── detailed_webscan.sh
├── LICENSE
├── CHANGELOG.md
├── screenshots/
└── examples/
```

---

## Roadmap

* JSON Report Export
* HTML Report Generation
* PDF Reports
* Multi-target Scanning
* Docker Support
* GitHub Actions Integration

---

## License

Released under the MIT License.

---

## Author

**Muhammed Fasal**

Cybersecurity Researcher | VAPT Specialist | IT Administrator

GitHub: https://github.com/Fasal17

Portfolio: https://fasal17.github.io/Muhammed-Fasal/

LinkedIn: https://linkedin.com/in/muhammed-fasal-ms

Bugcrowd: https://bugcrowd.com/h/Fasal17
