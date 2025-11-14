# WebSafeScan

WebSafeScan is a simple, non-exploitative Bash tool that checks basic website security such as:
- Security headers  
- Cookie flags  
- Allowed HTTP methods  
- Server / X-Powered-By disclosure  
- TLS/SSL configuration (via sslyze or openssl)

⚠️ **Use this tool only on websites you own or have written permission to test.**

---

## Requirements

Minimum:
- Bash
- curl
- openssl

Recommended (for full TLS checks):
- pipx
- sslyze

---

## Installation

### Option 1 — Recommended (pipx + sslyze)
```bash
sudo apt update
sudo apt install -y curl openssl python3 python3-pip pipx
python3 -m pipx ensurepath
pipx install sslyze
````

Make the script executable:

```bash
chmod +x detailed_webscan.sh
```

### Option 2 — Minimal install

```bash
sudo apt install -y curl openssl
chmod +x detailed_webscan.sh
```

(SSL checks will be basic without sslyze.)

---

## Usage

Basic scan:

```bash
./detailed_webscan.sh https://example.com
```

Save the output:

```bash
./detailed_webscan.sh https://example.com > report.txt
```

---

## What It Checks

* Missing/present security headers
* Cookies with/without Secure & HttpOnly flags
* Allowed HTTP methods (OPTIONS, TRACE, etc.)
* Server information disclosure
* TLS/SSL certificate & cipher info (if sslyze is installed)
* Basic compliance warnings

---


## Legal Notice

This tool is for **authorized security testing only**.
The author is not responsible for misuse.

---
