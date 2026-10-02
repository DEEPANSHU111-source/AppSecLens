# AppSecLens

> A modular Python CLI for passive web application security assessment with concurrent HTTP scanning, automated security checks, and JSON/HTML reporting.

AppSecLens is a Python-based **Web Application Security Posture Scanner** designed to identify common security configuration issues in web applications.

The project focuses on **passive security assessment and security automation** rather than exploitation.

---

## Features

* Passive web application security assessment
* Concurrent HTTP scanning
* Security header analysis
* Cookie security checks
* CORS configuration checks
* HTTPS/HTTP transport checks
* HTTP form-action detection
* Server information disclosure detection
* `X-Powered-By` detection
* Basic secret-like pattern detection
* Structured security findings
* JSON report generation
* HTML report generation
* Logging
* Automated unit testing
* Command-line interface

---

## Security Checks

### Security Headers

AppSecLens checks for commonly recommended security headers:

* Content-Security-Policy
* Strict-Transport-Security
* X-Content-Type-Options
* Referrer-Policy
* Permissions-Policy
* X-Frame-Options

### Cookie Security

The scanner checks cookie attributes including:

* `Secure`
* `HttpOnly`
* `SameSite`

### CORS

The scanner identifies potentially permissive CORS configurations, including:

```text
Access-Control-Allow-Origin: *
```

It also detects wildcard CORS combined with credentials.

### Transport Security

Checks include:

* HTTP final destinations
* HTTPS pages submitting forms to HTTP destinations

### Information Disclosure

The scanner checks for potentially unnecessary technology information exposed through:

* `Server`
* `X-Powered-By`

### Secret Indicators

AppSecLens searches responses for limited secret-like patterns such as:

* AWS access-key-like values
* Private-key markers

These detections are **indicators only** and do not prove that a credential is valid.

---

## Architecture

```text
                    AppSecLens
                        |
                        v
                       CLI
                        |
                        v
                  WebAppScanner
                        |
             +----------+----------+
             |                     |
             v                     v
        HTTPClient            Security Checks
                                   |
              +--------------------+--------------------+
              |          |          |         |         |
              v          v          v         v         v
           Headers     Cookies     CORS    Transport   Forms
                                                        |
                                                        v
                                               Secret Indicators
                                                        |
                                                        v
                                                  ScanResult
                                                        |
                                      +-----------------+----------------+
                                      |                                  |
                                      v                                  v
                                JSON Report                         HTML Report
```

---

## Project Structure

```text
AppSecLens/
│
├── appseclens/
│   ├── __init__.py
│   ├── checks.py
│   ├── cli.py
│   ├── http_client.py
│   ├── logger.py
│   ├── models.py
│   ├── reporter.py
│   └── scanner.py
│
├── tests/
│   ├── test_checks.py
│   └── test_scanner.py
│
├── docs/
│   └── PORTFOLIO.md
│
├── main.py
├── requirements.txt
├── targets.txt
├── pyproject.toml
├── .gitignore
└── README.md
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/AppSecLens.git
cd AppSecLens
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it.

### Linux / Kali

```bash
source .venv/bin/activate
```

### Windows

```powershell
.venv\Scripts\activate
```

Install the dependencies:

```bash
pip install -r requirements.txt
```

---

## Usage

### Scan a single URL

```bash
python main.py -u https://example.com
```

### Scan multiple targets

Add authorized targets to `targets.txt`:

```text
https://example.com
https://example.org
```

Then run:

```bash
python main.py -f targets.txt
```

### Increase concurrent workers

```bash
python main.py -f targets.txt -w 10
```

### Change request timeout

```bash
python main.py -u https://example.com -t 15
```

### Enable verbose logging

```bash
python main.py -u https://example.com -v
```

### Specify an output directory

```bash
python main.py -u https://example.com -o my-report
```

---

## Example Output

```text
=== AppSecLens Summary ===
Critical : 0
High     : 1
Medium   : 3
Low      : 4
Info     : 2

=== Target Results ===

https://example.com -> 200
Final URL: https://example.com/
Response Time: 245.31 ms

  [MEDIUM] Missing Content-Security-Policy
  [LOW] Missing Referrer-Policy
  [INFO] Server Header Exposes Server Information
```

---

## Reports

After a scan, AppSecLens generates:

```text
reports/
├── report.json
└── report.html
```

### JSON Report

The JSON report contains structured scan results including:

* Target URL
* Final URL
* HTTP status
* Response time
* Findings
* Severity
* Evidence
* Remediation
* Errors

### HTML Report

The HTML report provides a human-readable security assessment containing:

* Severity summary
* Target
* Security check
* Finding
* Evidence
* Remediation

---

## Testing

Run the test suite with:

```bash
pytest
```

The tests cover areas such as:

* URL normalization
* Invalid URL schemes
* Missing security headers
* Server information disclosure
* Wildcard CORS
* Credentialed wildcard CORS

---

## Technologies Used

* Python
* Requests
* BeautifulSoup
* argparse
* ThreadPoolExecutor
* Regular Expressions
* Logging
* JSON
* pytest
* HTML/CSS

---

## Python Concepts Demonstrated

This project applies practical Python concepts including:

* Functions
* Lists and dictionaries
* File handling
* `pathlib`
* JSON
* Exception handling
* Modules and imports
* OOP
* Inheritance
* HTTP requests
* `argparse`
* Regular expressions
* Logging
* Multithreading
* Automated testing

---

## Security Scope

AppSecLens is intentionally designed as a **passive security posture scanner**.

It does not perform active exploitation such as:

* SQL injection exploitation
* XSS exploitation
* Brute-force attacks
* Authentication bypass
* Command execution
* Malicious file uploads
* Destructive testing

The goal is to identify security configuration issues and provide actionable evidence and remediation guidance.

---

## Responsible Use

Use AppSecLens only against:

* Applications you own
* Local security labs
* Development environments
* Systems for which you have explicit authorization to test

Do not scan third-party systems without permission.

---

## Future Improvements

Planned improvements include:

* [ ] Additional security headers
* [ ] Improved cookie parsing
* [ ] Technology fingerprinting
* [ ] OpenAPI analysis
* [ ] API security checks
* [ ] Configurable security rules
* [ ] SARIF output
* [ ] CI/CD integration
* [ ] Improved HTML dashboard
* [ ] Better false-positive handling

---

## Author

**Deepanshu Deswal**

B.Tech Computer Science Engineering

Cybersecurity | Application Security | Security Automation

### Areas of Interest

* Web Application Security
* API Security
* Vulnerability Assessment
* Security Automation
* Bug Bounty Research
* Cloud Security

---

## Disclaimer

AppSecLens is intended for authorized security testing, education, and defensive security research.

Always obtain permission before testing systems that you do not own.
