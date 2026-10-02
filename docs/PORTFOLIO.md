# AppSecLens Portfolio Notes

## Project

AppSecLens is a Python-based passive web application security
posture scanner designed for authorized security assessment.

The project focuses on identifying common security configuration
issues without attempting exploitation.

---

## Main Features

- HTTP/HTTPS security assessment
- Security header analysis
- Cookie security flag analysis
- CORS configuration checks
- HTTPS transport checks
- HTTP form-action detection
- Server technology information disclosure detection
- Basic secret-like pattern detection
- Concurrent target scanning
- JSON reporting
- HTML reporting
- Structured security findings
- Logging
- Automated unit tests

---

## Security Checks

### Security Headers

AppSecLens checks for:

- Content-Security-Policy
- Strict-Transport-Security
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- X-Frame-Options

### Cookie Attributes

The scanner checks:

- Secure
- HttpOnly
- SameSite

### CORS

The scanner identifies:

- Wildcard Access-Control-Allow-Origin
- Wildcard CORS combined with credentials

### Transport Security

The scanner checks:

- HTTP final destinations
- HTTPS pages submitting forms to HTTP destinations

### Information Disclosure

The scanner checks:

- Server header
- X-Powered-By header

### Secret Indicators

The scanner searches for limited patterns such as:

- AWS access-key-like values
- Private-key markers

These detections are indicators only and do not prove
that a credential is valid.

---

## Python Concepts Demonstrated

This project demonstrates:

- Variables
- Data types
- Lists
- Dictionaries
- Functions
- Classes
- Inheritance
- Modules
- Exceptions
- File handling
- JSON
- pathlib
- argparse
- requests
- regular expressions
- subprocess-compatible project architecture
- logging
- ThreadPoolExecutor
- pytest

---

## Architecture

```text
User
 |
 v
CLI
 |
 v
WebAppScanner
 |
 +----> HTTPClient
 |
 +----> Security Checks
 |
 v
ScanResult
 |
 +----> JSON Reporter
 |
 +----> HTML Reporter



workflow.

Target URL
    |
    v
HTTP Request
    |
    v
Response Collection
    |
    +----> Headers
    |
    +----> Cookies
    |
    +----> CORS
    |
    +----> Transport
    |
    +----> Forms
    |
    +----> Secret Indicators
    |
    v
Security Findings
    |
    v
JSON + HTML Report
