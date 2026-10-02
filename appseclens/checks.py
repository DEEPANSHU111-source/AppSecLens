import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from .models import Finding


SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "MEDIUM",
        "description": (
            "Content-Security-Policy helps restrict which resources "
            "a browser is allowed to load."
        ),
        "remediation": (
            "Define and deploy a suitable Content-Security-Policy "
            "for the application."
        ),
    },
    "Strict-Transport-Security": {
        "severity": "MEDIUM",
        "description": (
            "HSTS instructs browsers to use HTTPS for future requests."
        ),
        "remediation": (
            "Enable Strict-Transport-Security after confirming "
            "the application is fully HTTPS-compatible."
        ),
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "description": (
            "This header helps prevent MIME-type sniffing."
        ),
        "remediation": (
            "Set X-Content-Type-Options to 'nosniff'."
        ),
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": (
            "Referrer-Policy controls how much referrer information "
            "is sent with requests."
        ),
        "remediation": (
            "Configure a restrictive Referrer-Policy appropriate "
            "for the application."
        ),
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": (
            "Permissions-Policy controls access to selected browser "
            "features."
        ),
        "remediation": (
            "Define a Permissions-Policy that disables unnecessary "
            "browser capabilities."
        ),
    },
    "X-Frame-Options": {
        "severity": "LOW",
        "description": (
            "X-Frame-Options can help reduce clickjacking risk."
        ),
        "remediation": (
            "Set X-Frame-Options to DENY or SAMEORIGIN where "
            "appropriate, or use CSP frame-ancestors."
        ),
    },
}


def create_finding(
    check: str,
    title: str,
    severity: str,
    description: str,
    evidence: str,
    remediation: str,
    references: list[str] | None = None,
) -> Finding:
    """Create a standardized Finding object."""

    return Finding(
        check=check,
        title=title,
        severity=severity,
        description=description,
        evidence=evidence,
        remediation=remediation,
        references=references or [],
    )


def check_security_headers(response) -> list[Finding]:
    """Check for common security headers."""

    findings = []

    headers = {
        key.lower(): value
        for key, value in response.headers.items()
    }

    for header, details in SECURITY_HEADERS.items():

        if header.lower() not in headers:

            findings.append(
                create_finding(
                    check="Security Headers",
                    title=f"Missing {header}",
                    severity=details["severity"],
                    description=details["description"],
                    evidence=f"{header} header was not present.",
                    remediation=details["remediation"],
                    references=[
                        "https://owasp.org/www-project-secure-headers/"
                    ],
                )
            )

    # Server header
    server = response.headers.get("Server")

    if server:

        findings.append(
            create_finding(
                check="Information Disclosure",
                title="Server Header Exposes Server Information",
                severity="INFO",
                description=(
                    "The response contains a Server header that may "
                    "disclose implementation information."
                ),
                evidence=f"Server: {server}",
                remediation=(
                    "Remove unnecessary server identification "
                    "information where practical."
                ),
            )
        )

    # X-Powered-By
    powered_by = response.headers.get("X-Powered-By")

    if powered_by:

        findings.append(
            create_finding(
                check="Information Disclosure",
                title="X-Powered-By Header Exposes Technology",
                severity="INFO",
                description=(
                    "X-Powered-By may reveal application framework "
                    "or runtime information."
                ),
                evidence=f"X-Powered-By: {powered_by}",
                remediation=(
                    "Remove the X-Powered-By header when it is "
                    "not required."
                ),
            )
        )

    return findings


def check_cookies(response) -> list[Finding]:
    """Check security attributes of Set-Cookie headers."""

    findings = []

    try:
        cookies = response.raw.headers.get_all("Set-Cookie")
    except AttributeError:
        cookies = []

    if not cookies:
        return findings

    is_https = response.url.lower().startswith("https://")

    for cookie in cookies:

        cookie_lower = cookie.lower()

        cookie_name = cookie.split("=", 1)[0].strip()

        if is_https and "secure" not in cookie_lower:

            findings.append(
                create_finding(
                    check="Cookie Security",
                    title="Cookie Missing Secure Flag",
                    severity="MEDIUM",
                    description=(
                        "A cookie received over HTTPS does not "
                        "contain the Secure attribute."
                    ),
                    evidence=f"Cookie: {cookie_name}",
                    remediation=(
                        "Set the Secure attribute on cookies that "
                        "should only be transmitted over HTTPS."
                    ),
                )
            )

        if "httponly" not in cookie_lower:

            findings.append(
                create_finding(
                    check="Cookie Security",
                    title="Cookie Missing HttpOnly Flag",
                    severity="LOW",
                    description=(
                        "The cookie does not contain the HttpOnly "
                        "attribute."
                    ),
                    evidence=f"Cookie: {cookie_name}",
                    remediation=(
                        "Use HttpOnly for cookies that do not need "
                        "to be accessed by client-side JavaScript."
                    ),
                )
            )

        if "samesite" not in cookie_lower:

            findings.append(
                create_finding(
                    check="Cookie Security",
                    title="Cookie Missing SameSite Attribute",
                    severity="LOW",
                    description=(
                        "The cookie does not explicitly define "
                        "a SameSite policy."
                    ),
                    evidence=f"Cookie: {cookie_name}",
                    remediation=(
                        "Set SameSite=Lax, Strict, or None according "
                        "to the application's cross-site requirements."
                    ),
                )
            )

    return findings


def check_cors(response) -> list[Finding]:
    """Check for potentially permissive CORS configuration."""

    findings = []

    origin = response.headers.get(
        "Access-Control-Allow-Origin",
        ""
    )

    credentials = response.headers.get(
        "Access-Control-Allow-Credentials",
        ""
    ).lower()

    if origin.strip() == "*":

        if credentials == "true":
            severity = "MEDIUM"
            title = "Wildcard CORS With Credentials"
        else:
            severity = "LOW"
            title = "Wildcard CORS Policy"

        findings.append(
            create_finding(
                check="CORS",
                title=title,
                severity=severity,
                description=(
                    "The response allows requests from any origin "
                    "using a wildcard CORS policy."
                ),
                evidence=(
                    f"Access-Control-Allow-Origin: {origin}; "
                    f"Access-Control-Allow-Credentials: "
                    f"{credentials or 'not set'}"
                ),
                remediation=(
                    "Restrict allowed origins to trusted origins "
                    "when cross-origin access is required."
                ),
            )
        )

    return findings


def check_transport(response) -> list[Finding]:
    """Check whether the final URL uses HTTPS."""

    findings = []

    final_url = response.url

    parsed = urlparse(final_url)

    if parsed.scheme.lower() == "http":

        findings.append(
            create_finding(
                check="Transport Security",
                title="Application Uses HTTP",
                severity="MEDIUM",
                description=(
                    "The final URL uses unencrypted HTTP instead of HTTPS."
                ),
                evidence=f"Final URL: {final_url}",
                remediation=(
                    "Serve the application over HTTPS and redirect "
                    "HTTP traffic to HTTPS."
                ),
            )
        )

    return findings


def check_forms(response) -> list[Finding]:
    """Check whether HTTPS pages submit forms to HTTP URLs."""

    findings = []

    if not response.text:
        return findings

    page_url = response.url

    if not page_url.lower().startswith("https://"):
        return findings

    soup = BeautifulSoup(
        response.text,
        "html.parser"
    )

    forms = soup.find_all("form")

    for form in forms:

        action = form.get("action", "").strip()

        if not action:
            continue

        parsed = urlparse(action)

        if parsed.scheme.lower() == "http":

            findings.append(
                create_finding(
                    check="Transport Security",
                    title="HTTPS Page Contains HTTP Form Action",
                    severity="HIGH",
                    description=(
                        "A secure HTTPS page contains a form that "
                        "submits data to an HTTP destination."
                    ),
                    evidence=f"Form action: {action}",
                    remediation=(
                        "Use HTTPS for form submission endpoints."
                    ),
                )
            )

    return findings


def check_secret_indicators(response) -> list[Finding]:
    """
    Search response text for simple secret-like indicators.

    These are indicators only and are not proof of a valid secret.
    """

    findings = []

    body = response.text or ""

    patterns = {
        "AWS Access Key Pattern": r"\bAKIA[0-9A-Z]{16}\b",
        "Private Key Marker": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    }

    for name, pattern in patterns.items():

        if re.search(pattern, body):

            findings.append(
                create_finding(
                    check="Secret Indicators",
                    title=f"Potential {name}",
                    severity="HIGH",
                    description=(
                        "A response contains a string matching a "
                        "known secret-like pattern."
                    ),
                    evidence=(
                        f"Pattern detected: {name}. "
                        "The value was not validated as a real credential."
                    ),
                    remediation=(
                        "Remove secrets from public responses and rotate "
                        "any credential that is confirmed to be exposed."
                    ),
                )
            )

    return findings


def run_all_checks(response) -> list[Finding]:
    """Run all passive checks against a response."""

    findings = []

    checks = [
        check_security_headers,
        check_cookies,
        check_cors,
        check_transport,
        check_forms,
        check_secret_indicators,
    ]

    for check in checks:
        findings.extend(check(response))

    return findings
