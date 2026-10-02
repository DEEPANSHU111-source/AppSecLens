from appseclens.checks import (
    check_cors,
    check_security_headers,
)


class FakeHeaders(dict):
    """Simple case-insensitive headers object."""

    def get(self, key, default=None):
        key_lower = key.lower()

        for existing_key, value in self.items():

            if existing_key.lower() == key_lower:
                return value

        return default


class FakeResponse:
    """Minimal fake response for unit tests."""

    def __init__(
        self,
        headers=None,
        url="https://example.com",
        text=""
    ):
        self.headers = FakeHeaders(
            headers or {}
        )

        self.url = url
        self.text = text

        class RawHeaders:
            def get_all(self, name):
                return []

        class Raw:
            headers = RawHeaders()

        self.raw = Raw()


def test_missing_security_headers():

    response = FakeResponse()

    findings = check_security_headers(response)

    titles = [
        finding.title
        for finding in findings
    ]

    assert "Missing Content-Security-Policy" in titles
    assert "Missing Strict-Transport-Security" in titles


def test_server_header_disclosure():

    response = FakeResponse(
        headers={
            "Server": "ExampleServer/1.0"
        }
    )

    findings = check_security_headers(response)

    titles = [
        finding.title
        for finding in findings
    ]

    assert (
        "Server Header Exposes Server Information"
        in titles
    )


def test_wildcard_cors():

    response = FakeResponse(
        headers={
            "Access-Control-Allow-Origin": "*"
        }
    )

    findings = check_cors(response)

    assert len(findings) == 1
    assert findings[0].severity == "LOW"


def test_credentialed_wildcard_cors():

    response = FakeResponse(
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
    )

    findings = check_cors(response)

    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"
