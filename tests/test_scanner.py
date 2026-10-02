import pytest

from appseclens.scanner import normalize_url


def test_https_url():

    assert (
        normalize_url("https://example.com")
        == "https://example.com"
    )


def test_http_url():

    assert (
        normalize_url("http://example.com")
        == "http://example.com"
    )


def test_url_without_scheme():

    assert (
        normalize_url("example.com")
        == "https://example.com"
    )


def test_invalid_scheme():

    with pytest.raises(ValueError):

        normalize_url(
            "ftp://example.com"
        )


def test_empty_url():

    assert normalize_url("") == ""
