"""utils.helpers birim testleri."""

from __future__ import annotations

from config import PHISHING_KEYWORDS
from utils.helpers import (
    contains_at_symbol,
    count_digits,
    count_subdomains,
    extract_host,
    find_phishing_keywords,
    get_tld,
    has_double_slash_redirect,
    has_https,
    is_ip_address,
    is_valid_url,
    normalize_url,
)


def test_normalize_url_adds_scheme() -> None:
    assert normalize_url("example.com") == "http://example.com"
    assert normalize_url("  https://a.com  ") == "https://a.com"


def test_is_valid_url() -> None:
    assert is_valid_url("https://example.com") is True
    assert is_valid_url("http://not a url") is False


def test_https_and_host_helpers() -> None:
    assert has_https("https://example.com") is True
    assert has_https("http://example.com") is False
    assert extract_host("https://www.example.com/path") == "www.example.com"


def test_ip_detection() -> None:
    assert is_ip_address("192.168.1.1") is True
    assert is_ip_address("example.com") is False


def test_suspicious_patterns() -> None:
    assert contains_at_symbol("https://apple.com@evil.tk/login") is True
    assert has_double_slash_redirect("http://evil.com//bank.com") is True
    assert count_digits("abc12345") == 5
    assert count_subdomains("https://a.b.c.example.com") == 3


def test_tld_and_keywords() -> None:
    assert get_tld("http://login.evil.xyz/path") == "xyz"
    found = find_phishing_keywords("https://secure-login.bank.com", PHISHING_KEYWORDS)
    assert "login" in found
    assert "secure" in found
    assert "bank" in found
