"""Credentials passed in URL query strings must never reach a log handler.

httpx logs every request URL at INFO, and some providers (Reoon) only accept
their API key as ``?key=...``.
"""

import logging

import pytest

from harvey.main import RedactSecrets


def logged(msg, *args):
    record = logging.LogRecord("httpx", logging.INFO, __file__, 1, msg, args, None)
    assert RedactSecrets().filter(record) is True
    return record.getMessage()


@pytest.mark.parametrize("name", ["key", "api_key", "apikey", "token", "access_token", "password"])
def test_secret_query_values_are_masked(name):
    out = logged(f"HTTP Request: GET https://svc.example/v1/verify?a=1&{name}=SECRET123&b=2")

    assert "SECRET123" not in out
    assert f"{name}=<redacted>" in out
    # Neighbouring, non-secret parameters survive.
    assert "a=1" in out and "b=2" in out


def test_masking_works_on_lazy_percent_style_arguments():
    # This is how httpx calls the logger: a format string plus arguments.
    out = logged('HTTP Request: %s %s "%s"', "GET", "https://svc.example/?key=SECRET123", "HTTP/1.1 200 OK")

    assert "SECRET123" not in out
    assert out.startswith("HTTP Request: GET https://svc.example/?key=<redacted>")


def test_messages_without_secrets_are_untouched():
    msg = "Scout: Added SDK.finance team at SDK.finance [backfill]"
    record = logging.LogRecord("harvey.scout", logging.INFO, __file__, 1, msg, (), None)
    RedactSecrets().filter(record)

    assert record.getMessage() == msg
    assert record.msg == msg


def test_a_word_ending_in_key_is_not_mistaken_for_a_secret():
    out = logged("sorted by sort_key=name then monkey=1")

    assert out == "sorted by sort_key=name then monkey=1"
