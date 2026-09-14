"""Tests the sioscgi.response module."""

from __future__ import annotations

import pytest

import sioscgi.response

_GOOD_RESPONSES: list[
    tuple[str, str | None, list[tuple[str, str]], bytes | None, bytes]
] = [
    (
        "Standard response with document",
        "200 OK",
        [("Content-Type", "text/plain; charset=UTF-8"), ("Content-Length", "2")],
        b"42",
        (
            b"Content-Type: text/plain; charset=UTF-8\r\n"
            b"Status: 200 OK\r\n"
            b"Content-Length: 2\r\n"
            b"\r\n"
            b"42"
        ),
    ),
    (
        "Local redirect",
        None,
        [("Location", "/foo")],
        None,
        b"Location: /foo\r\n\r\n",
    ),
    (
        "Client redirect with document",
        "301 Moved Permanently",
        [
            ("Content-Type", "text/plain; charset=UTF-8"),
            ("Content-Length", "5"),
            ("Location", "/foo"),
        ],
        b"moved",
        (
            b"Location: /foo\r\n"
            b"Status: 301 Moved Permanently\r\n"
            b"Content-Type: text/plain; charset=UTF-8\r\n"
            b"Content-Length: 5\r\n"
            b"\r\n"
            b"moved"
        ),
    ),
]
"""
The responses to generate.

Each element is a tuple of (name of subtest, response status, response headers, response
body, expected transmitted data).
"""


@pytest.mark.parametrize("case", _GOOD_RESPONSES, ids=lambda case: case[0])
def test_responses(
    case: tuple[str, str | None, list[tuple[str, str]], bytes | None, bytes],
) -> None:
    """Test the normal cases."""
    (_, response_status, response_headers, response_body, expected_tx) = case
    uut = sioscgi.response.SCGIWriter()
    acc = uut.send(sioscgi.response.Headers(response_status, response_headers))
    assert acc is not None
    if response_body is not None:
        to_send = uut.send(sioscgi.response.Body(response_body))
        assert to_send is not None
        acc += to_send
    assert acc == expected_tx
    eof = uut.send(sioscgi.response.End())
    assert eof is None


def test_non_latin1_content_type() -> None:
    """Test rejection of an unencodable Content-Type header value."""
    with pytest.raises(sioscgi.response.HeaderNotISO88591Error):
        sioscgi.response.Headers(
            "200 OK", [("Content-Type", "text/Ω"), ("Content-Length", "0")]
        )


def test_non_latin1_location() -> None:
    """Test rejection of an unencodable Location header value."""
    with pytest.raises(sioscgi.response.HeaderNotISO88591Error):
        sioscgi.response.Headers(
            "301 Moved Permanently",
            [
                ("Location", "/Ω"),
                ("Content-Type", "text/plain; charset=UTF-8"),
                ("Content-Length", "0"),
            ],
        )


def test_non_latin1_other() -> None:
    """Test rejection of an unencodable general header value."""
    with pytest.raises(sioscgi.response.HeaderNotISO88591Error):
        sioscgi.response.Headers(
            "200 OK",
            [
                ("Content-Type", "text/plain; charset=UTF-8"),
                ("Content-Length", "0"),
                ("Other-Thing", "Ω"),
            ],
        )


def test_local_redirect_with_content_type() -> None:
    """
    Test rejection of a local redirect with a Content-Type.

    A local redirect must not have any headers other than Location.
    """
    with pytest.raises(sioscgi.response.NonDocumentHeadersError):
        sioscgi.response.Headers(
            None,
            [("Location", "/foo"), ("Content-Type", "text/plain; charset=UTF-8")],
        )


def test_local_redirect_with_other_header() -> None:
    """
    Test rejection of a local redirect with an extra general header.

    A local redirect must not have any headers other than Location.
    """
    with pytest.raises(sioscgi.response.NonDocumentHeadersError):
        sioscgi.response.Headers(None, [("Location", "/foo"), ("Other-Thing", "bar")])


def test_headers_hop_by_hop() -> None:
    """Test trying to send a hop-by-hop header."""
    with pytest.raises(sioscgi.response.HeaderHopByHopError):
        sioscgi.response.Headers(
            "200 OK",
            [
                ("Content-Type", "text/plain; charset=UTF-8"),
                ("Content-Length", "27"),
                ("Connection", "keep-alive"),
            ],
        )


def test_response_body_before_headers() -> None:
    """Test trying to send some response body before sending the headers."""
    uut = sioscgi.response.SCGIWriter()
    assert uut.state is sioscgi.response.State.HEADERS
    tx_body = sioscgi.response.Body(b"abcd")
    with pytest.raises(sioscgi.response.BadEventInStateError):
        uut.send(tx_body)


def test_response_end_before_headers() -> None:
    """Test trying to send the response end marker before sending the headers."""
    uut = sioscgi.response.SCGIWriter()
    assert uut.state is sioscgi.response.State.HEADERS
    with pytest.raises(sioscgi.response.BadEventInStateError):
        uut.send(sioscgi.response.End())
