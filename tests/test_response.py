"""Tests the sioscgi.response module."""

from __future__ import annotations

import unittest
from typing import ClassVar

import sioscgi.response


class TestGood(unittest.TestCase):
    """Test the normal cases where things work properly."""

    RESPONSES: ClassVar[
        list[tuple[str, str | None, list[tuple[str, str]], bytes | None, bytes]]
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

    Each element is a tuple of (name of subtest, response status, response headers,
    response body, expected transmitted data).
    """

    def test_responses(self: TestGood) -> None:
        """Test the normal cases."""
        for (
            case_name,
            response_status,
            response_headers,
            response_body,
            expected_tx,
        ) in self.RESPONSES:
            with self.subTest(name=case_name):
                uut = sioscgi.response.SCGIWriter()
                acc = uut.send(
                    sioscgi.response.Headers(response_status, response_headers)
                )
                assert acc is not None
                if response_body is not None:
                    to_send = uut.send(sioscgi.response.Body(response_body))
                    assert to_send is not None
                    acc += to_send
                self.assertEqual(acc, expected_tx)
                eof = uut.send(sioscgi.response.End())
                self.assertIsNone(eof)


class TestBadResponseHeaders(unittest.TestCase):
    """Check that various invalid response header structures are caught and rejected."""

    def test_non_latin1_content_type(self: TestBadResponseHeaders) -> None:
        """Test rejection of an unencodable Content-Type header value."""
        with self.assertRaises(sioscgi.response.HeaderNotISO88591Error):
            sioscgi.response.Headers(
                "200 OK", [("Content-Type", "text/Ω"), ("Content-Length", "0")]
            )

    def test_non_latin1_location(self: TestBadResponseHeaders) -> None:
        """Test rejection of an unencodable Location header value."""
        with self.assertRaises(sioscgi.response.HeaderNotISO88591Error):
            sioscgi.response.Headers(
                "301 Moved Permanently",
                [
                    ("Location", "/Ω"),
                    ("Content-Type", "text/plain; charset=UTF-8"),
                    ("Content-Length", "0"),
                ],
            )

    def test_non_latin1_other(self: TestBadResponseHeaders) -> None:
        """Test rejection of an unencodable general header value."""
        with self.assertRaises(sioscgi.response.HeaderNotISO88591Error):
            sioscgi.response.Headers(
                "200 OK",
                [
                    ("Content-Type", "text/plain; charset=UTF-8"),
                    ("Content-Length", "0"),
                    ("Other-Thing", "Ω"),
                ],
            )

    def test_local_redirect_with_content_type(self: TestBadResponseHeaders) -> None:
        """
        Test rejection of a local redirect with a Content-Type.

        A local redirect must not have any headers other than Location.
        """
        with self.assertRaises(sioscgi.response.NonDocumentHeadersError):
            sioscgi.response.Headers(
                None,
                [("Location", "/foo"), ("Content-Type", "text/plain; charset=UTF-8")],
            )

    def test_local_redirect_with_other_header(self: TestBadResponseHeaders) -> None:
        """
        Test rejection of a local redirect with an extra general header.

        A local redirect must not have any headers other than Location.
        """
        with self.assertRaises(sioscgi.response.NonDocumentHeadersError):
            sioscgi.response.Headers(
                None, [("Location", "/foo"), ("Other-Thing", "bar")]
            )

    def test_headers_hop_by_hop(self: TestBadResponseHeaders) -> None:
        """Test trying to send a hop-by-hop header."""
        with self.assertRaises(sioscgi.response.HeaderHopByHopError):
            sioscgi.response.Headers(
                "200 OK",
                [
                    ("Content-Type", "text/plain; charset=UTF-8"),
                    ("Content-Length", "27"),
                    ("Connection", "keep-alive"),
                ],
            )


class TestBadResponseSequence(unittest.TestCase):
    """Test trying to send response events at the wrong time or in the wrong order."""

    def test_response_body_before_headers(self: TestBadResponseSequence) -> None:
        """Test trying to send some response body before sending the headers."""
        uut = sioscgi.response.SCGIWriter()
        self.assertIs(uut.state, sioscgi.response.State.HEADERS)
        tx_body = sioscgi.response.Body(b"abcd")
        with self.assertRaises(sioscgi.response.BadEventInStateError):
            uut.send(tx_body)

    def test_response_end_before_headers(self: TestBadResponseSequence) -> None:
        """Test trying to send the response end marker before sending the headers."""
        uut = sioscgi.response.SCGIWriter()
        self.assertIs(uut.state, sioscgi.response.State.HEADERS)
        with self.assertRaises(sioscgi.response.BadEventInStateError):
            uut.send(sioscgi.response.End())
