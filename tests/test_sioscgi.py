"""Tests the sioscgi module."""

from __future__ import annotations

import unittest

import sioscgi


class TestGood(unittest.TestCase):
    """Test the normal cases where things work properly."""

    RX_DATA = b"70:CONTENT_LENGTH\x0027\x00SCGI\x001\x00REQUEST_METHOD\x00POST\x00REQUEST_URI\x00/deepthought\x00,What is the answer to life?"
    """The raw received bytes."""
    RX_HEADERS = {
        "CONTENT_LENGTH": b"27",
        "SCGI": b"1",
        "REQUEST_METHOD": b"POST",
        "REQUEST_URI": b"/deepthought",
    }
    """The expected decoded request headers."""
    RX_BODY = b"What is the answer to life?"
    """The expected decoded request body."""

    RESPONSES = [
        (
            "Standard response with document",
            "200 OK",
            [("Content-Type", "text/plain; charset=UTF-8"), ("Content-Length", "2")],
            b"42",
            b"Content-Type: text/plain; charset=UTF-8\r\nStatus: 200 OK\r\nContent-Length: 2\r\n\r\n42",
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
            b"Location: /foo\r\nStatus: 301 Moved Permanently\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Length: 5\r\n\r\nmoved",
        ),
    ]
    """
    The responses to generate.

    Each element is a tuple of (name of subtest, response status, response headers,
    response body, expected transmitted data).
    """

    def test_big_buffer(self: TestGood) -> None:
        """
        Test the normal cases with a big buffer.

        The incoming raw data is delivered in one full chunk, and the response body is
        generated the same way.
        """
        for (
            case_name,
            response_status,
            response_headers,
            response_body,
            expected_tx,
        ) in self.RESPONSES:
            with self.subTest(name=case_name):
                uut = sioscgi.SCGIConnection()
                uut.receive_data(self.RX_DATA)
                uut.receive_data(b"")
                self.assertIs(uut.rx_state, sioscgi.RXState.DONE)
                self.assertIs(uut.tx_state, sioscgi.TXState.HEADERS)
                evt = uut.next_event()
                assert isinstance(evt, sioscgi.RequestHeaders)
                self.assertEqual(evt.environment, self.RX_HEADERS)
                evt = uut.next_event()
                assert isinstance(evt, sioscgi.RequestBody)
                self.assertEqual(evt.data, self.RX_BODY)
                evt = uut.next_event()
                self.assertIsInstance(evt, sioscgi.RequestEnd)
                evt = uut.next_event()
                self.assertIsNone(evt)
                acc = uut.send(
                    sioscgi.ResponseHeaders(response_status, response_headers)
                )
                assert acc is not None
                if response_body is not None:
                    to_send = uut.send(sioscgi.ResponseBody(response_body))
                    assert to_send is not None
                    acc += to_send
                self.assertEqual(acc, expected_tx)
                eof = uut.send(sioscgi.ResponseEnd())
                self.assertIsNone(eof)

    def test_tiny_buffer(self: TestGood) -> None:
        """
        Test the normal cases with a tiny buffer.

        The incoming raw data is delivered a byte at a time, and the response body is
        generated the same way.
        """
        for (
            case_name,
            response_status,
            response_headers,
            response_body,
            expected_tx,
        ) in self.RESPONSES:
            with self.subTest(name=case_name):
                uut = sioscgi.SCGIConnection()
                for i in self.RX_DATA:
                    uut.receive_data(bytes((i,)))
                uut.receive_data(b"")
                self.assertIs(uut.rx_state, sioscgi.RXState.DONE)
                self.assertIs(uut.tx_state, sioscgi.TXState.HEADERS)
                evt = uut.next_event()
                assert isinstance(evt, sioscgi.RequestHeaders)
                self.assertEqual(evt.environment, self.RX_HEADERS)
                for i in self.RX_BODY:
                    evt = uut.next_event()
                    assert isinstance(evt, sioscgi.RequestBody)
                    self.assertEqual(evt.data, bytes((i,)))
                evt = uut.next_event()
                self.assertIsInstance(evt, sioscgi.RequestEnd)
                evt = uut.next_event()
                self.assertIsNone(evt)
                acc = uut.send(
                    sioscgi.ResponseHeaders(response_status, response_headers)
                )
                assert acc is not None
                if response_body is not None:
                    for i in response_body:
                        to_send = uut.send(sioscgi.ResponseBody(bytes((i,))))
                        assert to_send is not None
                        acc += to_send
                self.assertEqual(acc, expected_tx)
                eof = uut.send(sioscgi.ResponseEnd())
                self.assertIsNone(eof)

    def test_request_response_interleaving(self: TestGood) -> None:
        """
        Test that response data can be shipped out before the request body is finished.

        This is not strictly permitted by the SCGI specification (“When the SCGI server
        sees the end of the request it sends back a response and closes the
        connection.”) but it is permitted by the CGI specification (“However, it is not
        obliged to read any of the data.”), works fine with a number of SCGI clients,
        and is useful to be able to do if supported by the environment.
        """
        (
            _,
            response_status,
            response_headers,
            response_body,
            response_expected,
        ) = self.RESPONSES[0]
        assert response_body is not None

        uut = sioscgi.SCGIConnection()
        uut.receive_data(
            b"70:CONTENT_LENGTH\x0027\x00SCGI\x001\x00REQUEST_METHOD\x00POST\x00REQUEST_URI\x00/deepthought\x00,"
        )
        evt = uut.next_event()
        self.assertIsInstance(evt, sioscgi.RequestHeaders)
        self.assertIsNone(uut.next_event())

        out_data = uut.send(sioscgi.ResponseHeaders(response_status, response_headers))
        assert out_data is not None

        uut.receive_data(b"What is")
        evt = uut.next_event()
        assert isinstance(evt, sioscgi.RequestBody)
        self.assertEqual(evt.data, b"What is")
        self.assertIsNone(uut.next_event())

        to_send = uut.send(
            sioscgi.ResponseBody(response_body[: len(response_body) // 2])
        )
        assert to_send is not None
        out_data += to_send

        uut.receive_data(b" the answer to life?")
        evt = uut.next_event()
        assert isinstance(evt, sioscgi.RequestBody)
        self.assertEqual(evt.data, b" the answer to life?")
        self.assertIsInstance(uut.next_event(), sioscgi.RequestEnd)
        self.assertIsNone(uut.next_event())

        to_send = uut.send(
            sioscgi.ResponseBody(response_body[len(response_body) // 2 :])
        )
        assert to_send is not None
        out_data += to_send
        self.assertIsNone(uut.send(sioscgi.ResponseEnd()))

        self.assertEqual(out_data, response_expected)


class TestBadResponseHeaders(unittest.TestCase):
    """Check that various invalid response header structures are caught and rejected."""

    def test_non_latin1_content_type(self: TestBadResponseHeaders) -> None:
        """Test rejection of an unencodable Content-Type header value."""
        with self.assertRaises(sioscgi.LocalProtocolError):
            sioscgi.ResponseHeaders(
                "200 OK", [("Content-Type", "text/Ω"), ("Content-Length", "0")]
            )

    def test_non_latin1_location(self: TestBadResponseHeaders) -> None:
        """Test rejection of an unencodable Location header value."""
        with self.assertRaises(sioscgi.LocalProtocolError):
            sioscgi.ResponseHeaders(
                "301 Moved Permanently",
                [
                    ("Location", "/Ω"),
                    ("Content-Type", "text/plain; charset=UTF-8"),
                    ("Content-Length", "0"),
                ],
            )

    def test_non_latin1_other(self: TestBadResponseHeaders) -> None:
        """Test rejection of an unencodable general header value."""
        with self.assertRaises(sioscgi.LocalProtocolError):
            sioscgi.ResponseHeaders(
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
        with self.assertRaises(sioscgi.LocalProtocolError):
            sioscgi.ResponseHeaders(
                None,
                [("Location", "/foo"), ("Content-Type", "text/plain; charset=UTF-8")],
            )

    def test_local_redirect_with_other_header(self: TestBadResponseHeaders) -> None:
        """
        Test rejection of a local redirect with an extra general header.

        A local redirect must not have any headers other than Location.
        """
        with self.assertRaises(sioscgi.LocalProtocolError):
            sioscgi.ResponseHeaders(
                None, [("Location", "/foo"), ("Other-Thing", "bar")]
            )


class TestBadRXData(unittest.TestCase):
    """Test various cases of invalid received data."""

    def test_premature_eof(self: TestBadRXData) -> None:
        """Test rejection of truncated received data."""
        uut = sioscgi.SCGIConnection()
        uut.receive_data(
            b"70:CONTENT_LENGTH\x0027\x00SCGI\x001\x00REQUEST_METHOD\x00POST\x00REQUEST_URI\x00/deepthought\x00,What is the answer to life"
        )  # Note missing final ?
        uut.receive_data(b"")
        with self.assertRaises(sioscgi.RemoteProtocolError):
            uut.next_event()

    def test_headers_no_comma(self: TestBadRXData) -> None:
        """Test rejection of a netstring encoding missing its trailing comma."""
        uut = sioscgi.SCGIConnection()
        uut.receive_data(
            b"70:CONTENT_LENGTH\x0027\x00SCGI\x001\x00REQUEST_METHOD\x00POST\x00REQUEST_URI\x00/deepthought\x00@What is the answer to life?"
        )  # Comma replaced with @
        uut.receive_data(b"")
        with self.assertRaises(sioscgi.RemoteProtocolError):
            uut.next_event()

    def test_headers_no_scgi(self: TestBadRXData) -> None:
        """Test rejection of a missing SCGI header."""
        uut = sioscgi.SCGIConnection()
        uut.receive_data(
            b"63:CONTENT_LENGTH\x0027\x00REQUEST_METHOD\x00POST\x00REQUEST_URI\x00/deepthought\x00,What is the answer to life?"
        )  # Comma replaced with @
        uut.receive_data(b"")
        with self.assertRaises(sioscgi.RemoteProtocolError):
            uut.next_event()

    def test_headers_no_content_length(self: TestBadRXData) -> None:
        """Test rejection of a missing CONTENT_LENGTH header."""
        uut = sioscgi.SCGIConnection()
        uut.receive_data(
            b"52:SCGI\x001\x00REQUEST_METHOD\x00POST\x00REQUEST_URI\x00/deepthought\x00@What is the answer to life?"
        )  # Comma replaced with @
        uut.receive_data(b"")
        with self.assertRaises(sioscgi.RemoteProtocolError):
            uut.next_event()

    def test_headers_no_nul(self: TestBadRXData) -> None:
        """Test rejection of a non-NUL-terminated header block."""
        uut = sioscgi.SCGIConnection()
        uut.receive_data(
            b"69:CONTENT_LENGTH\x0027\x00SCGI\x001\x00REQUEST_METHOD\x00POST\x00REQUEST_URI\x00/deepthought,What is the answer to life?"
        )
        uut.receive_data(b"")
        with self.assertRaises(sioscgi.RemoteProtocolError):
            uut.next_event()

    def test_headers_odd_number(self: TestBadRXData) -> None:
        """
        Test rejection of an odd number of NUL-terminated strings in the header block.

        This implies the presence of a key without a value or vice versa.
        """
        uut = sioscgi.SCGIConnection()
        uut.receive_data(
            b"65:CONTENT_LENGTH\x0027\x00SCGI\x001\x00REQUEST_METHOD\x00REQUEST_URI\x00/deepthought\x00,What is the answer to life?"
        )
        uut.receive_data(b"")
        with self.assertRaises(sioscgi.RemoteProtocolError):
            uut.next_event()

    def test_headers_wrong_scgi(self: TestBadRXData) -> None:
        """
        Test rejection of an incorrect SCGI header value.

        This implies that a different protocol version is in use.
        """
        uut = sioscgi.SCGIConnection()
        uut.receive_data(
            b"70:CONTENT_LENGTH\x0027\x00SCGI\x002\x00REQUEST_METHOD\x00POST\x00REQUEST_URI\x00/deepthought\x00,What is the answer to life?"
        )
        uut.receive_data(b"")
        with self.assertRaises(sioscgi.RemoteProtocolError):
            uut.next_event()

    def test_headers_length_space(self: TestBadRXData) -> None:
        """Test rejection of a netstring length starting with a space."""
        uut = sioscgi.SCGIConnection()
        uut.receive_data(b" ")
        uut.receive_data(b"")
        with self.assertRaises(sioscgi.RemoteProtocolError):
            uut.next_event()

    def test_headers_length_non_integer(self: TestBadRXData) -> None:
        """Test rejection of a netstring length starting with a non-integer."""
        uut = sioscgi.SCGIConnection()
        uut.receive_data(b"A")
        uut.receive_data(b"")
        with self.assertRaises(sioscgi.RemoteProtocolError):
            uut.next_event()


class TestBadResponseSequence(unittest.TestCase):
    """Test trying to send response events at the wrong time or in the wrong order."""

    def test_response_body_before_headers(self: TestBadResponseSequence) -> None:
        """Test trying to send some response body before sending the headers."""
        uut = sioscgi.SCGIConnection()
        uut.receive_data(
            b"70:CONTENT_LENGTH\x0027\x00SCGI\x001\x00REQUEST_METHOD\x00POST\x00REQUEST_URI\x00/deepthought\x00,What is the answer to life?"
        )
        while uut.next_event() is not None:
            pass
        self.assertIs(uut.tx_state, sioscgi.TXState.HEADERS)
        tx_body = sioscgi.ResponseBody(b"abcd")
        with self.assertRaises(sioscgi.LocalProtocolError):
            uut.send(tx_body)

    def test_response_end_before_headers(self: TestBadResponseSequence) -> None:
        """Test trying to send the response end marker before sending the headers."""
        uut = sioscgi.SCGIConnection()
        uut.receive_data(
            b"70:CONTENT_LENGTH\x0027\x00SCGI\x001\x00REQUEST_METHOD\x00POST\x00REQUEST_URI\x00/deepthought\x00,What is the answer to life?"
        )
        while uut.next_event() is not None:
            pass
        self.assertIs(uut.tx_state, sioscgi.TXState.HEADERS)
        with self.assertRaises(sioscgi.LocalProtocolError):
            uut.send(sioscgi.ResponseEnd())


class TestOtherErrors(unittest.TestCase):
    """Test other miscellaneous errors."""

    def test_rx_after_eof(self: TestOtherErrors) -> None:
        """Test that receiving additional data after EOF raises an exception."""
        uut = sioscgi.SCGIConnection()
        uut.receive_data(
            b"70:CONTENT_LENGTH\x0027\x00SCGI\x001\x00REQUEST_METHOD\x00POST\x00REQUEST_URI\x00/deepthought\x00,What is the answer to life?"
        )
        uut.receive_data(b"")
        while uut.next_event() is not None:
            pass
        # This is considered a local error, not a remote error, because receiving bytes
        # after EOF isn’t something that the remote peer is *capable* of causing if the
        # local software is written properly (once the remote peer sends EOF, the kernel
        # should prevent it from being able to send any more data, so if this happens,
        # it means the local software detected EOF improperly).
        with self.assertRaises(sioscgi.LocalProtocolError):
            uut.receive_data(b"x")
