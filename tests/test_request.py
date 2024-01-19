"""Tests the sioscgi.request module."""

from __future__ import annotations

import unittest
from typing import ClassVar

import sioscgi.request


class TestGood(unittest.TestCase):
    """Test the normal cases where things work properly."""

    RX_DATA: ClassVar[bytes] = (
        b"70:"
        b"CONTENT_LENGTH\x0027\x00"
        b"SCGI\x001\x00"
        b"REQUEST_METHOD\x00POST\x00"
        b"REQUEST_URI\x00/deepthought\x00"
        b","
        b"What is the answer to life?"
    )
    """The raw received bytes."""

    RX_HEADERS: ClassVar[dict[str, bytes]] = {
        "CONTENT_LENGTH": b"27",
        "SCGI": b"1",
        "REQUEST_METHOD": b"POST",
        "REQUEST_URI": b"/deepthought",
    }
    """The expected decoded request headers."""

    RX_BODY: ClassVar[bytes] = b"What is the answer to life?"
    """The expected decoded request body."""

    def test_big_buffer(self: TestGood) -> None:
        """
        Test the normal cases with a big buffer.

        The incoming raw data is delivered in one full chunk, and the response body is
        generated the same way.
        """
        uut = sioscgi.request.SCGIReader()
        uut.receive_data(self.RX_DATA)
        uut.receive_data(b"")
        self.assertIs(uut.state, sioscgi.request.State.DONE)
        evt = uut.next_event()
        assert isinstance(evt, sioscgi.request.Headers)
        self.assertEqual(evt.environment, self.RX_HEADERS)
        evt = uut.next_event()
        assert isinstance(evt, sioscgi.request.Body)
        self.assertEqual(evt.data, self.RX_BODY)
        evt = uut.next_event()
        self.assertIsInstance(evt, sioscgi.request.End)
        evt = uut.next_event()
        self.assertIsNone(evt)

    def test_tiny_buffer(self: TestGood) -> None:
        """
        Test the normal cases with a tiny buffer.

        The incoming raw data is delivered a byte at a time, and the response body is
        generated the same way.
        """
        uut = sioscgi.request.SCGIReader()
        for i in self.RX_DATA:
            uut.receive_data(bytes((i,)))
        uut.receive_data(b"")
        self.assertIs(uut.state, sioscgi.request.State.DONE)
        evt = uut.next_event()
        assert isinstance(evt, sioscgi.request.Headers)
        self.assertEqual(evt.environment, self.RX_HEADERS)
        for i in self.RX_BODY:
            evt = uut.next_event()
            assert isinstance(evt, sioscgi.request.Body)
            self.assertEqual(evt.data, bytes((i,)))
        evt = uut.next_event()
        self.assertIsInstance(evt, sioscgi.request.End)
        evt = uut.next_event()
        self.assertIsNone(evt)


class TestBadData(unittest.TestCase):
    """Test various cases of invalid received data."""

    def test_premature_eof(self: TestBadData) -> None:
        """Test rejection of truncated received data."""
        uut = sioscgi.request.SCGIReader()
        uut.receive_data(TestGood.RX_DATA[:-1])
        uut.receive_data(b"")
        with self.assertRaises(sioscgi.request.RemotePrematureEOFError):
            uut.next_event()

    def test_headers_no_comma(self: TestBadData) -> None:
        """Test rejection of a netstring encoding missing its trailing comma."""
        uut = sioscgi.request.SCGIReader()
        uut.receive_data(
            b"70:"
            b"CONTENT_LENGTH\x0027\x00"
            b"SCGI\x001\x00"
            b"REQUEST_METHOD\x00POST\x00"
            b"REQUEST_URI\x00/deepthought\x00"
            b"@"
            b"What is the answer to life?"
        )  # Comma replaced with @
        uut.receive_data(b"")
        with self.assertRaises(sioscgi.request.BadNetstringTerminatorError):
            uut.next_event()

    def test_headers_no_scgi(self: TestBadData) -> None:
        """Test rejection of a missing SCGI header."""
        uut = sioscgi.request.SCGIReader()
        uut.receive_data(
            b"63:"
            b"CONTENT_LENGTH\x0027\x00"
            b"REQUEST_METHOD\x00POST\x00"
            b"REQUEST_URI\x00/deepthought\x00"
            b","
            b"What is the answer to life?"
        )
        uut.receive_data(b"")
        with self.assertRaises(sioscgi.request.NoSCGIVariableError):
            uut.next_event()

    def test_headers_no_content_length(self: TestBadData) -> None:
        """Test rejection of a missing CONTENT_LENGTH header."""
        uut = sioscgi.request.SCGIReader()
        uut.receive_data(
            b"52:"
            b"SCGI\x001\x00"
            b"REQUEST_METHOD\x00POST\x00"
            b"REQUEST_URI\x00/deepthought\x00"
            b","
            b"What is the answer to life?"
        )
        uut.receive_data(b"")
        with self.assertRaises(sioscgi.request.NoContentLengthError):
            uut.next_event()

    def test_headers_no_nul(self: TestBadData) -> None:
        """Test rejection of a non-NUL-terminated header block."""
        uut = sioscgi.request.SCGIReader()
        uut.receive_data(
            b"69:"
            b"CONTENT_LENGTH\x0027\x00"
            b"SCGI\x001\x00"
            b"REQUEST_METHOD\x00POST\x00"
            b"REQUEST_URI\x00/deepthought"
            b","
            b"What is the answer to life?"
        )
        uut.receive_data(b"")
        with self.assertRaises(sioscgi.request.HeadersNotNULTerminatedError):
            uut.next_event()

    def test_headers_odd_number(self: TestBadData) -> None:
        """
        Test rejection of an odd number of NUL-terminated strings in the header block.

        This implies the presence of a key without a value or vice versa.
        """
        uut = sioscgi.request.SCGIReader()
        uut.receive_data(
            b"65:"
            b"CONTENT_LENGTH\x0027\x00"
            b"SCGI\x001\x00"
            b"REQUEST_METHOD\x00"
            b"REQUEST_URI\x00/deepthought\x00"
            b","
            b"What is the answer to life?"
        )
        uut.receive_data(b"")
        with self.assertRaises(sioscgi.request.HeadersOddStringCountError):
            uut.next_event()

    def test_headers_wrong_scgi(self: TestBadData) -> None:
        """
        Test rejection of an incorrect SCGI header value.

        This implies that a different protocol version is in use.
        """
        uut = sioscgi.request.SCGIReader()
        uut.receive_data(
            b"70:"
            b"CONTENT_LENGTH\x0027\x00"
            b"SCGI\x002\x00"
            b"REQUEST_METHOD\x00POST\x00"
            b"REQUEST_URI\x00/deepthought\x00"
            b","
            b"What is the answer to life?"
        )
        uut.receive_data(b"")
        with self.assertRaises(sioscgi.request.BadSCGIVersionError):
            uut.next_event()

    def test_headers_length_space(self: TestBadData) -> None:
        """Test rejection of a netstring length starting with a space."""
        uut = sioscgi.request.SCGIReader()
        uut.receive_data(b" :")
        uut.receive_data(b"")
        with self.assertRaises(sioscgi.request.BadNetstringLengthError):
            uut.next_event()

    def test_headers_length_non_integer(self: TestBadData) -> None:
        """Test rejection of a netstring length starting with a non-integer."""
        uut = sioscgi.request.SCGIReader()
        uut.receive_data(b"A:")
        uut.receive_data(b"")
        with self.assertRaises(sioscgi.request.BadNetstringLengthError):
            uut.next_event()


class TestOtherErrors(unittest.TestCase):
    """Test other miscellaneous errors."""

    def test_rx_after_eof(self: TestOtherErrors) -> None:
        """Test that receiving additional data after EOF raises an exception."""
        uut = sioscgi.request.SCGIReader()
        uut.receive_data(TestGood.RX_DATA)
        uut.receive_data(b"")
        while uut.next_event() is not None:
            pass
        # Because this indicates a bug in local software which is impossible for a
        # remote peer to trigger given properly compliant local code, the exception is
        # raised immediately from receive_data rather than being deferred to next_event.
        with self.assertRaises(sioscgi.request.ReceiveAfterEOFError):
            uut.receive_data(b"x")
