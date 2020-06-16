"""
Tests the sioscgi module.
"""

import unittest

import sioscgi


class TestGood(unittest.TestCase):
    """
    Test the normal cases where things work properly.
    """

    RX_DATA = B"70:CONTENT_LENGTH\x0027\x00SCGI\x001\x00REQUEST_METHOD\x00POST\x00REQUEST_URI\x00/deepthought\x00,What is the answer to life?"
    """The raw received bytes."""
    RX_HEADERS = {"CONTENT_LENGTH": B"27", "SCGI": B"1", "REQUEST_METHOD": B"POST", "REQUEST_URI": B"/deepthought"}
    """The expected decoded request headers."""
    RX_BODY = B"What is the answer to life?"
    """The expected decoded request body."""

    RESPONSES = [
        ("Standard response with document",
         "200 OK",
         [("Content-Type", "text/plain; charset=UTF-8"), ("Content-Length", "2")],
         B"42",
         B"Content-Type: text/plain; charset=UTF-8\r\nStatus: 200 OK\r\nContent-Length: 2\r\n\r\n42"),
        ("Local redirect",
         None,
         [("Location", "/foo")],
         None,
         B"Location: /foo\r\n\r\n"),
        ("Client redirect with document",
         "301 Moved Permanently",
         [("Content-Type", "text/plain; charset=UTF-8"), ("Content-Length", "5"), ("Location", "/foo")],
         B"moved",
         B"Location: /foo\r\nStatus: 301 Moved Permanently\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Length: 5\r\n\r\nmoved"),
    ]
    """
    The responses to generate.

    Each element is a tuple of (name of subtest, response status, response
    headers, response body, expected transmitted data).
    """

    def test_big_buffer(self) -> None:
        """
        Test the normal cases with a big buffer.

        The incoming raw data is delivered in one full chunk, and the response
        body is generated the same way.
        """
        for (case_name, response_status, response_headers, response_body, expected_tx) in self.RESPONSES:
            with self.subTest(name=case_name):
                uut = sioscgi.SCGIConnection()
                uut.receive_data(self.RX_DATA)
                uut.receive_data(B"")
                self.assertIs(uut.rx_state, sioscgi.RXState.DONE)
                self.assertIs(uut.tx_state, sioscgi.TXState.HEADERS)
                evt = uut.next_event()
                self.assertIsInstance(evt, sioscgi.RequestHeaders)
                self.assertEqual(evt.environment, self.RX_HEADERS)
                evt = uut.next_event()
                self.assertIsInstance(evt, sioscgi.RequestBody)
                self.assertEqual(evt.data, self.RX_BODY)
                evt = uut.next_event()
                self.assertIsInstance(evt, sioscgi.RequestEnd)
                evt = uut.next_event()
                self.assertIsNone(evt)
                acc = uut.send(sioscgi.ResponseHeaders(response_status, response_headers))
                if response_body is not None:
                    acc += uut.send(sioscgi.ResponseBody(response_body))
                self.assertEqual(acc, expected_tx)
                eof = uut.send(sioscgi.ResponseEnd())
                self.assertIsNone(eof)

    def test_tiny_buffer(self) -> None:
        """
        Test the normal cases with a tiny buffer.

        The incoming raw data is delivered a byte at a time, and the response
        body is generated the same way.
        """
        for (case_name, response_status, response_headers, response_body, expected_tx) in self.RESPONSES:
            with self.subTest(name=case_name):
                uut = sioscgi.SCGIConnection()
                for i in self.RX_DATA:
                    uut.receive_data(bytes((i, )))
                uut.receive_data(B"")
                self.assertIs(uut.rx_state, sioscgi.RXState.DONE)
                self.assertIs(uut.tx_state, sioscgi.TXState.HEADERS)
                evt = uut.next_event()
                self.assertIsInstance(evt, sioscgi.RequestHeaders)
                self.assertEqual(evt.environment, self.RX_HEADERS)
                for i in self.RX_BODY:
                    evt = uut.next_event()
                    self.assertIsInstance(evt, sioscgi.RequestBody)
                    self.assertEqual(evt.data, bytes((i, )))
                evt = uut.next_event()
                self.assertIsInstance(evt, sioscgi.RequestEnd)
                evt = uut.next_event()
                self.assertIsNone(evt)
                acc = uut.send(sioscgi.ResponseHeaders(response_status, response_headers))
                if response_body is not None:
                    for i in response_body:
                        acc += uut.send(sioscgi.ResponseBody(bytes((i, ))))
                self.assertEqual(acc, expected_tx)
                eof = uut.send(sioscgi.ResponseEnd())
                self.assertIsNone(eof)

    def test_request_response_interleaving(self):
        """
        Test that response data can be shipped out before the request body is
        finished.

        This is not strictly permitted by the SCGI specification (“When the
        SCGI server sees the end of the request it sends back a response and
        closes the connection.”) but it is permitted by the CGI specification
        (“However, it is not obliged to read any of the data.”), works fine
        with a number of SCGI clients, and is useful to be able to do if
        supported by the environment.
        """
        _, response_status, response_headers, response_body, response_expected = self.RESPONSES[0]

        uut = sioscgi.SCGIConnection()
        uut.receive_data(B"70:CONTENT_LENGTH\x0027\x00SCGI\x001\x00REQUEST_METHOD\x00POST\x00REQUEST_URI\x00/deepthought\x00,")
        evt = uut.next_event()
        self.assertIsInstance(evt, sioscgi.RequestHeaders)
        self.assertIsNone(uut.next_event())

        out_data = uut.send(sioscgi.ResponseHeaders(response_status, response_headers))

        uut.receive_data(B"What is")
        evt = uut.next_event()
        self.assertIsInstance(evt, sioscgi.RequestBody)
        self.assertEqual(evt.data, B"What is")
        self.assertIsNone(uut.next_event())

        out_data += uut.send(sioscgi.ResponseBody(response_body[:len(response_body) // 2]))

        uut.receive_data(B" the answer to life?")
        evt = uut.next_event()
        self.assertIsInstance(evt, sioscgi.RequestBody)
        self.assertEqual(evt.data, B" the answer to life?")
        self.assertIsInstance(uut.next_event(), sioscgi.RequestEnd)
        self.assertIsNone(uut.next_event())

        out_data += uut.send(sioscgi.ResponseBody(response_body[len(response_body) // 2:]))
        self.assertIsNone(uut.send(sioscgi.ResponseEnd()))

        self.assertEqual(out_data, response_expected)


class TestBadResponseHeaders(unittest.TestCase):
    """
    Check that various occurrences of invalid response header structures are
    caught and rejected.
    """

    def test_non_latin1_content_type(self) -> None:
        """
        Test that a Content-Type header with a non-ISO8859-1-encodable value is
        rejected.
        """
        with self.assertRaises(sioscgi.LocalProtocolError):
            sioscgi.ResponseHeaders("200 OK", [("Content-Type", "text/Ω"), ("Content-Length", "0")])

    def test_non_latin1_location(self) -> None:
        """
        Test that a Location header with a non-ISO8859-1-encodable value is
        rejected.
        """
        with self.assertRaises(sioscgi.LocalProtocolError):
            sioscgi.ResponseHeaders("301 Moved Permanently", [("Location", "/Ω"), ("Content-Type", "text/plain; charset=UTF-8"), ("Content-Length", "0")])

    def test_non_latin1_other(self) -> None:
        """
        Test that a header other than Content-Type or Location with a
        non-ISO8859-1-encodable value is rejected.
        """
        with self.assertRaises(sioscgi.LocalProtocolError):
            sioscgi.ResponseHeaders("200 OK", [("Content-Type", "text/plain; charset=UTF-8"), ("Content-Length", "0"), ("Other-Thing", "Ω")])

    def test_local_redirect_with_content_type(self) -> None:
        """
        Test that a local redirect with a Content-Type header is rejected (a
        local redirect must not have any headers other than Location).
        """
        with self.assertRaises(sioscgi.LocalProtocolError):
            sioscgi.ResponseHeaders(None, [("Location", "/foo"), ("Content-Type", "text/plain; charset=UTF-8")])

    def test_local_redirect_with_other_header(self) -> None:
        """
        Test that a local redirect with an additional header other than
        Content-Type is rejected (a local redirect must not have any headers
        other than Location).
        """
        with self.assertRaises(sioscgi.LocalProtocolError):
            sioscgi.ResponseHeaders(None, [("Location", "/foo"), ("Other-Thing", "bar")])


class TestBadRXData(unittest.TestCase):
    """
    Test various cases of invalid received data.
    """

    def test_premature_eof(self) -> None:
        """
        Test that an exception is raised if the received data is truncated.
        """
        uut = sioscgi.SCGIConnection()
        uut.receive_data(B"70:CONTENT_LENGTH\x0027\x00SCGI\x001\x00REQUEST_METHOD\x00POST\x00REQUEST_URI\x00/deepthought\x00,What is the answer to life")  # Note missing final ?
        uut.receive_data(B"")
        with self.assertRaises(sioscgi.RemoteProtocolError):
            uut.next_event()

    def test_headers_no_comma(self) -> None:
        """
        Test that an exception is raised if the received headers are not
        properly netstring-terminated with a comma.
        """
        uut = sioscgi.SCGIConnection()
        uut.receive_data(B"70:CONTENT_LENGTH\x0027\x00SCGI\x001\x00REQUEST_METHOD\x00POST\x00REQUEST_URI\x00/deepthought\x00@What is the answer to life?")  # Comma replaced with @
        uut.receive_data(B"")
        with self.assertRaises(sioscgi.RemoteProtocolError):
            uut.next_event()

    def test_headers_no_scgi(self) -> None:
        """
        Test that an exception is raised if the SCGI header is missing.
        """
        uut = sioscgi.SCGIConnection()
        uut.receive_data(B"63:CONTENT_LENGTH\x0027\x00REQUEST_METHOD\x00POST\x00REQUEST_URI\x00/deepthought\x00,What is the answer to life?")  # Comma replaced with @
        uut.receive_data(B"")
        with self.assertRaises(sioscgi.RemoteProtocolError):
            uut.next_event()

    def test_headers_no_content_length(self) -> None:
        """
        Test that an exception is raised if the CONTENT_LENGTH header is missing.
        """
        uut = sioscgi.SCGIConnection()
        uut.receive_data(B"52:SCGI\x001\x00REQUEST_METHOD\x00POST\x00REQUEST_URI\x00/deepthought\x00@What is the answer to life?")  # Comma replaced with @
        uut.receive_data(B"")
        with self.assertRaises(sioscgi.RemoteProtocolError):
            uut.next_event()

    def test_headers_no_nul(self) -> None:
        """
        Test that an exception is raised if the header block does not end with
        a NUL.
        """
        uut = sioscgi.SCGIConnection()
        uut.receive_data(B"69:CONTENT_LENGTH\x0027\x00SCGI\x001\x00REQUEST_METHOD\x00POST\x00REQUEST_URI\x00/deepthought,What is the answer to life?")
        uut.receive_data(B"")
        with self.assertRaises(sioscgi.RemoteProtocolError):
            uut.next_event()

    def test_headers_odd_number(self) -> None:
        """
        Test that an exception is raised if the number of NUL-terminated
        strings in the headers block is odd, implying a key without a value or
        a value without a key.
        """
        uut = sioscgi.SCGIConnection()
        uut.receive_data(B"65:CONTENT_LENGTH\x0027\x00SCGI\x001\x00REQUEST_METHOD\x00REQUEST_URI\x00/deepthought\x00,What is the answer to life?")
        uut.receive_data(B"")
        with self.assertRaises(sioscgi.RemoteProtocolError):
            uut.next_event()

    def test_headers_wrong_scgi(self) -> None:
        """
        Test that an exception is raised if the SCGI header has the wrong
        value, implying a different protocol version is in use.
        """
        uut = sioscgi.SCGIConnection()
        uut.receive_data(B"70:CONTENT_LENGTH\x0027\x00SCGI\x002\x00REQUEST_METHOD\x00POST\x00REQUEST_URI\x00/deepthought\x00,What is the answer to life?")
        uut.receive_data(B"")
        with self.assertRaises(sioscgi.RemoteProtocolError):
            uut.next_event()

    def test_headers_length_space(self) -> None:
        """
        Test that a space starting the netstring length for the headers block
        is rejected.
        """
        uut = sioscgi.SCGIConnection()
        uut.receive_data(B" ")
        uut.receive_data(B"")
        with self.assertRaises(sioscgi.RemoteProtocolError):
            uut.next_event()

    def test_headers_length_non_integer(self) -> None:
        """
        Test that a non-integer starting the netstring length for the headers
        block is rejected.
        """
        uut = sioscgi.SCGIConnection()
        uut.receive_data(B"A")
        uut.receive_data(B"")
        with self.assertRaises(sioscgi.RemoteProtocolError):
            uut.next_event()


class TestBadResponseSequence(unittest.TestCase):
    """
    Test various cases of trying to send response events at the wrong time or
    in the wrong order.
    """

    def test_response_body_before_headers(self) -> None:
        """
        Test trying to send some response body before sending the response
        headers.
        """
        uut = sioscgi.SCGIConnection()
        uut.receive_data(B"70:CONTENT_LENGTH\x0027\x00SCGI\x001\x00REQUEST_METHOD\x00POST\x00REQUEST_URI\x00/deepthought\x00,What is the answer to life?")
        while uut.next_event() is not None:
            pass
        self.assertIs(uut.tx_state, sioscgi.TXState.HEADERS)
        tx_body = sioscgi.ResponseBody(B"abcd")
        with self.assertRaises(sioscgi.LocalProtocolError):
            uut.send(tx_body)

    def test_response_end_before_headers(self) -> None:
        """
        Test trying to send the response end marker before sending the response
        headers.
        """
        uut = sioscgi.SCGIConnection()
        uut.receive_data(B"70:CONTENT_LENGTH\x0027\x00SCGI\x001\x00REQUEST_METHOD\x00POST\x00REQUEST_URI\x00/deepthought\x00,What is the answer to life?")
        while uut.next_event() is not None:
            pass
        self.assertIs(uut.tx_state, sioscgi.TXState.HEADERS)
        with self.assertRaises(sioscgi.LocalProtocolError):
            uut.send(sioscgi.ResponseEnd())


class TestOtherErrors(unittest.TestCase):
    """
    Test other miscellaneous errors.
    """

    def test_rx_after_eof(self) -> None:
        """
        Test that receiving additional data after EOF raises an exception.
        """
        uut = sioscgi.SCGIConnection()
        uut.receive_data(B"70:CONTENT_LENGTH\x0027\x00SCGI\x001\x00REQUEST_METHOD\x00POST\x00REQUEST_URI\x00/deepthought\x00,What is the answer to life?")
        uut.receive_data(B"")
        while uut.next_event() is not None:
            pass
        # This is considered a local error, not a remote error, because
        # receiving bytes after EOF isn’t something that the remote
        # peer is *capable* of causing if the local software is written
        # properly (once the remote peer sends EOF, the kernel should
        # prevent it from being able to send any more data, so if this
        # happens, it means the local software detected EOF
        # improperly).
        with self.assertRaises(sioscgi.LocalProtocolError):
            uut.receive_data(B"x")
