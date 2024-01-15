"""Implements the SCGI protocol."""

from __future__ import annotations

import collections
import enum
import functools
import logging
import wsgiref.headers
import wsgiref.util
from collections.abc import Callable
from typing import ClassVar, NoReturn


@enum.unique
class RXState(enum.Enum):
    """The possible states the receive half of the connection can be in."""

    HEADER_LENGTH = enum.auto()
    HEADERS = enum.auto()
    BODY = enum.auto()
    DONE = enum.auto()
    ERROR = enum.auto()


@enum.unique
class TXState(enum.Enum):
    """The possible states the transmit half of the connection can be in."""

    HEADERS = enum.auto()
    BODY = enum.auto()
    NO_BODY = enum.auto()
    DONE = enum.auto()
    ERROR = enum.auto()


class ProtocolError(Exception):
    """
    Raised when a violation of protocol occurs.

    The violation may be by either the remote peer or the local application.

    This is the base class of LocalProtocolError and RemoteProtocolError.
    """

    __slots__ = ()


class LocalProtocolError(ProtocolError):
    """
    Raised when the local application violates protocol.

    This is the base class of various specific errors and is never raised directly.
    """

    __slots__ = ()


class ResponseHeaderHopByHopError(LocalProtocolError):
    """Raised when a response includes a hop-by-hop header."""

    __slots__ = ()

    def __init__(self: ResponseHeaderHopByHopError, name: str) -> None:
        """
        Construct a new ResponseHeaderHopByHopError.

        :param name: The name of the unacceptable header.
        """
        super().__init__(f"Header {name} is hop-by-hop and therefore illegal")


class ResponseHeaderNotISO88591Error(LocalProtocolError):
    """Raised when a response header value cannot be encoded in ISO-8859-1."""

    __slots__ = ()

    def __init__(self: ResponseHeaderNotISO88591Error) -> None:
        """Construct a new ResponseHeaderNotISO88591Error."""
        super().__init__("A response header is not ISO-8859-1-encodable")


class NonDocumentHeadersError(LocalProtocolError):
    """Raised when response headers are invalid for a non-document response."""

    __slots__ = ()

    def __init__(self: NonDocumentHeadersError) -> None:
        """Construct a new NonDocumentHeadersError."""
        super().__init__(
            "Non-document responses must contain a Location header and no others"
        )


class ReceiveAfterEOFError(LocalProtocolError):
    """Raised when data is received after EOF."""

    __slots__ = ()

    def __init__(self: ReceiveAfterEOFError) -> None:
        """Construct a new ReceiveAfterEOFError."""
        super().__init__("Data received after EOF")


class BadEventInStateError(LocalProtocolError):
    """Raised when the local application sends an unacceptable event."""

    __slots__ = ()

    def __init__(
        self: BadEventInStateError, event: type[Event], state: TXState
    ) -> None:
        """
        Construct a new BadEventInStateError.

        :param event: The event that the application tried to send.
        :param state: The state that the state machine was in.
        """
        super().__init__(f"Event {type(event)} prohibited in state {state}")


class RemoteProtocolError(ProtocolError):
    """
    Raised when the remote peer violates protocol.

    This is the base class of various specific errors and is never raised directly.
    """

    __slots__ = ()


class RequestHeadersError(RemoteProtocolError):
    """
    Raised when the remote peer sends an invalid environment block.

    This is the base class of various specific errors and is never raised directly.
    """

    __slots__ = ()


class NetstringError(RequestHeadersError):
    """
    Raised when the remote peer sends an invalid netstring.

    This is the base class of various specific errors and is never raised directly.
    """

    __slots__ = ()


class BadNetstringLengthError(NetstringError):
    """Raised when the remote peer sends a netstring with an invalid length prefix."""

    __slots__ = ()

    def __init__(self: BadNetstringLengthError) -> None:
        """Construct a new BadNetstringLengthError."""
        super().__init__("Invalid netstring length prefix")


class Error(NetstringError):
    """Raised when the remote peer sends a netstring length that is too large."""

    __slots__ = ()

    def __init__(self: Error, length: int, limit: int) -> None:
        """
        Construct a new Error.

        :param length: The length sent by the remote peer.
        :param limit: The maximum permitted length.
        """
        super().__init__(f"Netstring too long (got {length}, limit {limit})")


class BadNetstringTerminatorError(NetstringError):
    """Raised when the remote peer sends a netstring with the wrong terminator."""

    __slots__ = ()

    def __init__(self: BadNetstringTerminatorError) -> None:
        """Construct a new BadNetstringTerminatorError."""
        super().__init__("Invalid end-of-environment character")


class RequestHeadersStructuralError(RequestHeadersError):
    """
    Raised when the remote peer sends request headers with a structural problem.

    This is the base class of various specific errors and is never raised directly.
    """

    __slots__ = ()


class RequestHeadersNotNULTerminatedError(RequestHeadersStructuralError):
    """Raised when the remote peer sends request headers whose last byte is not NUL."""

    __slots__ = ()

    def __init__(self: RequestHeadersNotNULTerminatedError) -> None:
        """Construct a new RequestHeadersNotNULTerminatedError."""
        super().__init__("Environment block not NUL-terminated")


class RequestHeadersOddStringCountError(RequestHeadersStructuralError):
    """Raised when the remote peer sends an odd number of strings in the environment."""

    __slots__ = ()

    def __init__(self: RequestHeadersOddStringCountError) -> None:
        """Construct a new RequestHeadersOddStringCountError."""
        super().__init__("Environment block missing final value")


class RequestHeaderNotISO88591Error(RequestHeadersStructuralError):
    """Raised when the remote peer sends a variable whose name is invalid ISO-8859-1."""

    __slots__ = ()

    def __init__(self: RequestHeaderNotISO88591Error, name: bytes) -> None:
        """
        Construct a new RequestHeaderNotISO88591Error.

        :param name: The non-ISO-8859-1 variable name.
        """
        super().__init__(f"Environment variable name {name!r} is not ISO-8859-1")


class RequestHeaderEmptyError(RequestHeadersStructuralError):
    """Raised when the remote peer sends a variable whose name is empty."""

    __slots__ = ()

    def __init__(self: RequestHeaderEmptyError) -> None:
        """Construct a new RequestHeaderEmptyError."""
        super().__init__("Environment variable with empty name")


class DuplicateRequestHeaderError(RequestHeadersStructuralError):
    """Raised when the remote peer sends two variables with the same name."""

    __slots__ = ()

    def __init__(self: DuplicateRequestHeaderError, name: str) -> None:
        """
        Construct a new DuplicateRequestHeaderError.

        :param name: The name of the variable which appears multiple times.
        """
        super().__init__(f"Duplicate environment variable {name}")


class RequestHeadersContentError(RequestHeadersError):
    """
    Raised when the remote peer sends request headers with a content problem.

    This is the base class of various specific errors and is never raised directly.
    """

    __slots__ = ()


class NoSCGIVariableError(RequestHeadersContentError):
    """Raised when the remote peer does not send the SCGI variable."""

    __slots__ = ()

    def __init__(self: NoSCGIVariableError) -> None:
        """Construct a new NoSCGIVariableError."""
        super().__init__("Mandatory variable SCGI missing")


class BadSCGIVersionError(RequestHeadersContentError):
    """Raised when the remote peer is speaking an unsupported version of SCGI."""

    __slots__ = ()

    def __init__(self: BadSCGIVersionError, version: bytes) -> None:
        """
        Construct a new BadSCGIVersionError.

        :param version: The version that the peer is speaking.
        """
        super().__init__(f"SCGI variable is {version!r}, expected 1")


class NoContentLengthError(RequestHeadersContentError):
    """Raised when the remote peer does not send the CONTENT_LENGTH variable."""

    __slots__ = ()

    def __init__(self: NoContentLengthError) -> None:
        """Construct a new NoContentLengthError."""
        super().__init__("Mandatory variable CONTENT_LENGTH missing")


class BadContentLengthError(RequestHeadersContentError):
    """Raised when the remote peer sends an invalid CONTENT_LENGTH value."""

    __slots__ = ()

    def __init__(self: BadContentLengthError, value: str) -> None:
        """
        Construct a new BadContentLengthError.

        :param value: The invalid value.
        """
        super().__init__(f"Invalid CONTENT_LENGTH {value}, expected a whole number")


class RemoteBodyOverlongError(RemoteProtocolError):
    """Raised when the remote peer sends more than CONTENT_LENGTH body bytes."""

    __slots__ = ()

    def __init__(self: RemoteBodyOverlongError) -> None:
        """Construct a new RemoteBodyOverlongError."""
        super().__init__("Request body longer than CONTENT_LENGTH")


class RemotePrematureEOFError(RemoteProtocolError):
    """Raised when the remote peer closes the connection before it should have."""

    __slots__ = ()

    def __init__(self: RemotePrematureEOFError) -> None:
        """Construct a new RemotePrematureEOFError."""
        super().__init__("Premature EOF")


class Event:
    """The base class of all events returned by an SCGIConnection."""

    __slots__ = ()


class RequestHeaders(Event):
    """Reports that a request has started and carries the environment data."""

    __slots__ = {
        "environment": """The environment variables, as a dict from name to value""",
    }

    environment: dict[str, bytes]

    def __init__(self: RequestHeaders, environment: dict[str, bytes]) -> None:
        """
        Construct a new RequestHeaders.

        :param environment: The environment variables, as a dict from name to value.
        """
        self.environment = environment

    def __repr__(self: RequestHeaders) -> str:
        """Return a representation of the environment."""
        return f"RequestHeaders({self.environment})"


class RequestBody(Event):
    """
    Transports some request body data.

    In between a RequestHeaders and a RequestEnd, zero or more RequestBody events are
    delivered, each carrying a chunk of the request body.

    No RequestBody event carries an empty chunk; consequently, a request without a body
    never generates RequestBody events.
    """

    __slots__ = {
        "data": """The body data chunk.""",
    }

    data: bytes

    def __init__(self: RequestBody, data: bytes) -> None:
        """
        Construct a new RequestBody.

        :param data: The body data chunk.
        """
        self.data = data

    def __repr__(self: RequestBody) -> str:
        """Return a representation of the body data."""
        return f"RequestBody({self.data!r})"


class RequestEnd(Event):
    """
    Reports that a request has finished.

    When this event occurs, both headers and all body data have been delivered in
    preceding events. Once this event has been delivered, the application can start
    sending the response.
    """

    __slots__ = ()

    def __repr__(self: RequestEnd) -> str:
        """Return a representation of the end marker."""
        return "RequestEnd()"


class ResponseHeaders(Event):
    """
    Sends the headers of a response to the SCGI client.

    This event must be sent after RequestEnd is received. After sending ResponseHeaders,
    if appropriate to the response, one or more ResponseBody events should be sent,
    followed by a ResponseEnd.
    """

    __slots__ = {
        "status": """The HTTP status code and string.""",
        "content_type": """The value of the Content-Type header.""",
        "location": """The value of the Location header.""",
        "other_headers": """The HTTP headers, except Content-Type and Location.""",
    }

    status: str | None
    content_type: str | None
    location: str | None
    other_headers: wsgiref.headers.Headers

    def __init__(
        self: ResponseHeaders, status: str | None, headers: list[tuple[str, str]]
    ) -> None:
        """
        Construct a ResponseHeaders.

        :param status: The HTTP status code and string (e.g. “200 OK”), or None if a
            local redirect or client redirect without document is being generated.
        :param headers: A list of (name, value) tuples of HTTP headers.
        :raises LocalProtocolError: If the application provided invalid data.
        """
        self.status = status
        self.other_headers = wsgiref.headers.Headers(list(headers))
        self.content_type = self.other_headers["Content-Type"]
        del self.other_headers["Content-Type"]
        self.location = self.other_headers["Location"]
        del self.other_headers["Location"]
        self._sanity_check()

    def encode(self: ResponseHeaders) -> bytes:
        """Convert this event into its encoding as raw bytes."""
        if self.status is None:
            # This is a local redirect or client redirect without document, which should
            # be served as a Location header and nothing else.
            #
            # Checked in sanity checks if status is None
            assert self.location is not None
            return b"Location: " + self.location.encode("ISO-8859-1") + b"\r\n\r\n"
        if self.location is not None:
            # This is a client redirect with document, which should be served as
            # Location, then Status, then Content-Type (if present), then everything
            # else.
            return (
                b"Location: "
                + self.location.encode("ISO-8859-1")
                + b"\r\nStatus: "
                + self.status.encode("ISO-8859-1")
                + b"\r\n"
                + self._content_type_encoded
                + bytes(self.other_headers)
            )
        # This is a document response, which should be served as Content-Type (if
        # present), then Status, then everything else.
        return (
            self._content_type_encoded
            + b"Status: "
            + self.status.encode("ISO-8859-1")
            + b"\r\n"
            + bytes(self.other_headers)
        )

    @property
    def succeeding_state(self: ResponseHeaders) -> TXState:
        """Return the state the transmit half be in after sending these headers."""
        return TXState.BODY if self.status is not None else TXState.NO_BODY

    def __repr__(self: ResponseHeaders) -> str:
        """Return a representation of the response headers."""
        return (
            f"ResponseHeaders(status={self.status}, content_type={self.content_type}, "
            f"location={self.location}, other_headers={self.other_headers!r})"
        )

    def _sanity_check(self: ResponseHeaders) -> None:
        """
        Perform sanity checks to verify that the headers are consistent.

        :raises LocalProtocolError: If a sanity check fails.
        """
        # The application must not specify any hop-by-hop headers.
        #
        # .keys() is necessary because wsgiref.headers.Headers objects are not iterable!
        for name in self.other_headers.keys():  # noqa: SIM118
            if wsgiref.util.is_hop_by_hop(name):
                raise ResponseHeaderHopByHopError(name)
        try:
            # The name and value of every header must be encodable in ISO-8859-1…
            bytes(self.other_headers)
            # … including Content-Type and Location…
            if self.content_type is not None:
                self.content_type.encode("ISO-8859-1")
            if self.location is not None:
                self.location.encode("ISO-8859-1")
            # … as must the status line.
            if self.status is not None:
                self.status.encode("ISO-8859-1")
        except UnicodeError as exp:
            raise ResponseHeaderNotISO88591Error from exp
        if self.status is None:
            self._sanity_check_without_document()

    def _sanity_check_without_document(self: ResponseHeaders) -> None:
        """
        Perform sanity checks specific to responses without bodies.

        :raises LocalProtocolError: If a sanity check fails.
        """
        # A response without a document must contain a Location header and nothing else.
        if self.location is None:
            raise NonDocumentHeadersError
        if self.content_type is not None or self.other_headers:
            raise NonDocumentHeadersError

    @property
    def _content_type_encoded(self: ResponseHeaders) -> bytes:
        """
        Return the encoded form of the Content-Type header.

        If the header is present, this is its name and value encoded to bytes plus a
        terminating CRLF. If not, this is the empty bytes.
        """
        if self.content_type is None:
            return b""
        return b"Content-Type: " + self.content_type.encode("ISO-8859-1") + b"\r\n"


class ResponseBody(Event):
    """Sends a chunk of response body to the SCGI client."""

    __slots__ = {
        "data": """The body data chunk.""",
    }

    data: bytes

    def __init__(self: ResponseBody, data: bytes) -> None:
        """
        Construct a ResponseBody.

        :param data: The bytes to send.
        """
        self.data = data

    def __repr__(self: ResponseBody) -> str:
        """Return a representation of the body data."""
        return f"ResponseBody({self.data!r})"


class ResponseEnd(Event):
    """
    Ends the response.

    This event must be the last one sent in a normal response.
    """

    __slots__ = ()

    def __repr__(self: ResponseEnd) -> str:
        """Return a representation of the end marker."""
        return "ResponseEnd()"


class SCGIConnection:
    """
    An SCGI connection.

    This class implements the SCGI protocol as a sans-I/O state machine, which simply
    translates between chunks of bytes and sequences of protocol events.
    """

    __slots__ = {
        "_rx_state": """
            The state of the receive half.

            This is the effective state after consuming all events in _event_queue but
            before considering any bytes in _rx_buffer.
            """,
        "_tx_state": """The state of the transmit half.""",
        "_error": """A callable which, when called, raises the detected error.""",
        "_event_queue": """
            The decoded but not yet returned events.

            These are events that have been received (via receive_data) but not yet
            returned by next_event.
            """,
        "_rx_buffer": """
            The received but not yet decoded bytes.

            These are bytes that have been received (via receive_data) but not yet
            converted into events and pushed to _event_queue. In between calls to
            receive_data, this is only the bytes making up a partial event (i.e. one for
            which some, but not all, of the bytes have been received yet). During a call
            to receive_data, it sometimes temporarily contains bytes making up one or
            more complete events, plus possible extra residue at the end, until the
            completed events are parsed and removed.
            """,
        "_rx_buffer_length": """The total number of bytes in _rx_buffer.""",
        "_rx_buffer_limit": """
            The maximum size of _rx_buffer in between calls to receive_bytes.

            During a call to receive_bytes, the buffer may exceed this length, but only
            temporarily until complete events are removed. Incomplete events must always
            be within this limit.
            """,
        "_rx_eof": """Whether an EOF has been reported via call to receive_bytes.""",
        "_rx_env_length": """The length of the headers block, once known.""",
        "_rx_body_remaining": """
            The amount of request body not yet converted into events in _event_queue.

            This includes both bytes in _rx_buffer and bytes not yet received.
            """,
    }

    _rx_state: RXState
    _tx_state: TXState
    _error: Callable[[], ProtocolError] | None
    _event_queue: collections.deque[Event]
    _rx_buffer: collections.deque[bytes]
    _rx_buffer_length: int
    _rx_buffer_limit: int
    _rx_eof: bool
    _rx_env_length: int
    _rx_body_remaining: int

    _MAX_NETSTRING_LENGTH_LENGTH: ClassVar[int] = 15
    """
    The maximum length of the netstring length prefix.

    If the length prefix is more than 15 characters long, then the netstring itself is
    almost a TiB long or more, which is unreasonable.
    """

    def __init__(self: SCGIConnection, rx_buffer_limit: int = 65536) -> None:
        """
        Construct a new SCGIConnection.

        :param rx_buffer_limit: The maximum number of received bytes that can be
            buffered locally before being turned into an event; this value bounds the
            size of request environment.
        """
        super().__init__()
        self._rx_state = RXState.HEADER_LENGTH
        self._tx_state = TXState.HEADERS
        self._error = None
        self._event_queue = collections.deque()
        self._rx_buffer = collections.deque()
        self._rx_buffer_length = 0
        self._rx_buffer_limit = rx_buffer_limit
        self._rx_eof = False
        self._rx_env_length = 0
        self._rx_body_remaining = 0

    @property
    def rx_state(self: SCGIConnection) -> RXState:
        """
        The state the receive half of the connection is currently in.

        Events and state transitions are generated on receipt of data, not on call to
        next_event, so this value reflects the state of the connection as it will be
        after all events have been consumed.
        """
        return self._rx_state

    @property
    def tx_state(self: SCGIConnection) -> TXState:
        """The state the transmit half of the connection is currently in."""
        return self._tx_state

    def receive_data(self: SCGIConnection, data: bytes) -> None:
        """
        Provide data received over the network to the SCGI connection.

        :param data: The received bytes, or a zero-length bytes object if the remote
            peer closed its end of the connection.
        :raises LocalProtocolError: If this method is called again after first being
            called with a zero-length parameter.
        """
        if data:
            if self._rx_eof:
                logging.getLogger(__name__).debug(
                    "Received %d bytes after EOF", len(data)
                )
                self._save_and_raise_error(ReceiveAfterEOFError)
            if self._rx_state is not RXState.ERROR:
                logging.getLogger(__name__).debug("Received %d bytes", len(data))
                self._rx_buffer.append(data)
                self._rx_buffer_length += len(data)
        else:
            logging.getLogger(__name__).debug("Received EOF")
            self._rx_eof = True
        # _parse_events raises a RemoteProtocolError if the peer violates protocol. Such
        # problems should not be reported via receive_data, but rather via next_event.
        # Thus, should such an exception be raised, stash it away instead of propagating
        # it.
        try:
            self._parse_events()
        except RemoteProtocolError:
            # The error should already have been saved in self._error, so all we should
            # need to do is swallow the exception to prevent it from coming out of the
            # wrong method.
            assert self._error is not None

    def next_event(self: SCGIConnection) -> Event | None:
        """
        Return the next event in the event queue.

        This method should generally be called repeatedly until it returns None after a
        call to receive_data. However, it is legal to leave some events unprocessed
        until a more convenient time, or even call receive_data again before receiving
        all the events.

        :raises LocalProtocolError: If a LocalProtocolError was previously raised by
            some other method of this connection.
        :raises RemoteProtocolError: If the remote peer violated SCGI protocol rules.
        """
        if self._rx_state is RXState.ERROR:
            assert self._error is not None  # Implied by RXState.ERROR
            raise self._error()  # noqa: RSE102
        if self._event_queue:
            return self._event_queue.popleft()
        return None

    def send(self: SCGIConnection, event: Event) -> bytes | None:
        """
        Send an event to the peer.

        :param event: The event to send.
        :raises LocalProtocolError: If the event is not acceptable right now.
        """
        logging.getLogger(__name__).debug("Sending %s", type(event))
        if self._tx_state is TXState.ERROR:
            assert self._error is not None  # Implied by TXState.ERROR
            raise self._error()  # noqa: RSE102
        if self._tx_state is TXState.HEADERS and isinstance(event, ResponseHeaders):
            self._tx_state = event.succeeding_state
            return event.encode()
        if self._tx_state is TXState.BODY and isinstance(
            event, ResponseBody | ResponseEnd
        ):
            if isinstance(event, ResponseBody):
                return event.data
            self._tx_state = TXState.DONE
            return None
        if self._tx_state is TXState.NO_BODY and isinstance(event, ResponseEnd):
            self._tx_state = TXState.DONE
            return None
        self._save_and_raise_error(
            functools.partial(BadEventInStateError, type(event), self._tx_state)
        )
        raise AssertionError

    def _parse_events(self: SCGIConnection) -> None:
        """
        Remove bytes from the receive buffer and create events in the event queue.

        :raises RemoteProtocolError: If the remote peer violated SCGI protocol rules.
        """
        # Throughout this method, we assume that at most one element has been added to
        # the receive buffer; this is safe because this method is called from
        # receive_data, so we eagerly parse as much as we can on every received chunk.
        logger = logging.getLogger(__name__)
        if self._rx_state is RXState.HEADER_LENGTH:
            logger.debug("In RX_HEADER_LENGTH")
            if self._rx_buffer:
                # The length-of-environment integer ends with a colon.
                index = self._rx_buffer[-1].find(b":")
                if (
                    index < 0
                    and self._rx_buffer_length > self._MAX_NETSTRING_LENGTH_LENGTH
                ):
                    self._save_and_raise_error(BadNetstringLengthError)
                if index >= 0:
                    logger.debug("Found : at %d", index)
                    # We have the full length-of-environment integer and its terminating
                    # colon. Split up received data into the length-of-environment
                    # integer, the colon (which we discard), and any bytes following the
                    # colon (residue).
                    residue = self._rx_buffer[-1][index + 1 :]
                    if index == 0:
                        self._rx_buffer.pop()
                    else:
                        self._rx_buffer[-1] = self._rx_buffer[-1][:index]
                    consumed = b"".join(self._rx_buffer)
                    self._rx_buffer.clear()
                    self._rx_buffer_length = 0
                    # Parse the length-of-environment integer.
                    try:
                        self._rx_env_length = int(consumed.decode("ASCII"))
                    except ValueError:
                        self._save_and_raise_error(BadNetstringLengthError)
                    # Sanity check the length-of-environment integer.
                    if self._rx_env_length <= 0:
                        self._save_and_raise_error(BadNetstringLengthError)
                    if self._rx_env_length > self._rx_buffer_limit:
                        self._save_and_raise_error(
                            functools.partial(
                                Error, self._rx_env_length, self._rx_buffer_limit
                            )
                        )
                    # Advance the state machine, keeping any residual bytes.
                    self._rx_state = RXState.HEADERS
                    if residue:
                        self._rx_buffer.append(residue)
                        self._rx_buffer_length += len(residue)
                    logger.debug(
                        "Length of headers is %d, residue is %d bytes",
                        self._rx_env_length,
                        len(residue),
                    )
        if self._rx_state is RXState.HEADERS:
            logger.debug("In RX_HEADERS")
            if self._rx_buffer_length > self._rx_env_length:
                # Split the receive buffer into the environment of the designated
                # length, the comma, and any bytes following the comma (residue).
                logger.debug("Got all headers")
                last_chunk_start_pos = self._rx_buffer_length - len(self._rx_buffer[-1])
                assert last_chunk_start_pos <= self._rx_env_length
                comma_pos = self._rx_env_length - last_chunk_start_pos
                comma = self._rx_buffer[-1][comma_pos]
                residue = self._rx_buffer[-1][comma_pos + 1 :]
                if last_chunk_start_pos == self._rx_env_length:
                    self._rx_buffer.pop()
                else:
                    self._rx_buffer[-1] = self._rx_buffer[-1][:comma_pos]
                environment = b"".join(self._rx_buffer)
                self._rx_buffer.clear()
                self._rx_buffer_length = 0
                # Check that the comma is a comma.
                if comma != ord(","):
                    self._save_and_raise_error(BadNetstringTerminatorError)
                # Check that the last byte of the environment block is a NUL
                if environment[-1] != 0x00:
                    self._save_and_raise_error(RequestHeadersNotNULTerminatedError)
                # Split the environment block into NUL-terminated chunks.
                split_environment = environment[:-1].split(b"\x00")
                # Check that there are an even number of parts.
                if len(split_environment) % 2 == 1:
                    self._save_and_raise_error(RequestHeadersOddStringCountError)
                # Build the dictionary.
                env_dict: dict[str, bytes] = {}
                for i in range(0, len(split_environment), 2):
                    try:
                        key = split_environment[i].decode("ISO-8859-1")
                    except UnicodeError:
                        self._save_and_raise_error(
                            functools.partial(
                                RequestHeaderNotISO88591Error, split_environment[i]
                            )
                        )
                    if not key:
                        self._save_and_raise_error(RequestHeaderEmptyError)
                    if key in env_dict:
                        self._save_and_raise_error(
                            functools.partial(DuplicateRequestHeaderError, key)
                        )
                    env_dict[key] = split_environment[i + 1]
                # Check for mandatory environment variables.
                scgi_version = env_dict.get("SCGI", None)
                if scgi_version is None:
                    self._save_and_raise_error(NoSCGIVariableError)
                if scgi_version != b"1":
                    self._save_and_raise_error(
                        functools.partial(BadSCGIVersionError, scgi_version)
                    )
                # Advance the state machine, keeping any residual bytes.
                self._rx_state = RXState.BODY
                if residue:
                    self._rx_buffer.append(residue)
                    self._rx_buffer_length += len(residue)
                content_length = env_dict.get("CONTENT_LENGTH", None)
                if content_length is None:
                    self._save_and_raise_error(NoContentLengthError)
                try:
                    self._rx_body_remaining = int(content_length)
                except ValueError:
                    self._rx_body_remaining = -1
                if self._rx_body_remaining < 0:
                    self._save_and_raise_error(
                        functools.partial(BadContentLengthError, content_length)
                    )
                self._event_queue.append(RequestHeaders(env_dict))
                logger.debug(
                    "Retrieved %d headers, residue is %d bytes",
                    len(env_dict),
                    len(residue),
                )
        if self._rx_state is RXState.BODY:
            logger.debug(
                "In RX_BODY, buffer length = %d, body remaining = %d",
                self._rx_buffer_length,
                self._rx_body_remaining,
            )
            if self._rx_buffer_length <= self._rx_body_remaining:
                for chunk in self._rx_buffer:
                    self._event_queue.append(RequestBody(chunk))
                self._rx_body_remaining -= self._rx_buffer_length
                self._rx_buffer.clear()
                self._rx_buffer_length = 0
                if self._rx_body_remaining == 0:
                    self._event_queue.append(RequestEnd())
                    self._rx_state = RXState.DONE
            else:
                self._save_and_raise_error(RemoteBodyOverlongError)
        if self._rx_state is RXState.DONE:
            logger.debug("In RX_DONE")
            if self._rx_buffer_length:
                self._save_and_raise_error(RemoteBodyOverlongError)
        if self._rx_eof and self._rx_state in {
            RXState.HEADER_LENGTH,
            RXState.HEADERS,
            RXState.BODY,
        }:
            self._save_and_raise_error(RemotePrematureEOFError)

    def _save_and_raise_error(
        self: SCGIConnection, error: Callable[[], ProtocolError]
    ) -> NoReturn:
        """
        Record and immediately raise a protocol error.

        :param error: A callable that, when invoked, constructs the error.
        """
        self._rx_state = RXState.ERROR
        self._tx_state = TXState.ERROR
        self._error = error
        raise error()  # noqa: RSE102
