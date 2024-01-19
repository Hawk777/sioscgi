"""Implements the transmit half of the SCGI protocol."""

from __future__ import annotations

import enum
import logging
import wsgiref.headers
import wsgiref.util


@enum.unique
class State(enum.Enum):
    """The possible states the transmit half of the connection can be in."""

    HEADERS = enum.auto()
    """The application needs to send the headers."""

    BODY = enum.auto()
    """The application needs to send the next part of the body or end the body."""

    NO_BODY = enum.auto()
    """The application needs to send an end-of-request marker."""

    DONE = enum.auto()
    """The response is complete and the application should close the socket."""


class Error(Exception):
    """
    Raised when the local application violates protocol.

    This is the base class of various specific errors and is never raised directly.
    """

    __slots__ = ()


class HeaderHopByHopError(Error):
    """Raised when a response includes a hop-by-hop header."""

    __slots__ = ()

    def __init__(self: HeaderHopByHopError, name: str) -> None:
        """
        Construct a new HeaderHopByHopError.

        :param name: The name of the unacceptable header.
        """
        super().__init__(f"Header {name} is hop-by-hop and therefore illegal")


class HeaderNotISO88591Error(Error):
    """Raised when a response header value cannot be encoded in ISO-8859-1."""

    __slots__ = ()

    def __init__(self: HeaderNotISO88591Error) -> None:
        """Construct a new HeaderNotISO88591Error."""
        super().__init__("A response header is not ISO-8859-1-encodable")


class NonDocumentHeadersError(Error):
    """Raised when response headers are invalid for a non-document response."""

    __slots__ = ()

    def __init__(self: NonDocumentHeadersError) -> None:
        """Construct a new NonDocumentHeadersError."""
        super().__init__(
            "Non-document responses must contain a Location header and no others"
        )


class BadEventInStateError(Error):
    """Raised when the local application sends an unacceptable event."""

    __slots__ = ()

    def __init__(self: BadEventInStateError, event: type[Event], state: State) -> None:
        """
        Construct a new BadEventInStateError.

        :param event: The event that the application tried to send.
        :param state: The state that the state machine was in.
        """
        super().__init__(f"Event {type(event)} prohibited in state {state}")


class Event:
    """The base class of all events sendable to an SCGIWriter."""

    __slots__ = ()


class Headers(Event):
    """
    Sends the headers of a response to the SCGI client.

    This event must be sent first. After sending Headers, if appropriate to the
    response, one or more Body events should be sent, followed by a End.
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
        self: Headers, status: str | None, headers: list[tuple[str, str]]
    ) -> None:
        """
        Construct a Headers.

        :param status: The HTTP status code and string (e.g. “200 OK”), or None if a
            local redirect or client redirect without document is being generated.
        :param headers: A list of (name, value) tuples of HTTP headers.
        :raises Error: If the application provided invalid data.
        """
        self.status = status
        self.other_headers = wsgiref.headers.Headers(list(headers))
        self.content_type = self.other_headers["Content-Type"]
        del self.other_headers["Content-Type"]
        self.location = self.other_headers["Location"]
        del self.other_headers["Location"]
        self._sanity_check()

    def encode(self: Headers) -> bytes:
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
    def succeeding_state(self: Headers) -> State:
        """Return the state the transmit half will be in after sending these headers."""
        return State.BODY if self.status is not None else State.NO_BODY

    def __repr__(self: Headers) -> str:
        """Return a representation of the response headers."""
        return (
            f"Headers(status={self.status}, content_type={self.content_type}, "
            f"location={self.location}, other_headers={self.other_headers!r})"
        )

    def _sanity_check(self: Headers) -> None:
        """
        Perform sanity checks to verify that the headers are consistent.

        :raises Error: If a sanity check fails.
        """
        # The application must not specify any hop-by-hop headers.
        #
        # .keys() is necessary because wsgiref.headers.Headers objects are not iterable!
        for name in self.other_headers.keys():  # noqa: SIM118
            if wsgiref.util.is_hop_by_hop(name):
                raise HeaderHopByHopError(name)
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
            raise HeaderNotISO88591Error from exp
        if self.status is None:
            self._sanity_check_without_document()

    def _sanity_check_without_document(self: Headers) -> None:
        """
        Perform sanity checks specific to responses without bodies.

        :raises Error: If a sanity check fails.
        """
        # A response without a document must contain a Location header and nothing else.
        if self.location is None:
            raise NonDocumentHeadersError
        if self.content_type is not None or self.other_headers:
            raise NonDocumentHeadersError

    @property
    def _content_type_encoded(self: Headers) -> bytes:
        """
        Return the encoded form of the Content-Type header.

        If the header is present, this is its name and value encoded to bytes plus a
        terminating CRLF. If not, this is the empty bytes.
        """
        if self.content_type is None:
            return b""
        return b"Content-Type: " + self.content_type.encode("ISO-8859-1") + b"\r\n"


class Body(Event):
    """Sends a chunk of response body to the SCGI client."""

    __slots__ = {
        "data": """The body data chunk.""",
    }

    data: bytes

    def __init__(self: Body, data: bytes) -> None:
        """
        Construct a Body.

        :param data: The bytes to send.
        """
        self.data = data

    def __repr__(self: Body) -> str:
        """Return a representation of the body data."""
        return f"Body({self.data!r})"


class End(Event):
    """
    Ends the response.

    This event must be the last one sent in a normal response.
    """

    __slots__ = ()

    def __repr__(self: End) -> str:
        """Return a representation of the end marker."""
        return "End()"


class SCGIWriter:
    """
    The write half of an SCGI connection.

    This class implements the write half of the SCGI protocol as a sans-I/O state
    machine, which simply translates sequences of protocol events into chunks of bytes.
    """

    __slots__ = {
        "_state": """The state of the state machine.""",
    }

    _state: State

    def __init__(self: SCGIWriter) -> None:
        """Construct a new SCGIWriter."""
        super().__init__()
        self._state = State.HEADERS

    @property
    def state(self: SCGIWriter) -> State:
        """The state the transmit half of the connection is currently in."""
        return self._state

    def send(self: SCGIWriter, event: Event) -> bytes | None:
        """
        Send an event to the peer.

        :param event: The event to send.
        :return: The bytes to send over the socket to implement this event, or None to
            close the socket.
        :raises Error: If the event is not acceptable right now.
        """
        logging.getLogger(__name__).debug("Sending %s", type(event))
        if self._state is State.HEADERS and isinstance(event, Headers):
            self._state = event.succeeding_state
            return event.encode()
        if self._state is State.BODY and isinstance(event, Body | End):
            if isinstance(event, Body):
                return event.data
            self._state = State.DONE
            return None
        if self._state is State.NO_BODY and isinstance(event, End):
            self._state = State.DONE
            return None
        raise BadEventInStateError(type(event), self._state)
