"""Implements the request half of the SCGI protocol."""

from __future__ import annotations

import collections
import enum
import functools
import logging
from collections.abc import Callable
from typing import ClassVar, NoReturn


@enum.unique
class State(enum.Enum):
    """The possible states the receive half of the connection can be in."""

    HEADER_LENGTH = enum.auto()
    """The length of the header block is being read."""

    HEADERS = enum.auto()
    """The header block is being read."""

    BODY = enum.auto()
    """The request body is being read."""

    DONE = enum.auto()
    """The request body has finished being read."""

    ERROR = enum.auto()
    """An error occurred."""


class Error(Exception):
    """
    Raised when the remote peer violates protocol.

    This is the base class of various specific errors and is never raised directly.
    """

    __slots__ = ()


class HeadersError(Error):
    """
    Raised when the remote peer sends an invalid environment block.

    This is the base class of various specific errors and is never raised directly.
    """

    __slots__ = ()


class NetstringError(HeadersError):
    """
    Raised when the remote peer sends an invalid netstring.

    This is the base class of various specific errors and is never raised directly.
    """

    __slots__ = ()


class BadNetstringLengthError(NetstringError):
    """
    Raised when the remote peer sends a netstring with bad length prefix.

    This means that either the length is improperly encoded or that it is too large.
    """

    __slots__ = ()

    def __init__(self: BadNetstringLengthError) -> None:
        """Construct a new BadNetstringLengthError."""
        super().__init__("Invalid netstring length prefix")


class BadNetstringTerminatorError(NetstringError):
    """Raised when the remote peer sends a netstring with the wrong terminator."""

    __slots__ = ()

    def __init__(self: BadNetstringTerminatorError) -> None:
        """Construct a new BadNetstringTerminatorError."""
        super().__init__("Invalid end-of-environment character")


class HeadersStructuralError(HeadersError):
    """
    Raised when the remote peer sends request headers with a structural problem.

    This is the base class of various specific errors and is never raised directly.
    """

    __slots__ = ()


class HeadersNotNULTerminatedError(HeadersStructuralError):
    """Raised when the remote peer sends request headers whose last byte is not NUL."""

    __slots__ = ()

    def __init__(self: HeadersNotNULTerminatedError) -> None:
        """Construct a new HeadersNotNULTerminatedError."""
        super().__init__("Environment block not NUL-terminated")


class HeadersOddStringCountError(HeadersStructuralError):
    """Raised when the remote peer sends an odd number of strings in the environment."""

    __slots__ = ()

    def __init__(self: HeadersOddStringCountError) -> None:
        """Construct a new HeadersOddStringCountError."""
        super().__init__("Environment block missing final value")


class HeaderNotISO88591Error(HeadersStructuralError):
    """Raised when the remote peer sends a variable whose name is invalid ISO-8859-1."""

    __slots__ = ()

    def __init__(self: HeaderNotISO88591Error, name: bytes) -> None:
        """
        Construct a new HeaderNotISO88591Error.

        :param name: The non-ISO-8859-1 variable name.
        """
        super().__init__(f"Environment variable name {name!r} is not ISO-8859-1")


class HeaderEmptyError(HeadersStructuralError):
    """Raised when the remote peer sends a variable whose name is empty."""

    __slots__ = ()

    def __init__(self: HeaderEmptyError) -> None:
        """Construct a new HeaderEmptyError."""
        super().__init__("Environment variable with empty name")


class DuplicateHeaderError(HeadersStructuralError):
    """Raised when the remote peer sends two variables with the same name."""

    __slots__ = ()

    def __init__(self: DuplicateHeaderError, name: str) -> None:
        """
        Construct a new DuplicateHeaderError.

        :param name: The name of the variable which appears multiple times.
        """
        super().__init__(f"Duplicate environment variable {name}")


class HeadersContentError(HeadersError):
    """
    Raised when the remote peer sends request headers with a content problem.

    This is the base class of various specific errors and is never raised directly.
    """

    __slots__ = ()


class NoSCGIVariableError(HeadersContentError):
    """Raised when the remote peer does not send the SCGI variable."""

    __slots__ = ()

    def __init__(self: NoSCGIVariableError) -> None:
        """Construct a new NoSCGIVariableError."""
        super().__init__("Mandatory variable SCGI missing")


class BadSCGIVersionError(HeadersContentError):
    """Raised when the remote peer is speaking an unsupported version of SCGI."""

    __slots__ = ()

    def __init__(self: BadSCGIVersionError, version: bytes) -> None:
        """
        Construct a new BadSCGIVersionError.

        :param version: The version that the peer is speaking.
        """
        super().__init__(f"SCGI variable is {version!r}, expected 1")


class NoContentLengthError(HeadersContentError):
    """Raised when the remote peer does not send the CONTENT_LENGTH variable."""

    __slots__ = ()

    def __init__(self: NoContentLengthError) -> None:
        """Construct a new NoContentLengthError."""
        super().__init__("Mandatory variable CONTENT_LENGTH missing")


class BadContentLengthError(HeadersContentError):
    """Raised when the remote peer sends an invalid CONTENT_LENGTH value."""

    __slots__ = ()

    def __init__(self: BadContentLengthError, value: str) -> None:
        """
        Construct a new BadContentLengthError.

        :param value: The invalid value.
        """
        super().__init__(f"Invalid CONTENT_LENGTH {value}, expected a whole number")


class RemotePrematureEOFError(Error):
    """Raised when the remote peer closes the connection before it should have."""

    __slots__ = ()

    def __init__(self: RemotePrematureEOFError) -> None:
        """Construct a new RemotePrematureEOFError."""
        super().__init__("Premature EOF")


class ReceiveAfterEOFError(Error):
    """Raised when data is received after EOF."""

    __slots__ = ()

    def __init__(self: ReceiveAfterEOFError) -> None:
        """Construct a new ReceiveAfterEOFError."""
        super().__init__("Data received after EOF")


class Event:
    """The base class of all events returned by an SCGIReader."""

    __slots__ = ()


class Headers(Event):
    """Reports that a request has started and carries the environment data."""

    __slots__ = {
        "environment": """The environment variables, as a dict from name to value""",
    }

    environment: dict[str, bytes]

    def __init__(self: Headers, environment: dict[str, bytes]) -> None:
        """
        Construct a new Headers.

        :param environment: The environment variables, as a dict from name to value.
        """
        self.environment = environment

    def __repr__(self: Headers) -> str:
        """Return a representation of the environment."""
        return f"Headers({self.environment})"


class Body(Event):
    """
    Transports some request body data.

    In between a Headers and a End, zero or more Body events are delivered, each
    carrying a chunk of the request body.

    No Body event carries an empty chunk; consequently, a request without a body never
    generates Body events.
    """

    __slots__ = {
        "data": """The body data chunk.""",
    }

    data: bytes

    def __init__(self: Body, data: bytes) -> None:
        """
        Construct a new Body.

        :param data: The body data chunk.
        """
        self.data = data

    def __repr__(self: Body) -> str:
        """Return a representation of the body data."""
        return f"Body({self.data!r})"


class End(Event):
    """
    Reports that a request has finished.

    When this event occurs, both headers and all body data have been delivered in
    preceding events. Once this event has been delivered, the application can start
    sending the response.
    """

    __slots__ = ()

    def __repr__(self: End) -> str:
        """Return a representation of the end marker."""
        return "End()"


class SCGIReader:
    """
    The read half of an SCGI connection.

    This class implements the read half of the SCGI protocol as a sans-I/O state
    machine, which simply translates chunks of bytes into sequences of protocol events.
    """

    __slots__ = {
        "_body_remaining": """
            The amount of request body not yet converted into events in _event_queue.

            This includes both bytes in _buffer and bytes not yet received.
            """,
        "_buffer": """
            The received but not yet decoded bytes.

            These are bytes that have been received (via receive_data) but not yet
            converted into events and pushed to _event_queue. In between calls to
            receive_data, this is only the bytes making up a partial event (i.e. one for
            which some, but not all, of the bytes have been received yet). During a call
            to receive_data, it sometimes temporarily contains bytes making up one or
            more complete events, plus possible extra residue at the end, until the
            completed events are parsed and removed.
            """,
        "_buffer_length": """The total number of bytes in _buffer.""",
        "_buffer_limit": """
            The maximum size of _buffer in between calls to receive_bytes.

            During a call to receive_bytes, the buffer may exceed this length, but only
            temporarily until complete events are removed. Incomplete events must always
            be within this limit.
            """,
        "_env_length": """The length of the headers block, once known.""",
        "_eof": """Whether an EOF has been reported via call to receive_bytes.""",
        "_error": """A callable which, when called, raises the detected error.""",
        "_event_queue": """
            The decoded but not yet returned events.

            These are events that have been received (via receive_data) but not yet
            returned by next_event.
            """,
        "_state": """
            The state of the state machine.

            This is the effective state after consuming all events in _event_queue but
            before considering any bytes in _buffer.
            """,
    }

    _body_remaining: int
    _buffer: collections.deque[bytes]
    _buffer_length: int
    _buffer_limit: int
    _env_length: int
    _eof: bool
    _error: Callable[[], Error] | None
    _event_queue: collections.deque[Event]
    _state: State

    _MAX_NETSTRING_LENGTH_LENGTH: ClassVar[int] = 15
    """
    The maximum length of the netstring length prefix.

    If the length prefix is more than 15 characters long, then the netstring itself is
    almost a TiB long or more, which is unreasonable.
    """

    def __init__(self: SCGIReader, rx_buffer_limit: int = 65536) -> None:
        """
        Construct a new SCGIReader.

        :param rx_buffer_limit: The maximum number of received bytes that can be
            buffered locally before being turned into an event; this value bounds the
            size of request environment.
        """
        super().__init__()
        self._body_remaining = 0
        self._buffer = collections.deque()
        self._buffer_length = 0
        self._buffer_limit = rx_buffer_limit
        self._env_length = 0
        self._eof = False
        self._error = None
        self._event_queue = collections.deque()
        self._state = State.HEADER_LENGTH

    @property
    def state(self: SCGIReader) -> State:
        """
        The state the state machine is currently in.

        Events and state transitions are generated on receipt of data, not on call to
        next_event, so this value reflects the state of the reader as it will be after
        all events have been consumed.
        """
        return self._state

    def receive_data(self: SCGIReader, data: bytes) -> None:
        """
        Provide data received over the network to the SCGI reader.

        :param data: The received bytes, or a zero-length bytes object if the remote
            peer closed its end of the connection.
        :raises ReceiveAfterEOFError: If this method is called again after first being
            called with a zero-length parameter.
        """
        if data:
            if self._eof:
                logging.getLogger(__name__).debug(
                    "Received %d bytes after EOF", len(data)
                )
                self._save_and_raise_error(ReceiveAfterEOFError)
            if self._state is not State.ERROR:
                logging.getLogger(__name__).debug("Received %d bytes", len(data))
                self._buffer.append(data)
                self._buffer_length += len(data)
        else:
            logging.getLogger(__name__).debug("Received EOF")
            self._eof = True
        # _parse_events raises an Error if the peer violates protocol. Such problems
        # should not be reported via receive_data, but rather via next_event. Thus,
        # should such an exception be raised, stash it away instead of propagating it.
        try:
            self._parse_events()
        except Error:
            # The error should already have been saved in self._error, so all we should
            # need to do is swallow the exception to prevent it from coming out of the
            # wrong method.
            assert self._error is not None

    def next_event(self: SCGIReader) -> Event | None:
        """
        Return the next event in the event queue.

        This method should generally be called repeatedly until it returns None after a
        call to receive_data. However, it is legal to leave some events unprocessed
        until a more convenient time, or even call receive_data again before receiving
        all the events.

        :raises Error: If an Error was previously raised by some other method of this
            reader.
        :raises Error: If the remote peer violated SCGI protocol rules.
        """
        if self._state is State.ERROR:
            assert self._error is not None  # Implied by State.ERROR
            raise self._error()
        if self._event_queue:
            return self._event_queue.popleft()
        return None

    def _parse_events(self: SCGIReader) -> None:
        """
        Remove bytes from the receive buffer and create events in the event queue.

        :raises Error: If the remote peer violated SCGI protocol rules.
        """
        # Throughout this method, we assume that at most one element has been added to
        # the receive buffer; this is safe because this method is called from
        # receive_data, so we eagerly parse as much as we can on every received chunk.
        logger = logging.getLogger(__name__)
        if self._state is State.HEADER_LENGTH:
            logger.debug("In RX_HEADER_LENGTH")
            if self._buffer:
                # The length-of-environment integer ends with a colon.
                index = self._buffer[-1].find(b":")
                if (
                    index < 0
                    and self._buffer_length > self._MAX_NETSTRING_LENGTH_LENGTH
                ):
                    self._save_and_raise_error(BadNetstringLengthError)
                if index >= 0:
                    logger.debug("Found : at %d", index)
                    # We have the full length-of-environment integer and its terminating
                    # colon. Split up received data into the length-of-environment
                    # integer, the colon (which we discard), and any bytes following the
                    # colon (residue).
                    residue = self._buffer[-1][index + 1 :]
                    if index == 0:
                        self._buffer.pop()
                    else:
                        self._buffer[-1] = self._buffer[-1][:index]
                    consumed = b"".join(self._buffer)
                    self._buffer.clear()
                    self._buffer_length = 0
                    # Parse the length-of-environment integer.
                    try:
                        self._env_length = int(consumed.decode("ASCII"))
                    except ValueError:
                        self._save_and_raise_error(BadNetstringLengthError)
                    # Sanity check the length-of-environment integer.
                    if self._env_length <= 0:
                        self._save_and_raise_error(BadNetstringLengthError)
                    if self._env_length > self._buffer_limit:
                        self._save_and_raise_error(BadNetstringLengthError)
                    # Advance the state machine, keeping any residual bytes.
                    self._state = State.HEADERS
                    if residue:
                        self._buffer.append(residue)
                        self._buffer_length += len(residue)
                    logger.debug(
                        "Length of headers is %d, residue is %d bytes",
                        self._env_length,
                        len(residue),
                    )
        if self._state is State.HEADERS:
            logger.debug("In RX_HEADERS")
            if self._buffer_length > self._env_length:
                # Split the receive buffer into the environment of the designated
                # length, the comma, and any bytes following the comma (residue).
                logger.debug("Got all headers")
                last_chunk_start_pos = self._buffer_length - len(self._buffer[-1])
                assert last_chunk_start_pos <= self._env_length
                comma_pos = self._env_length - last_chunk_start_pos
                comma = self._buffer[-1][comma_pos]
                residue = self._buffer[-1][comma_pos + 1 :]
                if last_chunk_start_pos == self._env_length:
                    self._buffer.pop()
                else:
                    self._buffer[-1] = self._buffer[-1][:comma_pos]
                environment = b"".join(self._buffer)
                self._buffer.clear()
                self._buffer_length = 0
                # Check that the comma is a comma.
                if comma != ord(","):
                    self._save_and_raise_error(BadNetstringTerminatorError)
                # Check that the last byte of the environment block is a NUL
                if environment[-1] != 0x00:
                    self._save_and_raise_error(HeadersNotNULTerminatedError)
                # Split the environment block into NUL-terminated chunks.
                split_environment = environment[:-1].split(b"\x00")
                # Check that there are an even number of parts.
                if len(split_environment) % 2 == 1:
                    self._save_and_raise_error(HeadersOddStringCountError)
                # Build the dictionary.
                env_dict: dict[str, bytes] = {}
                for i in range(0, len(split_environment), 2):
                    try:
                        key = split_environment[i].decode("ISO-8859-1")
                    except UnicodeError:
                        self._save_and_raise_error(
                            functools.partial(
                                HeaderNotISO88591Error, split_environment[i]
                            )
                        )
                    if not key:
                        self._save_and_raise_error(HeaderEmptyError)
                    if key in env_dict:
                        self._save_and_raise_error(
                            functools.partial(DuplicateHeaderError, key)
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
                self._state = State.BODY
                if residue:
                    self._buffer.append(residue)
                    self._buffer_length += len(residue)
                content_length = env_dict.get("CONTENT_LENGTH", None)
                if content_length is None:
                    self._save_and_raise_error(NoContentLengthError)
                try:
                    self._body_remaining = int(content_length)
                except ValueError:
                    self._body_remaining = -1
                if self._body_remaining < 0:
                    self._save_and_raise_error(
                        functools.partial(BadContentLengthError, content_length)
                    )
                self._event_queue.append(Headers(env_dict))
                logger.debug(
                    "Retrieved %d headers, residue is %d bytes",
                    len(env_dict),
                    len(residue),
                )
        if self._state is State.BODY:
            logger.debug(
                "In RX_BODY, buffer length = %d, body remaining = %d",
                self._buffer_length,
                self._body_remaining,
            )
            while 0 < self._buffer_length <= self._body_remaining:
                chunk = self._buffer.popleft()
                self._event_queue.append(Body(chunk))
                self._body_remaining -= len(chunk)
                self._buffer_length -= len(chunk)
            if 0 < self._body_remaining < self._buffer_length:
                chunk = self._buffer.popleft()
                self._event_queue.append(Body(chunk[: self._body_remaining]))
                self._body_remaining = 0
                self._buffer_length -= len(chunk)
            if self._body_remaining == 0:
                self._event_queue.append(End())
                self._state = State.DONE
        if self._state is State.DONE:
            logger.debug("In RX_DONE")
            self._buffer.clear()
            self._buffer_length = 0
        if self._eof and self._state in {
            State.HEADER_LENGTH,
            State.HEADERS,
            State.BODY,
        }:
            self._save_and_raise_error(RemotePrematureEOFError)

    def _save_and_raise_error(self: SCGIReader, error: Callable[[], Error]) -> NoReturn:
        """
        Record and immediately raise a protocol error.

        :param error: A callable that, when invoked, constructs the error.
        """
        self._state = State.ERROR
        self._error = error
        raise error()
