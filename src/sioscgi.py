"""
Implements the SCGI protocol.
"""

import collections
import enum
import logging
from typing import Deque, Dict, List, Optional, Tuple, Type
import wsgiref.headers
import wsgiref.util


@enum.unique
class RXState(enum.Enum):
    """
    The possible states the receive half of the connection can be in.
    """

    HEADER_LENGTH = enum.auto()
    HEADERS = enum.auto()
    BODY = enum.auto()
    DONE = enum.auto()
    ERROR = enum.auto()


@enum.unique
class TXState(enum.Enum):
    """
    The possible states the transmit half of the connection can be in.
    """
    HEADERS = enum.auto()
    BODY = enum.auto()
    NO_BODY = enum.auto()
    DONE = enum.auto()
    ERROR = enum.auto()


class ProtocolError(Exception):
    """
    Raised when a violation of protocol occurs, by either the remote peer or
    the local application.

    This is the base class of LocalProtocolError and RemoteProtocolError.
    """


class LocalProtocolError(ProtocolError):
    """
    Raised when the local application violates protocol.
    """


class RemoteProtocolError(ProtocolError):
    """
    Raised when the remote peer violates protocol.
    """


class Event:
    """
    The base class of all events returned by an SCGIConnection.
    """
    __slots__ = ()


class RequestHeaders(Event):
    """
    Reports that a request has started and carries the environment data.
    """
    __slots__ = ("environment",)

    def __init__(self, environment: Dict[str, str]):
        self.environment = environment
        """The environment variables, as a dict from name to value"""

    def __repr__(self) -> str:
        return "RequestHeaders({})".format(self.environment)


class RequestBody(Event):
    """
    Transports some request body data.

    In between a RequestHeaders and a RequestEnd, zero or more RequestBody
    events are delivered, each carrying a chunk of the request body.

    No RequestBody event carries an empty chunk; consequently, a request
    without a body never generates RequestBody events.
    """
    __slots__ = ("data",)

    def __init__(self, data: bytes):
        self.data = data
        """The body data chunk"""

    def __repr__(self) -> str:
        return "RequestBody({})".format(repr(self.data))


class RequestEnd(Event):
    """
    Reports that a request has finished and both headers and all body data have
    been delivered in preceding events.

    Once this event has been delivered, the application can start sending the
    response.
    """
    __slots__ = ()

    def __repr__(self) -> str:
        return "RequestEnd()"


class ResponseHeaders(Event):
    """
    Sends the headers of a response to the SCGI client.

    This event must be sent after RequestEnd is received. After sending
    ResponseHeaders, if appropriate to the response, one or more ResponseBody
    events should be sent, followed by a ResponseEnd.
    """
    __slots__ = ("status", "content_type", "location", "other_headers")

    status: Optional[str]
    content_type: Optional[str]
    location: Optional[str]
    other_headers: wsgiref.headers.Headers

    def __init__(self, status: Optional[str], headers: List[Tuple[str, str]]):
        """
        Construct a ResponseHeaders.

        status -- the HTTP status code and string (e.g. “200 OK”), or None if a
            local redirect or client redirect without document is being
            generated
        headers -- a list of (name, value) tuples of HTTP headers
        """
        self.status = status
        self.other_headers = wsgiref.headers.Headers(list(headers))
        self.content_type = self.other_headers["Content-Type"]
        del self.other_headers["Content-Type"]
        self.location = self.other_headers["Location"]
        del self.other_headers["Location"]
        self._sanity_check()

    def encode(self) -> bytes:
        """
        Convert this event into its encoding as raw bytes.
        """
        if self.status is None:
            # This is a local redirect or client redirect without document,
            # which should be served as a Location header and nothing else.
            assert self.location is not None  # Checked in sanity checks if status is None
            return B"Location: " + self.location.encode("ISO-8859-1") + B"\r\n\r\n"
        elif self.location is not None:
            # This is a client redirect with document, which should be served
            # as Location, then Status, then Content-Type, then everything
            # else.
            assert self.content_type is not None  # Checked in sanity checks if status is not None
            return B"Location: " + self.location.encode("ISO-8859-1") + B"\r\nStatus: " + self.status.encode("ISO-8859-1") + B"\r\nContent-Type: " + self.content_type.encode("ISO-8859-1") + B"\r\n" + bytes(self.other_headers)
        else:
            # This is a document response, which should be served as
            # Content-Type, then Status, then everything else.
            assert self.content_type is not None  # Checked in sanity checks if status is not None
            return B"Content-Type: " + self.content_type.encode("ISO-8859-1") + B"\r\nStatus: " + self.status.encode("ISO-8859-1") + B"\r\n" + bytes(self.other_headers)

    @property
    def succeeding_state(self) -> TXState:
        """
        Return the state the state machine should be in after sending these
        headers.
        """
        if self.status is not None:
            return TXState.BODY
        else:
            return TXState.NO_BODY

    def __repr__(self) -> str:
        return "ResponseHeaders(status={}, content_type={}, location={}, other_headers={})".format(self.status, self.content_type, self.location, repr(self.other_headers))

    def _sanity_check(self) -> None:
        # The application must not specify any hop-by-hop headers.
        for name in self.other_headers.keys():
            if wsgiref.util.is_hop_by_hop(name):
                raise LocalProtocolError("Header {} is hop-by-hop and therefore illegal".format(name))
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
        except UnicodeError:
            raise LocalProtocolError("A header is not ISO-8859-1-encodable")
        if self.status is not None:
            self._sanity_check_with_document()
        else:
            self._sanity_check_without_document()

    def _sanity_check_with_document(self) -> None:
        # A response with a document must contain a Content-Type header.
        if self.content_type is None:
            raise LocalProtocolError("Header Content-Type is mandatory for document response")

    def _sanity_check_without_document(self) -> None:
        # A response without a document must contain a Location header and
        # nothing else.
        if self.location is None:
            raise LocalProtocolError("Header Location is mandatory for non-document response")
        if self.content_type is not None or self.other_headers:
            raise LocalProtocolError("Headers other than Location are prohibited for non-document response")


class ResponseBody(Event):
    """
    Sends a chunk of response body to the SCGI client.
    """
    __slots__ = ("data",)

    def __init__(self, data: bytes):
        """
        Construct a ResponseBody.

        data -- the bytes to send
        """
        self.data = data

    def __repr__(self) -> str:
        return "ResponseBody({})".format(repr(self.data))


class ResponseEnd(Event):
    """
    Ends the response.

    This event must be the last one sent in a normal response.
    """
    __slots__ = ()

    def __repr__(self) -> str:
        return "ResponseEnd()"


class SCGIConnection:
    """
    An SCGI connection.

    This class implements the SCGI protocol as a sans-I/O state machine, which
    simply translates between chunks of bytes and sequences of protocol events.
    """

    __slots__ = (
        "_rx_state",
        "_tx_state",
        "_error_class",
        "_error_msg",
        "_event_queue",
        "_rx_buffer",
        "_rx_buffer_length",
        "_rx_buffer_limit",
        "_rx_eof",
        "_rx_env_length",
        "_rx_body_remaining",
    )

    _rx_state: RXState
    _tx_state: TXState
    _error_class: Optional[Type[ProtocolError]]
    _error_msg: Optional[str]
    _event_queue: Deque[Event]
    _rx_buffer: Deque[bytes]
    _rx_buffer_length: int
    _rx_buffer_limit: int
    _rx_eof: bool
    _rx_env_length: int
    _rx_body_remaining: int

    def __init__(self, rx_buffer_limit: int = 65536):
        """
        Construct a new SCGIConnection.

        rx_buffer_limit -- the maximum number of received bytes that can be
            buffered locally before being turned into an event; this value
            bounds the size of request environment
        """
        super().__init__()
        self._rx_state = RXState.HEADER_LENGTH
        self._tx_state = TXState.HEADERS
        self._error_class = None
        self._error_msg = None
        self._event_queue = collections.deque()
        self._rx_buffer = collections.deque()
        self._rx_buffer_length = 0
        self._rx_buffer_limit = rx_buffer_limit
        self._rx_eof = False
        self._rx_env_length = 0
        self._rx_body_remaining = 0

    @property
    def rx_state(self) -> RXState:
        """
        The state the receive half of the connection is currently in.

        Events and state transitions are generated on receipt of data, not on
        call to next_event, so this value reflects the state of the connection
        as it will be after all events have been consumed.
        """
        return self._rx_state

    @property
    def tx_state(self) -> TXState:
        """
        The state the transmit half of the connection is currently in.
        """
        return self._tx_state

    def receive_data(self, data: bytes) -> None:
        """
        Provide data received over the network to the SCGI connection.

        data -- the received bytes, or a zero-length bytes object if the remote
            peer closed its end of the connection

        This method raises LocalProtocolError if a nonzero-length data is
        passed in after a zero-length data has previously been passed. It does
        not raise exceptions for any other reason.
        """
        if data:
            if self._rx_eof:
                logging.getLogger(__name__).debug("Received %d bytes after EOF", len(data))
                raise self._report_local_error("Data received after EOF")
            if self._rx_state != RXState.ERROR:
                logging.getLogger(__name__).debug("Received %d bytes", len(data))
                self._rx_buffer.append(data)
                self._rx_buffer_length += len(data)
        else:
            logging.getLogger(__name__).debug("Received EOF")
            self._rx_eof = True
        self._parse_events()

    def next_event(self) -> Optional[Event]:
        """
        Return the next event in the event queue.

        This method should generally be called repeatedly until it returns None
        after a call to receive_data. However, it is legal to leave some events
        unprocessed until a more convenient time, or even call receive_data
        again before receiving all the events.

        This method raises RemoteProtocolError in the event of a remote
        protocol error, or LocalProtocolError in the event that the same
        exception was previously raised by some other method.
        """
        if self._rx_state is RXState.ERROR:
            assert self._error_class is not None  # Implied by RXState.ERROR
            raise self._error_class(self._error_msg)
        elif self._event_queue:
            return self._event_queue.popleft()
        else:
            return None

    def send(self, event: Event) -> Optional[bytes]:
        """
        Send an event to the peer and return the bytes to send, or None if the
        connection should now be closed.

        event -- the event to send

        This method raises LocalProtocolError if event is not acceptable right
        now.
        """
        logging.getLogger(__name__).debug("Sending %s", type(event))
        if self._tx_state is TXState.ERROR:
            assert self._error_class is not None  # Implied by TXState.ERROR
            raise self._error_class(self._error_msg)
        elif self._tx_state is TXState.HEADERS and isinstance(event, ResponseHeaders):
            self._tx_state = event.succeeding_state
            return event.encode()
        elif self._tx_state is TXState.BODY and isinstance(event, (ResponseBody, ResponseEnd)):
            if isinstance(event, ResponseBody):
                return event.data
            else:
                self._tx_state = TXState.DONE
                return None
        elif self._tx_state is TXState.NO_BODY and isinstance(event, ResponseEnd):
            self._tx_state = TXState.DONE
            return None
        else:
            raise self._report_local_error("Event {} prohibited in state {}".format(type(event), self._tx_state))

    def _parse_events(self) -> None:
        # Throughout this method, we assume that at most one element has been
        # added to the receive buffer; this is safe because this method is
        # called from receive_data, so we eagerly parse as much as we can on
        # every received chunk.
        logger = logging.getLogger(__name__)
        if self._rx_state is RXState.HEADER_LENGTH:
            logger.debug("In RX_HEADER_LENGTH")
            if self._rx_buffer:
                # The length-of-environment integer ends with a colon.
                index = self._rx_buffer[-1].find(B":")
                if index >= 0:
                    logger.debug("Found : at %d", index)
                    # We have the full length-of-environment integer and its
                    # terminating colon. Split up received data into the
                    # length-of-environment integer, the colon (which we
                    # discard), and any bytes following the colon (residue).
                    residue = self._rx_buffer[-1][index + 1:]
                    if index == 0:
                        self._rx_buffer.pop()
                    else:
                        self._rx_buffer[-1] = self._rx_buffer[-1][:index]
                    consumed = B"".join(self._rx_buffer)
                    self._rx_buffer.clear()
                    self._rx_buffer_length = 0
                    # Parse the length-of-environment integer.
                    try:
                        self._rx_env_length = int(consumed.decode("ASCII"))
                    except ValueError:
                        self._report_remote_error("Invalid length-of-environment")
                    else:
                        # Sanity check the length-of-environment integer.
                        if self._rx_env_length <= 0:
                            self._report_remote_error("Invalid length-of-environment")
                        elif self._rx_env_length > self._rx_buffer_limit:
                            self._report_remote_error("Headers too long (got {}, limit {})".format(self._rx_env_length, self._rx_buffer_limit))
                        else:
                            # Advance the state machine, keeping any residual
                            # bytes.
                            self._rx_state = RXState.HEADERS
                            if residue:
                                self._rx_buffer.append(residue)
                                self._rx_buffer_length += len(residue)
                            logger.debug("Length of headers is %d, residue is %d bytes", self._rx_env_length, len(residue))
        if self._rx_state is RXState.HEADERS:
            logger.debug("In RX_HEADERS")
            if self._rx_buffer_length > self._rx_env_length:
                # Split the receive buffer into the environment of the
                # designated length, the comma, and any bytes following the
                # comma (residue).
                logger.debug("Got all headers")
                last_chunk_start_pos = self._rx_buffer_length - len(self._rx_buffer[-1])
                assert last_chunk_start_pos <= self._rx_env_length
                comma_pos = self._rx_env_length - last_chunk_start_pos
                comma = self._rx_buffer[-1][comma_pos]
                residue = self._rx_buffer[-1][comma_pos + 1:]
                if last_chunk_start_pos == self._rx_env_length:
                    self._rx_buffer.pop()
                else:
                    self._rx_buffer[-1] = self._rx_buffer[-1][:comma_pos]
                environment = B"".join(self._rx_buffer)
                self._rx_buffer.clear()
                self._rx_buffer_length = 0
                # Check that the comma is a comma.
                if comma != 0x2C:
                    self._report_remote_error("Invalid end-of-environment character")
                # Check that the last byte of the environment block is a NUL
                elif environment[-1] != 0x00:
                    self._report_remote_error("Environment block not NUL-terminated")
                else:
                    # Split the environment block into NUL-terminated chunks.
                    split_environment = environment[:-1].split(B"\x00")
                    # Check that there are an even number of parts.
                    if len(split_environment) % 2 == 1:
                        self._report_remote_error("Environment block missing final value")
                    else:
                        # Build the dictionary.
                        env_dict: Dict[str, str] = {}
                        for i in range(0, len(split_environment), 2):
                            try:
                                key = split_environment[i].decode("ISO-8859-1")
                                value = split_environment[i + 1].decode("ISO-8859-1")
                            except UnicodeError:
                                self._report_remote_error("Environment variable is not ISO-8859-1")
                                break
                            if not key:
                                self._report_remote_error("Environment variable with empty name")
                                break
                            if key in env_dict:
                                self._report_remote_error("Duplicate environment variable {}".format(key))
                                break
                            env_dict[key] = value
                        if self._rx_state != RXState.ERROR:
                            # Check for mandatory environment variables.
                            if env_dict.get("SCGI", None) != "1":
                                self._report_remote_error("Mandatory variable SCGI not set to 1")
                            else:
                                # Advance the state machine, keeping any residual
                                # bytes.
                                self._rx_state = RXState.BODY
                                if residue:
                                    self._rx_buffer.append(residue)
                                    self._rx_buffer_length += len(residue)
                                try:
                                    self._rx_body_remaining = int(env_dict.get("CONTENT_LENGTH", ""))
                                    if self._rx_body_remaining < 0:
                                        raise ValueError()
                                    self._event_queue.append(RequestHeaders(env_dict))
                                    logger.debug("Retrieved %d headers, residue is %d bytes", len(env_dict), len(residue))
                                except ValueError:
                                    self._report_remote_error("CONTENT_LENGTH missing or not a whole number")
        if self._rx_state is RXState.BODY:
            logger.debug("In RX_BODY, buffer length = %d, body remaining = %d", self._rx_buffer_length, self._rx_body_remaining)
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
                self._report_remote_error("Request body longer than CONTENT_LENGTH")
        if self._rx_state is RXState.DONE:
            logger.debug("In %s", self._rx_state)
            if self._rx_buffer_length:
                self._report_remote_error("Request body longer than CONTENT_LENGTH")
        if self._rx_buffer_length > self._rx_buffer_limit:
            self._report_remote_error("Too many bytes buffered")
        elif self._rx_eof and self._rx_state in {RXState.HEADER_LENGTH, RXState.HEADERS, RXState.BODY}:
            self._report_remote_error("Premature EOF")

    def _report_local_error(self, msg: str) -> LocalProtocolError:
        self._report_error(LocalProtocolError, msg)
        return LocalProtocolError(msg)

    def _report_remote_error(self, msg: str) -> None:
        self._report_error(RemoteProtocolError, msg)

    def _report_error(self, error_class: Type[ProtocolError], msg: str) -> None:
        self._rx_state = RXState.ERROR
        self._tx_state = TXState.ERROR
        self._error_class = error_class
        self._error_msg = msg
