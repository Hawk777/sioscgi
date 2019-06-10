What is sioscgi?
================

sioscgi is an implementation of the Simple Common Gateway Interface (SCGI)
protocol under the Sans-I/O philosophy.


What is SCGI?
=============

SCGI is a protocol used for communication between HTTP servers and Web
applications. Compared to CGI, SCGI is more efficient because it does not fork
and execute a separate instance of the application for every request; instead,
the application is launched ahead of time and receives multiple requests
(either sequentially or concurrently) via socket connections. Compared to
FastCGI, SCGI is a much simpler protocol as it uses a separate socket
connection for each request, rather than including framing within a single
connection to multiplex requests (a feature which is rarely used in FastCGI
anyway due to the lack of per-request flow control).

See the Wikipedia_ and Python_ SCGI pages for more information.


What is Sans-I/O?
=================

Sans-I/O is a philosophy for developing protocol processing libraries in which
the library does not do any I/O. Instead, a user of the library is responsible
for transferring blocks of bytes between the socket or pipe and the protocol
library, and for receiving application-level protocol items from and sending
them to the library. This obviously makes a sans-I/O library a little more
difficult to use, but comes with the advantage that the same library can be
used with any I/O and concurrency mechanism: the same library should be usable
in a single-request-at-a-time server, a process-per-request or
thread-per-request blocking server, a server using select/poll and
continuations, or a server using asyncio, Twisted, or any other asynchronous
framework.

See SansIO_ for more information.


How do I install it?
====================

sioscgi’s releases are published on PyPI for installation through pip. You can
run ``pip install sioscgi``.

For development, the source is available at GitLab_ and GitHub_.


How do I use it?
================

In general terms, as follows:

1. Accept an SCGI connection from the HTTP server (or other SCGI client).
2. Construct an ``SCGIConnection`` object.
3. Receive the request from the SCGI client by repeating the following until a
   ``RequestEnd`` event occurs:

   a) Read some bytes from the connection and pass them to
      ``SCGIConnection.receive_data``.
   b) Call ``SCGIConnection.next_event`` to receive high-level events
      corresponding to the received data (one ``RequestHeaders``, zero or more
      ``RequestBody`` events, and one ``RequestEnd``).

4. Send the response to the SCGI client using ``SCGIConnection.send``, sending
   first a ``ResponseHeaders`` event, then zero or more ``ResponseBody`` events,
   then a ``ResponseEnd`` event, and sending the returned bytes over the
   connection.

This being a sans-I/O library, how exactly you implement each step will depend
on what I/O and application framework you’re working under. For example, for a
thread-per-request or process-per-request server, you would likely do a
blocking receive from a normal function in step 3.1; in an asyncio-based server
you would instead ``await`` new data from a coroutine.

For detailed information about the classes and methods available, see the
module documentation provided in the docstrings by running ``import sioscgi``
followed by ``help(sioscgi)``.


.. _Wikipedia: https://en.wikipedia.org/wiki/Simple_Common_Gateway_Interface
.. _Python: http://www.python.ca/scgi/
.. _SansIO: https://sans-io.readthedocs.io/
.. _GitLab: https://gitlab.com/Hawk777/sioscgi
.. _GitHub: https://github.com/Hawk777/sioscgi
