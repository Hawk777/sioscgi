Changes in 4.0.0
================

CI configuration was updated. Very minor code cleanup was performed. This
version requires Python 3.9 or higher due to updating to newer type hints.

Changes in 3.0.1
================

CI configuration, lint configuration, and build system configuration were
updated. Very minor code cleanup was performed.

Changes in 3.0.0
================

The ``environment`` member of the ``RequestHeaders`` event now maps from
``str`` to ``bytes`` rather than from ``str`` to ``str``. This is because HTTP
header values do not have any standards-defined character encoding; therefore,
it must be left up to each application to decode each header as it sees
fit, if it intends to use the header value as textual data.

Changes in 2.1.0
================

A ``py.typed`` file is now installed, allowing Mypy to type check consumers of
sioscgi.

Changes in 2.0.0
================

The transmit and receive state machines have been split to allow interleaving
of request and response bodies. While such interleaving is not strictly
permitted by the SCGI specification, it is permitted by the CGI specification
and is supported by some SCGI clients. The ``state`` property in
``SCGIConnection`` and the ``State`` enumeration no longer exist, having been
replaced with the ``rx_state`` and ``tx_state`` properties and the ``RXState``
and ``TXState`` enumerations. Applications referring to these must be updated
to refer to the state machine about which they care; applications not referring
to these will continue to work without modification.
