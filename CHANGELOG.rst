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
