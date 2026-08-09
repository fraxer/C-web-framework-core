cmake_minimum_required(VERSION 3.12.4)

# QUIC transport: streams, flow control, acknowledgement, loss recovery and
# congestion control (RFC 9000 §2-13, RFC 9002) -- docs/http3/04-quic-transport.md.
#
# Every module here takes its time from quic_now_us (quic_common), never from
# clock_gettime directly, so loss detection and pacing can be driven by an
# injected clock under test.
# metrics: loss detection, the stream table and the send loop each report a
# counter now (docs/http3/07-integration.md §3). Named explicitly rather than
# relied on transitively -- the header was reachable by accident before.
cwfr_add_lib(quic_transport LINK_LIBS quic_common quic_crypto misc metrics)
