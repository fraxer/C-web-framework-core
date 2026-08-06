cmake_minimum_required(VERSION 3.12.4)

# Wire format and cross-cutting definitions of QUIC v1: varints, packet headers,
# frames, connection ids, transport parameters (docs/http3/02-quic-core.md),
# plus the monotonic clock and the qlog facility every other QUIC module emits
# through.
#
# Pure codecs with no connection state and no dependency beyond libc, so the
# module stays unit-testable in isolation -- the same contract h2frame and hpack
# hold for HTTP/2.
cwfr_add_lib(quic_common)
