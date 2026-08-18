cmake_minimum_required(VERSION 3.12.4)

# Wire format and cross-cutting definitions of QUIC v1: varints, packet headers,
# frames, connection ids, transport parameters (docs/http3/02-quic-core.md),
# plus the monotonic clock and the qlog facility every other QUIC module emits
# through.
#
# No connection state, so the module stays unit-testable in isolation -- the
# same contract h2frame and hpack hold for HTTP/2. `misc` is the one dependency
# beyond libc and pthreads (the CID routing table shards a mutex): qlog writes
# through log.h when a trace cannot be opened, and a diagnostics facility that
# fails silently is worse than none.
cwfr_add_lib(quic_common LINK_LIBS misc)
