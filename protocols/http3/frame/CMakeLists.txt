cmake_minimum_required(VERSION 3.12.4)

# HTTP/3 frame layer (RFC 9114 §7) and the HTTP/3 + QPACK error codes every
# other h3 module reports through (docs/http3/05-http3.md). Like h2frame, it
# carries no connection state and depends only on the C standard library.
cwfr_add_lib(h3frame LINK_LIBS quic_common httppriority)
