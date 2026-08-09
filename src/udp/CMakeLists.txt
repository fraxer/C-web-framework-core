cmake_minimum_required(VERSION 3.12.4)

# UDP socket and the QUIC endpoint that demultiplexes datagrams onto
# connections (docs/http3/01-udp-endpoint.md).
#
# Gated from the inside: src/CMakeLists.txt calls cwfr_add_subdirs(), which
# recurses unconditionally, so a directory that must not build has to refuse.
if(NOT INCLUDE_HTTP3 STREQUAL yes)
	return()
endif()

# connection brings the multiplexing headers with it (connection_s.h includes
# multiplexingserver.h), so udp does not name multiplexing itself -- that would
# declare a cycle, since multiplexingserver.c calls into this library.
cwfr_add_lib(udp LINK_LIBS misc quic_common quic_crypto quic_transport connection server config openssl metrics)

# The interop shim is a second application protocol on the same streams, chosen
# by ALPN; the endpoint's turn branches into it (docs/http3/08 §3e).
if(INCLUDE_HQ_INTEROP STREQUAL yes)
	target_link_libraries(udp hq)
endif()
