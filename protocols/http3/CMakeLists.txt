cmake_minimum_required(VERSION 3.12.4)

# HTTP/3 (RFC 9114) and QPACK (RFC 9204) -- docs/http3/05-http3.md, 06-qpack.md.
# Gated from the inside for the same reason as protocols/quic/CMakeLists.txt.
if(NOT INCLUDE_HTTP3 STREQUAL yes)
	return()
endif()

cwfr_add_subdirs()
