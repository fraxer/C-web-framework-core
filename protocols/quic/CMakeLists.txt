cmake_minimum_required(VERSION 3.12.4)

# QUIC transport (RFC 8999/9000/9001/9002) -- docs/http3/.
#
# The gate lives here rather than in the parent: protocols/CMakeLists.txt calls
# cwfr_add_subdirs(), which recurses into every subdirectory unconditionally, so
# a directory that must not build has to refuse from the inside.
if(NOT INCLUDE_HTTP3 STREQUAL yes)
	return()
endif()

cwfr_add_subdirs()
