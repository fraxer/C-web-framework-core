cmake_minimum_required(VERSION 3.12.4)

# HTTP/0.9 over QUIC for the interop runner (docs/http3/08 §3e). Gated from the
# inside, like protocols/quic and protocols/http3: the parent globs its
# subdirectories, so a directory that must not build has to say so itself.
if(NOT INCLUDE_HQ_INTEROP STREQUAL yes)
	return()
endif()

cwfr_add_lib(hq LINK_LIBS quic_common quic_transport config)
