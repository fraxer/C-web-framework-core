cmake_minimum_required(VERSION 3.12.4)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/cwfr.cmake)

# QUIC / HTTP/3 is opt-in.
#
# It needs the OpenSSL QUIC TLS API (SSL_set_quic_tls_cbs), which lets a
# third-party QUIC stack drive the TLS 1.3 handshake and collect the per-level
# secrets. That API landed in OpenSSL 3.5. The rest of the framework still
# builds against 1.1.1+, so the requirement must not be imposed on builds that
# do not want h3 -- hence a flag rather than a bare find_package version bump.
# See docs/http3/00-overview.md §2.3.
set(INCLUDE_HTTP3 "no" CACHE STRING "Build QUIC/HTTP/3 support: yes|no")
set_property(CACHE INCLUDE_HTTP3 PROPERTY STRINGS yes no)

if(INCLUDE_HTTP3 STREQUAL yes)
	if(OPENSSL_VERSION VERSION_LESS 3.5.0)
		message(FATAL_ERROR
			"INCLUDE_HTTP3=yes needs OpenSSL >= 3.5 for the QUIC TLS API "
			"(SSL_set_quic_tls_cbs); found ${OPENSSL_VERSION}. "
			"Upgrade OpenSSL, or configure with -DINCLUDE_HTTP3=no.")
	endif()

	# Version alone is not proof: a distribution may configure OpenSSL with
	# `no-quic`, which keeps the version and drops the API. Catch that at
	# configure time instead of at link time.
	include(CheckCSourceCompiles)
	set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
	set(CMAKE_REQUIRED_LIBRARIES OpenSSL::SSL)
	# check_symbol_exists generates a fragile "((int*)(&SYM))[i]" probe that GCC
	# rejects on some prototypes ("arrays of functions are not meaningful",
	# observed with OpenSSL 3.6.3's SSL_set_quic_tls_cbs). Probe the real way:
	# include the header and call the function -- needs both the declaration and
	# the symbol in libssl at link time.
	check_c_source_compiles("
#include <openssl/ssl.h>
int main(void) {
    (void)SSL_set_quic_tls_cbs(0, 0, 0);
    return 0;
}
" CWFR_HAVE_QUIC_TLS_CBS)
	unset(CMAKE_REQUIRED_INCLUDES)
	unset(CMAKE_REQUIRED_LIBRARIES)

	if(NOT CWFR_HAVE_QUIC_TLS_CBS)
		message(FATAL_ERROR
			"INCLUDE_HTTP3=yes: OpenSSL ${OPENSSL_VERSION} does not expose "
			"SSL_set_quic_tls_cbs (built with `no-quic`?). "
			"Configure with -DINCLUDE_HTTP3=no.")
	endif()

	# Directory-scoped, so it reaches every core target (including tests and
	# framework_shared) and nothing in the application layer.
	add_compile_definitions(CWFR_HTTP3)
	message(STATUS "HTTP/3 enabled (OpenSSL ${OPENSSL_VERSION})")
endif()

# HTTP/0.9 over QUIC, for the interop runner and for nothing else.
#
# Almost every quic-interop-runner test case moves its files with HTTP/0.9 under
# ALPN `hq-interop` rather than with HTTP/3 -- so without this, one case of the
# matrix is reachable and the transport half of it (loss, corruption, Retry,
# resumption, rebinding) is not. Every implementation in the matrix carries the
# same shim.
#
# A build flag rather than a configuration key, deliberately: HTTP/0.9 has no
# headers, no host, no length and no status. It must not be one careless setting
# away from being served by a production binary (docs/http3/08 §3e).
set(INCLUDE_HQ_INTEROP "no" CACHE STRING "Build the HTTP/0.9 interop shim: yes|no")
set_property(CACHE INCLUDE_HQ_INTEROP PROPERTY STRINGS yes no)

if(INCLUDE_HQ_INTEROP STREQUAL yes)
	if(NOT INCLUDE_HTTP3 STREQUAL yes)
		message(FATAL_ERROR
			"INCLUDE_HQ_INTEROP=yes needs INCLUDE_HTTP3=yes: the shim rides on "
			"QUIC streams and has nothing to run on otherwise.")
	endif()

	add_compile_definitions(CWFR_HQ_INTEROP)
	message(STATUS "HTTP/0.9 interop shim enabled -- NOT for production builds")
endif()

add_subdirectory(framework)
add_subdirectory(misc)
add_subdirectory(protocols)
add_subdirectory(src)
# cwfr_framework aggregates the framework static archives above, so it must be
# defined after them. apps (cwfr/migrate) link it, so they come last.
add_subdirectory(framework_shared)

# Enable tests if building with tests enabled
if(BUILD_TESTS STREQUAL yes)
    message(STATUS "Core tests found")
    add_subdirectory(tests)
endif()

add_subdirectory(apps)
