cmake_minimum_required(VERSION 3.12.4)

# Single shared library aggregating the entire cwfr framework. Both the cwfr
# executable and dynamically-loaded handler (.so) modules link it, so the
# framework exists as ONE instance (shared state: db pools, appconfig, i18n)
# and handler modules stay small -- they resolve framework symbols from here
# at runtime instead of baking the framework into every .so.

add_library(cwfr_framework SHARED cwfr_framework.c)

# Framework archives aggregated in full (every object member), including
# database with its conditionally-enabled DB drivers.
set(FW_LIBS
	model database http misc protocols view storage session config connection
	broadcast domain metrics mimetype moduleloader multiplexing openssl ratelimiter
	redirect route server signal socket thread taskmanager middleware translation
	http_client http_client_parsers http_server http_server_filters http_server_parsers
	smtp smtp_client smtp_client_parsers websocket websocket_server websocket_server_parsers
	hpack h2frame h2server)

# QUIC / HTTP/3 archives. They exist only in an h3 build -- protocols/quic and
# protocols/http3 return early otherwise -- so naming them unconditionally would
# break every build that leaves INCLUDE_HTTP3 at its default (core/CMakeLists.txt).
if(INCLUDE_HTTP3 STREQUAL yes)
	list(APPEND FW_LIBS quic_common quic_crypto quic_transport h3frame h3server qpack udp)
endif()

# The HTTP/0.9 interop shim, when it is built at all (core/CMakeLists.txt).
if(INCLUDE_HQ_INTEROP STREQUAL yes)
	list(APPEND FW_LIBS hq)
endif()

# The embedding application may inject its own static archives (models,
# middlewares implementing the middlewares_init() hook, contexts, ...) by
# setting CWFR_EXTRA_FW_LIBS before add_subdirectory(core). They are aggregated
# whole-archive alongside the framework so handler .so modules resolve their
# symbols from this single shared instance at runtime. The core itself knows
# nothing about these targets.
list(APPEND FW_LIBS ${CWFR_EXTRA_FW_LIBS})

target_link_libraries(cwfr_framework PRIVATE
	"-Wl,--whole-archive" ${FW_LIBS} "-Wl,--no-whole-archive"
	${PCRE2_LIBRARIES} ZLIB::ZLIB OpenSSL::SSL OpenSSL::Crypto
	${LIBXML2_LIBRARIES} ${IDN2_LIBRARIES} ${UNISTRING_LIBRARIES}
	Threads::Threads ${CMAKE_DL_LIBS})

# Expose the framework include directories to consumers (cwfr, handlers, service
# libs) via the interface -- WITHOUT making the static archives a link
# requirement (the code already lives in this .so). This is what decouples
# include propagation from link propagation.
#
# BUILD_INTERFACE only: these are source-tree paths that mean nothing to an
# installed package. The installed tree gets every one of these headers flattened
# into a single <prefix>/include/cwfr, added below -- which is why the flat
# directory has to stay collision-free (cmake/install.cmake enforces that).
foreach(_l ${FW_LIBS})
	target_include_directories(cwfr_framework INTERFACE
		$<BUILD_INTERFACE:$<TARGET_PROPERTY:${_l},INTERFACE_INCLUDE_DIRECTORIES>>)
endforeach()

target_include_directories(cwfr_framework INTERFACE
	$<INSTALL_INTERFACE:include/cwfr>)

# Consumers spell it cwfr::framework whether they came through add_subdirectory()
# or find_package(cwfr) -- the alias is what makes one cwfr_add_handlers() call
# work in this repository and in a standalone application project alike.
set_target_properties(cwfr_framework PROPERTIES EXPORT_NAME framework)
add_library(cwfr::framework ALIAS cwfr_framework)

# An application built against one framework release must not silently load the
# next one: handler .so files record the SONAME, so bumping it is what turns an
# incompatible framework into a load-time error instead of a crash.
set_target_properties(cwfr_framework PROPERTIES
	VERSION ${CWFR_VERSION}
	SOVERSION ${CWFR_VERSION_MAJOR})

# cwfr/migrate carry the INSTALL_RPATH that locates this .so; the framework .so
# itself needs no RPATH.
