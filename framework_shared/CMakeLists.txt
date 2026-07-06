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
	broadcast domain mimetype moduleloader multiplexing openssl ratelimiter
	redirect route server signal socket thread taskmanager middleware translation
	http_client http_client_parsers http_server http_server_filters http_server_parsers
	smtp smtp_client smtp_client_parsers websocket websocket_server websocket_server_parsers)

# The embedding application may inject its own static archives (models,
# middlewares implementing the middlewares_init() hook, contexts, ...) by
# setting CWFR_EXTRA_FW_LIBS before add_subdirectory(core). They are aggregated
# whole-archive alongside the framework so handler .so modules resolve their
# symbols from this single shared instance at runtime. The core itself knows
# nothing about these targets.
list(APPEND FW_LIBS ${CWFR_EXTRA_FW_LIBS})

target_link_libraries(cwfr_framework PRIVATE
	"-Wl,--whole-archive" ${FW_LIBS} "-Wl,--no-whole-archive"
	-l:libpcre.so.3 ZLIB::ZLIB OpenSSL::SSL OpenSSL::Crypto
	${LIBXML2_LIBRARIES} ${IDN2_LIBRARIES} ${UNISTRING_LIBRARIES}
	argon2 Threads::Threads ${CMAKE_DL_LIBS})

# Expose the framework include directories to consumers (cwfr, handlers, service
# libs) via the interface -- WITHOUT making the static archives a link
# requirement (the code already lives in this .so). This is what decouples
# include propagation from link propagation.
foreach(_l ${FW_LIBS})
	target_include_directories(cwfr_framework INTERFACE
		$<TARGET_PROPERTY:${_l},INTERFACE_INCLUDE_DIRECTORIES>)
endforeach()

# cwfr/migrate carry the INSTALL_RPATH that locates this .so; the framework .so
# itself needs no RPATH.
