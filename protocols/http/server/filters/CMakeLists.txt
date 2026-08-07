cmake_minimum_required(VERSION 3.12.4)

# filters_create_h3 names the h3 terminal stage, so this target needs to see its
# header -- but only the header. Linking h3server here would close a cycle
# (h3server -> http -> http_server_filters); the symbol is resolved when
# libcwfr_framework.so is linked, which aggregates both archives anyway. The h2
# stage needs no such line because protocols/http2/server is already on the
# include path this target inherits.
set(FILTER_INCLUDE_DIRS ".")
if(INCLUDE_HTTP3 STREQUAL yes)
	list(APPEND FILTER_INCLUDE_DIRS
		"${CMAKE_CURRENT_SOURCE_DIR}/../../../http3/server"
		"${CMAKE_CURRENT_SOURCE_DIR}/../../../http3/frame"
		"${CMAKE_CURRENT_SOURCE_DIR}/../../../http3/qpack")
endif()

cwfr_add_lib(http_server_filters INCLUDE_DIRS ${FILTER_INCLUDE_DIRS} LINK_LIBS misc)
