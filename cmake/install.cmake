# Installed layout and the exported CMake package.
#
# The point of this file is that an application does not need the framework's
# sources: everything a handler .so has to compile and link against is installed
# here, and `find_package(cwfr)` hands it over as the imported target
# cwfr::framework plus the cwfr_add_handlers() / cwfr_add_migrations() helpers.
#
#   <prefix>/bin/cwfr, bin/migrate
#   <prefix>/include/cwfr/*.h              -- flat, see below
#   <prefix>/lib/cwfr/libcwfr_framework.so
#   <prefix>/lib/cmake/cwfr/*.cmake        -- the package

include(GNUInstallDirs)

# --- headers ---------------------------------------------------------------
#
# Flattened into one directory on purpose. The framework's own sources include
# each other by bare name ("httprequest.h", not "protocols/http/httprequest.h")
# and rely on ~50 include directories to resolve them; reproducing that for a
# consumer would mean exporting the core's internal layout and pinning it
# forever. One directory, one -I, and the include lines keep working verbatim.
#
# It only holds together while the basenames stay unique across the tree, so
# that is checked here rather than discovered as a silently wrong header later.
file(GLOB_RECURSE CWFR_PUBLIC_HEADERS
	${CMAKE_CURRENT_SOURCE_DIR}/src/*.h
	${CMAKE_CURRENT_SOURCE_DIR}/framework/*.h
	${CMAKE_CURRENT_SOURCE_DIR}/protocols/*.h
	${CMAKE_CURRENT_SOURCE_DIR}/misc/*.h)

# Internals: included by the unit tests, never by an application.
list(FILTER CWFR_PUBLIC_HEADERS EXCLUDE REGEX "_internal\\.h$")

set(_seen "")
foreach(_h ${CWFR_PUBLIC_HEADERS})
	get_filename_component(_name ${_h} NAME)
	if(_name IN_LIST _seen)
		message(FATAL_ERROR
			"cwfr install: duplicate public header name '${_name}' (${_h}). "
			"The installed include/cwfr directory is flat, so header basenames "
			"must be unique across the core -- rename one of them.")
	endif()
	list(APPEND _seen ${_name})
endforeach()

install(FILES ${CWFR_PUBLIC_HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cwfr)

# --- binaries and the framework library ------------------------------------

install(TARGETS cwfr migrate RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

install(TARGETS cwfr_framework
	EXPORT cwfrTargets
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/cwfr
	INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cwfr)

# --- the CMake package -----------------------------------------------------

set(CWFR_CMAKE_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/cwfr)

install(EXPORT cwfrTargets
	FILE cwfrTargets.cmake
	NAMESPACE cwfr::
	DESTINATION ${CWFR_CMAKE_DIR})

# The build helpers travel with the package: cwfr_add_handlers() and
# cwfr_add_migrations() are how an application declares its modules, and
# cwfr_add_lib() is how it declares its own static archives.
install(FILES
	${CMAKE_CURRENT_SOURCE_DIR}/cmake/cwfr.cmake
	${CMAKE_CURRENT_SOURCE_DIR}/cmake/app.cmake
	DESTINATION ${CWFR_CMAKE_DIR})

# --- what a consumer needs to compile against these headers -----------------
#
# The public headers are not self-contained: route.h/domain.h/redirect.h include
# <pcre2.h>, session/openssl headers include <openssl/*.h>, and dbresult.h pulls
# in whichever database client headers were enabled at build time. So the package
# has to hand a consumer the same include paths and the same feature macros the
# framework itself was built with.
#
# The macros are not cosmetic: PostgreSQL_FOUND and friends gate struct members
# in the database headers. A handler compiled without them would disagree with
# libcwfr_framework.so about the layout of the very structs it passes across the
# boundary -- an ABI mismatch that no linker would catch.
set(CWFR_WITH_MYSQL      no)
set(CWFR_WITH_POSTGRESQL no)
set(CWFR_WITH_REDIS      no)
set(CWFR_WITH_SQLITE     no)

if(MySQL_FOUND AND INCLUDE_MYSQL STREQUAL yes)
	set(CWFR_WITH_MYSQL yes)
endif()
if(PostgreSQL_FOUND AND INCLUDE_POSTGRESQL STREQUAL yes)
	set(CWFR_WITH_POSTGRESQL yes)
endif()
if(Redis_FOUND AND INCLUDE_REDIS STREQUAL yes)
	set(CWFR_WITH_REDIS yes)
endif()
if(SQLite_FOUND AND INCLUDE_SQLITE STREQUAL yes)
	set(CWFR_WITH_SQLITE yes)
endif()

set(CWFR_WITH_HTTP3 ${INCLUDE_HTTP3})

# The Find modules travel with the package: cwfrConfig.cmake re-runs them to
# locate the same third-party headers on the consumer's machine, rather than
# baking this machine's absolute paths into an installed file.
install(FILES
	${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindPCRE2.cmake
	${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindMySQL.cmake
	${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindPostgreSQL.cmake
	${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindRedis.cmake
	${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindSQLite.cmake
	DESTINATION ${CWFR_CMAKE_DIR})

include(CMakePackageConfigHelpers)

configure_package_config_file(
	${CMAKE_CURRENT_SOURCE_DIR}/cmake/cwfrConfig.cmake.in
	${CMAKE_CURRENT_BINARY_DIR}/cwfrConfig.cmake
	INSTALL_DESTINATION ${CWFR_CMAKE_DIR})

write_basic_package_version_file(
	${CMAKE_CURRENT_BINARY_DIR}/cwfrConfigVersion.cmake
	VERSION ${CWFR_VERSION}
	COMPATIBILITY SameMajorVersion)

install(FILES
	${CMAKE_CURRENT_BINARY_DIR}/cwfrConfig.cmake
	${CMAKE_CURRENT_BINARY_DIR}/cwfrConfigVersion.cmake
	DESTINATION ${CWFR_CMAKE_DIR})
