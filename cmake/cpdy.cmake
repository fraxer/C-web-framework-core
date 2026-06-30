# Shared CMake helpers for the cpdy framework (backend/core).
#
# These functions are global once this file is include()'d from the core root
# (CMake function scope is not limited to the defining directory, unlike variables).
# They collapse two patterns that were duplicated across every subdirectory:
#   * the SUBDIRLIST macro + foreach(add_subdirectory) boilerplate, and
#   * the FILE(GLOB) -> add_library(STATIC) -> target_include_directories
#     -> target_link_libraries skeleton.

# Recurse into every subdirectory of CMAKE_CURRENT_SOURCE_DIR that contains a
# CMakeLists.txt. Replaces the verbatim MACRO(SUBDIRLIST) block.
function(cpdy_add_subdirs)
	file(GLOB _children RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/*)
	set(_dirlist "")
	foreach(_child ${_children})
		if(IS_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${_child})
			list(APPEND _dirlist ${_child})
		endif()
	endforeach()
	foreach(_dir ${_dirlist})
		add_subdirectory(${_dir})
	endforeach()
endfunction()

# Build a STATIC library from *.c/*.h in the current directory.
#
#   cpdy_add_lib(<name>
#       [FORCE_C]                       # header-only target (no .c): force C linker language
#       [INCLUDE_DIRS <dir>...]         # default is "."; pass the full list to override/extend
#       [LINK_LIBS <lib>...])           # dependencies forwarded to target_link_libraries
function(cpdy_add_lib NAME)
	cmake_parse_arguments(ARG "FORCE_C" "" "INCLUDE_DIRS;LINK_LIBS" ${ARGN})

	file(GLOB SOURCES *.c *.h)
	add_library(${NAME} STATIC ${SOURCES})

	if(ARG_FORCE_C)
		set_target_properties(${NAME} PROPERTIES LINKER_LANGUAGE C)
	endif()

	if(NOT ARG_INCLUDE_DIRS)
		set(ARG_INCLUDE_DIRS ".")
	endif()
	target_include_directories(${NAME} PUBLIC ${ARG_INCLUDE_DIRS})

	if(ARG_LINK_LIBS)
		target_link_libraries(${NAME} ${ARG_LINK_LIBS})
	endif()
endfunction()
