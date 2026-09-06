# Application-layer CMake helpers: handler and migration modules.
#
# Shipped with the installed package (lib/cmake/cwfr/), so an application built
# against an installed framework declares its modules exactly the way the
# in-tree example application does:
#
#   find_package(cwfr REQUIRED)
#   cwfr_add_handlers(LINK_LIBS cwfr::framework app)
#   cwfr_install_handlers()
#
# One SHARED handler (.so) per *.c file under routes/, and one per *.c file in
# each migrations/<server>/ subdirectory. There is no per-module namespace and no
# gettext locale handling here: handler and migration targets keep their
# historical names and output paths, so config.json references them as
# handlers/<sub>/lib_<name>.so and migrations/<server>/lib<name>.so verbatim.

# Configurable output directories for handler/migration .so modules. Override at
# configure time (-DCWFR_HANDLER_OUT_DIR=..., -DCWFR_MIGRATION_OUT_DIR=...) to
# emit them outside the build tree (e.g. into $HOME) so they can be rebuilt
# independently of an installed binary prefix. Default to the build tree to
# preserve the historical layout.
set(CWFR_HANDLER_OUT_DIR   "${CMAKE_BINARY_DIR}/exec/handlers"
	CACHE PATH "Where handler .so modules are written (module/sub-path appended)")
set(CWFR_MIGRATION_OUT_DIR "${CMAKE_BINARY_DIR}/exec/migrations"
	CACHE PATH "Where migration .so modules are written (sub-dir appended)")

# Configurable INSTALL destinations for those same modules. Override at configure
# time (-DCWFR_HANDLER_INSTALL_DIR=..., -DCWFR_MIGRATION_INSTALL_DIR=...) to send
# handlers/migrations to a different root than the binaries at `cmake --install`
# time. A relative path is resolved under CMAKE_INSTALL_PREFIX (the default); an
# ABSOLUTE path is used verbatim and ignores --prefix -- handy for keeping
# frequently-rebuilt modules in $HOME separate from a stable binary install.
set(CWFR_HANDLER_INSTALL_DIR   "lib/cwfr/handlers"
	CACHE PATH "Install destination for handler .so modules (relative => under prefix; absolute => verbatim)")
set(CWFR_MIGRATION_INSTALL_DIR "lib/cwfr/migrations"
	CACHE PATH "Install destination for migration .so modules (relative => under prefix; absolute => verbatim)")

# RPATH recorded in handler/migration modules.
#
# Mostly belt and braces: cwfr and migrate already have libcwfr_framework.so
# loaded, and cwfr loads the application module from `main.modules`, before any
# handler is dlopen'd -- so the loader satisfies a handler's DT_NEEDED entries
# from the link map by SONAME without touching the filesystem. The RPATH is what
# keeps a module loadable on its own (ldd, a test harness, dlopen from a tool),
# and it walks up out of handlers/<sub>/ to the lib/cwfr/ that holds the .so
# files. Override it when the modules are installed somewhere else entirely.
set(CWFR_MODULE_RPATH "$ORIGIN:$ORIGIN/..:$ORIGIN/../..:$ORIGIN/../../.."
	CACHE STRING "RPATH recorded in handler and migration .so modules")

# Build one SHARED handler (.so) per *.c file under the current directory, named
# _<file> and written to <CWFR_HANDLER_OUT_DIR>/<relative-path>/lib_<file>.so.
#
# Handlers stay small: the framework (and whatever application library is passed
# in LINK_LIBS) is a shared library, resolved at runtime from the single instance
# the server has already loaded.
function(cwfr_add_handlers)
	cmake_parse_arguments(ARG "" "" "INCLUDE_DIRS;LINK_LIBS" ${ARGN})

	file(GLOB_RECURSE _filepaths *.c)

	foreach(_filepath ${_filepaths})
		get_filename_component(_filedir ${_filepath} DIRECTORY)
		get_filename_component(_filename ${_filepath} NAME_WE)
		file(RELATIVE_PATH _rel ${CMAKE_CURRENT_SOURCE_DIR} ${_filedir})

		set(_target _${_filename})
		set(_out_dir "${CWFR_HANDLER_OUT_DIR}/${_rel}")

		add_library(${_target} SHARED ${_filepath})
		set_target_properties(${_target} PROPERTIES
			LIBRARY_OUTPUT_DIRECTORY ${_out_dir}
			INSTALL_RPATH "${CWFR_MODULE_RPATH}")

		if(ARG_INCLUDE_DIRS)
			target_include_directories(${_target} PRIVATE ${ARG_INCLUDE_DIRS})
		endif()
		target_link_libraries(${_target} ${ARG_LINK_LIBS})
	endforeach()
endfunction()

# Build one SHARED migration (.so) per *.c file in each subdirectory of the
# current directory (s1/, s2/, ...). Targets are <file>, output to
# <CWFR_MIGRATION_OUT_DIR>/<subdir>/.
function(cwfr_add_migrations)
	cmake_parse_arguments(ARG "" "" "INCLUDE_DIRS;LINK_LIBS" ${ARGN})

	if(NOT ARG_LINK_LIBS)
		set(ARG_LINK_LIBS cwfr::framework)
	endif()

	file(GLOB _children RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/*)
	foreach(_subdir ${_children})
		if(IS_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${_subdir})
			file(GLOB _filepaths "${_subdir}/*.c")
			set(_out_dir "${CWFR_MIGRATION_OUT_DIR}/${_subdir}")

			foreach(_filepath ${_filepaths})
				get_filename_component(_filename ${_filepath} NAME_WE)

				add_library(${_filename} SHARED ${_filepath})
				set_target_properties(${_filename} PROPERTIES
					LIBRARY_OUTPUT_DIRECTORY ${_out_dir}
					INSTALL_RPATH "${CWFR_MODULE_RPATH}")

				if(ARG_INCLUDE_DIRS)
					target_include_directories(${_filename} PRIVATE ${ARG_INCLUDE_DIRS})
				endif()
				target_link_libraries(${_filename} ${ARG_LINK_LIBS})
			endforeach()
		endif()
	endforeach()
endfunction()

# install() rules for the trees the two functions above produce. The trailing
# slash installs the *contents* of the out-dir, so the handlers/<sub>/ layout that
# config.json names is preserved verbatim while an absolute
# -DCWFR_HANDLER_INSTALL_DIR=... redirects the tree independently of --prefix.
function(cwfr_install_handlers)
	install(DIRECTORY ${CWFR_HANDLER_OUT_DIR}/
		DESTINATION ${CWFR_HANDLER_INSTALL_DIR}
		USE_SOURCE_PERMISSIONS
		FILES_MATCHING PATTERN "*.so")
endfunction()

function(cwfr_install_migrations)
	install(DIRECTORY ${CWFR_MIGRATION_OUT_DIR}/
		DESTINATION ${CWFR_MIGRATION_INSTALL_DIR}
		USE_SOURCE_PERMISSIONS)
endfunction()
