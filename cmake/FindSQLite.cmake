#-- Try to find SQLite headers and library.
#
# Usage of this module as follows:
#
#     find_package(SQLite)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  SQLite_ROOT_DIR          Set this variable to the root installation of
#                            SQLite if the module has problems finding the
#                            proper installation path.
#
# Variables defined by this module:
#
#  SQLite_FOUND               System has SQLite library/headers.
#  SQLite_LIBRARY             The SQLite library.
#  SQLite_INCLUDE_DIRS        The location of SQLite headers.

find_path(SQLite_DIR
    HINTS
    /usr
    /usr/local
)

find_path(SQLite_INCLUDE_DIR sqlite3.h
    HINTS
    /usr
    /usr/local
    ${SQLite_DIR}
    PATH_SUFFIXES include
)

find_library(SQLite_LIBRARY sqlite3
    HINTS
    /usr
    /usr/lib/
    ${SQLite_DIR}
    PATH SUFFIXES lib
)

set(SQLite_INCLUDE_DIRS ${SQLite_INCLUDE_DIR})
set(SQLite_LIBRARIES ${SQLite_LIBRARY})


include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SQLite DEFAULT_MSG SQLite_LIBRARY SQLite_INCLUDE_DIR)

if(SQLite_FOUND)
  message(STATUS "SQLite found")
endif()

mark_as_advanced(
    SQLite_DIR
    SQLite_LIBRARY
    SQLite_INCLUDE_DIR
)
