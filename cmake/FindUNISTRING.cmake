# - Find UNISTRING
# Find the native libunistring headers and libraries.
#
# UNISTRING_INCLUDE_DIRS  - where to find unistr.h, unicase.h, etc.
# UNISTRING_LIBRARIES     - List of libraries when using libunistring.
# UNISTRING_FOUND         - True if libunistring found.

# Look for the header file.
FIND_PATH(UNISTRING_INCLUDE_DIR NAMES unistr.h)

# Look for the library.
FIND_LIBRARY(UNISTRING_LIBRARY NAMES unistring)

# Handle the QUIETLY and REQUIRED arguments and set UNISTRING_FOUND to TRUE if all listed variables are TRUE.
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(UNISTRING DEFAULT_MSG UNISTRING_LIBRARY UNISTRING_INCLUDE_DIR)

# Copy the results to the output variables.
IF(UNISTRING_FOUND)
	SET(UNISTRING_LIBRARIES ${UNISTRING_LIBRARY})
	SET(UNISTRING_INCLUDE_DIRS ${UNISTRING_INCLUDE_DIR})
	message(STATUS "UNISTRING found")
ELSE(UNISTRING_FOUND)
	SET(UNISTRING_LIBRARIES)
	SET(UNISTRING_INCLUDE_DIRS)
ENDIF(UNISTRING_FOUND)

MARK_AS_ADVANCED(UNISTRING_INCLUDE_DIRS UNISTRING_LIBRARIES)
