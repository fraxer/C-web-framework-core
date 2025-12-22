# - Find idn2
# Find the native IDN2 headers and libraries.
#
# IDN2_INCLUDE_DIRS	- where to find idn2.h, etc.
# IDN2_LIBRARIES	- List of libraries when using idn2.
# IDN2_FOUND	- True if idn2 found.

# Look for the header file.
FIND_PATH(IDN2_INCLUDE_DIR NAMES idn2.h)

# Look for the library.
FIND_LIBRARY(IDN2_LIBRARY NAMES idn2)

# Handle the QUIETLY and REQUIRED arguments and set IDN2_FOUND to TRUE if all listed variables are TRUE.
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(IDN2 DEFAULT_MSG IDN2_LIBRARY IDN2_INCLUDE_DIR)

# Copy the results to the output variables.
IF(IDN2_FOUND)
	SET(IDN2_LIBRARIES ${IDN2_LIBRARY})
	SET(IDN2_INCLUDE_DIRS ${IDN2_INCLUDE_DIR})
	message(STATUS "IDN2 found")
ELSE(IDN2_FOUND)
	SET(IDN2_LIBRARIES)
	SET(IDN2_INCLUDE_DIRS)
ENDIF(IDN2_FOUND)

MARK_AS_ADVANCED(IDN2_INCLUDE_DIRS IDN2_LIBRARIES)
