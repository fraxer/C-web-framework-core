cmake_minimum_required(VERSION 3.12.4)

cwfr_add_lib(misc INCLUDE_DIRS . ${IDN2_INCLUDE_DIRS} ${UNISTRING_INCLUDE_DIRS} LINK_LIBS config ZLIB::ZLIB OpenSSL::Crypto ${IDN2_LIBRARIES} ${UNISTRING_LIBRARIES})

# misc itself globs only its own directory, so the subdirectory needs its own
# call. validation links misc, never the other way round.
add_subdirectory(validation)
