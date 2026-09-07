cmake_minimum_required(VERSION 3.12.4)

# The include path to shadowload.h is added by hand rather than by linking
# moduleloader: moduleloader already links route, and naming it here would close
# the cycle. Only the header is needed -- both archives are whole-archived into
# libcwfr_framework.so, which is where shadow_dlopen actually resolves.
cwfr_add_lib(route
	INCLUDE_DIRS . ${CMAKE_CURRENT_SOURCE_DIR}/../moduleloader
	LINK_LIBS protocols ratelimiter misc ${PCRE2_LIBRARIES} ${CMAKE_DL_LIBS})
