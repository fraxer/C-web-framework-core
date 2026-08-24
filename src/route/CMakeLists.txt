cmake_minimum_required(VERSION 3.12.4)

cwfr_add_lib(route LINK_LIBS protocols ratelimiter misc ${PCRE2_LIBRARIES} ${CMAKE_DL_LIBS})
