cmake_minimum_required(VERSION 3.12.4)

cwfr_add_lib(form LINK_LIBS misc validation storage ${PCRE2_LIBRARIES})
