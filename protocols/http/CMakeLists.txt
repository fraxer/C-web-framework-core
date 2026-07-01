cmake_minimum_required(VERSION 3.12.4)

cwfr_add_lib(http LINK_LIBS connection middleware misc http_server_parsers http_server_filters)

cwfr_add_subdirs()
