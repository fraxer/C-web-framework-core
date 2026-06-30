cmake_minimum_required(VERSION 3.12.4)

cpdy_add_lib(http LINK_LIBS connection middleware misc http_server_parsers http_server_filters)

cpdy_add_subdirs()
