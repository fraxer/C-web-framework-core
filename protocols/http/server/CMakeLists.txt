cmake_minimum_required(VERSION 3.12.4)

cwfr_add_lib(http_server LINK_LIBS connection h2server)

cwfr_add_subdirs()
