cmake_minimum_required(VERSION 3.12.4)

cwfr_add_lib(websocket_server LINK_LIBS connection middleware websocket_server_parsers misc)

cwfr_add_subdirs()
